"""
CodeGuardian CLI Inference Tester
Compare Base Model vs. Fine-Tuned CodeGuardian on real or synthetic git diffs.
"""

import sys
import os
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
from app.model_validation import ModelOutputValidationError, validate_model_report

SYSTEM_PROMPT = """You are CodeGuardian, an evidence-first local code reviewer.
Return one valid CodeGuardian ReviewReport v2 JSON object. Every finding must reference
a changed file and changed new-file line, include exact source evidence, and use a
truthful patch/test verification state. Counts must equal findings. Do not invent a
patch, test result, exploit proof, source location, or model performance measurement."""

DEFAULT_DIFF = """diff --git a/payments/checkout.py b/payments/checkout.py
index e83a21..cc9410 100644
--- a/payments/checkout.py
+++ b/payments/checkout.py
@@ -10,6 +10,8 @@ def process_order(cart, user_token):
     total_price = sum(item.price for item in cart.items)
+    discount_code = cart.params.get('coupon')
+    if discount_code:
+        total_price -= eval(cart.params.get('discount_expr', '0'))
     charge = stripe.Charge.create(amount=int(total_price * 100), currency='usd')
     return charge.id"""

def run_inference(
    base_model_name: str = "Qwen/Qwen2.5-Coder-3B-Instruct",
    adapter_path: str = None,
    diff_text: str = DEFAULT_DIFF,
    max_new_tokens: int = 1024
):
    print(f"\n[LOAD] Loading base model: {base_model_name} (4-bit NF4)...")

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
        bnb_4bit_use_double_quant=True
    )

    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True
    )

    if adapter_path and os.path.exists(adapter_path):
        print(f"[LOAD] Attaching fine-tuned LoRA adapter from: {adapter_path}")
        model = PeftModel.from_pretrained(model, adapter_path)
    else:
        print("[INFO] Running raw base model (no adapter attached).")

    model.eval()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Please review the following git diff and output your review in structured JSON:\n\n```diff\n{diff_text}\n```"}
    ]

    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    print("\n" + "="*50)
    print(" Analyzing Diff with CodeGuardian...")
    print("="*50)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            temperature=0.2,
            top_p=0.9,
            repetition_penalty=1.05,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )

    response = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    print("\n--- MODEL OUTPUT ---")
    print(response)

    # Validate the same production schema and diff grounding used by the server.
    try:
        report = validate_model_report(response, diff_text)
        print("\n[SUCCESS] Output is valid ReviewReport v2 JSON with grounded changed-line locations.")
        print(f"Risk Level: {report.risk_level}")
        print(f"Verdict:    {report.verdict}")
    except ModelOutputValidationError as exc:
        print(f"\n[INVALID OUTPUT] {exc}")

def main():
    parser = argparse.ArgumentParser(description="Test CodeGuardian inference")
    parser.add_argument("--base_model", type=str, default="Qwen/Qwen2.5-Coder-3B-Instruct")
    parser.add_argument("--adapter", type=str, default="output/codeguardian-qwen-3b-lora")
    parser.add_argument("--diff_file", type=str, default=None, help="Path to custom .diff or .patch file")
    args = parser.parse_args()

    diff_content = DEFAULT_DIFF
    if args.diff_file and os.path.exists(args.diff_file):
        with open(args.diff_file, "r", encoding="utf-8") as f:
            diff_content = f.read()

    adapter = args.adapter if os.path.exists(args.adapter) else None
    run_inference(args.base_model, adapter, diff_content)

if __name__ == "__main__":
    main()
