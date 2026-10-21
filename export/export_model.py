"""
CodeGuardian Model Exporter
Merges LoRA adapter with base weights and generates Ollama Modelfile + GGUF export instructions.
"""

import os
import argparse
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

SYSTEM_PROMPT = """You are CodeGuardian, an expert automated code reviewer and security auditor.
Analyze the provided code diff carefully.
Always respond in strictly valid JSON format conforming to this schema:
{
  "summary": "1-2 sentence high-level summary of changes",
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "findings": [
    {
      "file": "path/to/file",
      "type": "SECURITY" | "BUG" | "PERFORMANCE" | "STYLE",
      "title": "Concise issue description",
      "description": "Clear explanation of why this is problematic",
      "suggested_fix": "Unified diff or replacement snippet"
    }
  ],
  "unit_tests": "Executable unit test code covering edge cases",
  "verdict": "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
}"""

def export_merged_model(
    base_model_name: str,
    adapter_path: str,
    output_dir: str
):
    print(f"\n[LOAD] Loading base model: {base_model_name} in float16...")
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        torch_dtype=torch.float16,
        device_map="cpu", # Merge on 24GB CPU RAM to conserve 8GB VRAM
        trust_remote_code=True
    )

    print(f"[LOAD] Attaching LoRA adapter from: {adapter_path}...")
    model = PeftModel.from_pretrained(base_model, adapter_path)

    print("[MERGE] Merging LoRA weights into base model...")
    merged_model = model.merge_and_unload()

    print(f"[SAVE] Saving merged full-precision model to: {output_dir}...")
    os.makedirs(output_dir, exist_ok=True)
    merged_model.save_pretrained(output_dir, safe_serialization=True)
    tokenizer.save_pretrained(output_dir)

    # Generate Ollama Modelfile
    modelfile_path = os.path.join(output_dir, "Modelfile")
    with open(modelfile_path, "w", encoding="utf-8") as f:
        f.write(f"""FROM {output_dir}

TEMPLATE \"\"\"{{{{ if .System }}}}<|im_start|>system
{{{{ .System }}}}<|im_end|>
{{{{ end }}}}{{{{ if .Prompt }}}}<|im_start|>user
{{{{ .Prompt }}}}<|im_end|>
{{{{ end }}}}<|im_start|>assistant
{{{{ .Response }}}}<|im_end|>\"\"\"

SYSTEM \"\"\"{SYSTEM_PROMPT}\"\"\"

PARAMETER temperature 0.2
PARAMETER top_p 0.9
PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"
""")

    print(f"[OLLAMA] Generated Ollama Modelfile at: {modelfile_path}")
    print("\n[NEXT STEPS]")
    print(f"1. Convert to GGUF using llama.cpp:")
    print(f"   python llama.cpp/convert_hf_to_gguf.py {output_dir} --outtype q8_0 --outfile codeguardian.gguf")
    print(f"2. Or import directly into Ollama:")
    print(f"   ollama create codeguardian -f {modelfile_path}")

def main():
    parser = argparse.ArgumentParser(description="Export and merge CodeGuardian LoRA")
    parser.add_argument("--base_model", type=str, default="Qwen/Qwen2.5-Coder-3B-Instruct")
    parser.add_argument("--adapter", type=str, default="output/codeguardian-qwen-3b-lora")
    parser.add_argument("--output_dir", type=str, default="output/codeguardian-merged-16bit")
    args = parser.parse_args()

    if not os.path.exists(args.adapter):
        print(f"[ERROR] Adapter directory '{args.adapter}' not found. Please run training first.")
        return

    export_merged_model(args.base_model, args.adapter, args.output_dir)

if __name__ == "__main__":
    main()
