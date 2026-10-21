"""
CodeGuardian: QLoRA Fine-Tuning Pipeline
Supports Unsloth (optimized 2x speed) with graceful HuggingFace PEFT fallback.
Hardware-targeted for NVIDIA RTX 5060 (8GB VRAM) + 24GB RAM.
"""

import os
import sys
import yaml
import torch
from datasets import load_dataset
from vram_monitor import VRAMMonitor

def load_config(config_path: str = "configs/train_config.yaml") -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def train():
    monitor = VRAMMonitor()
    monitor.print_summary("Pre-Training Hardware Status")
    
    config = load_config()
    model_cfg = config["model"]
    lora_cfg = config["lora"]
    train_cfg = config["training"]
    data_cfg = config["data"]

    max_seq_length = model_cfg.get("max_seq_length", 2048)
    model_name = model_cfg.get("name_or_path", "Qwen/Qwen2.5-Coder-3B-Instruct")
    output_dir = train_cfg.get("output_dir", "output/codeguardian-lora")

    print(f"\n[INFO] Starting CodeGuardian Training for: {model_name}")
    print(f"[INFO] Sequence Length: {max_seq_length} | Target Output: {output_dir}")

    # Determine if Unsloth is available
    use_unsloth = False
    try:
        from unsloth import FastLanguageModel
        use_unsloth = True
        print("[ENGINE] Found Unsloth! Activating ultra-fast kernels & memory optimizations.")
    except ImportError:
        print("[ENGINE] Unsloth not found. Using standard Hugging Face PEFT + BitsAndBytes pipeline.")

    # 1. Dataset Loading
    train_file = data_cfg.get("train_file", "data/sample_train.jsonl")
    val_file = data_cfg.get("val_file", "data/sample_val.jsonl")

    if not os.path.exists(train_file):
        raise FileNotFoundError(f"Training dataset '{train_file}' not found. Run dataset_generator.py first.")

    dataset = load_dataset("json", data_files={"train": train_file, "val": val_file})
    print(f"[DATA] Loaded {len(dataset['train'])} train samples, {len(dataset['val'])} validation samples.")

    monitor.start_background()

    if use_unsloth:
        # -------------------------------------------------------------
        # Branch A: Unsloth Optimized Path
        # -------------------------------------------------------------
        from trl import SFTTrainer
        from transformers import TrainingArguments

        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=model_name,
            max_seq_length=max_seq_length,
            dtype=torch.bfloat16,
            load_in_4bit=True,
        )

        model = FastLanguageModel.get_peft_model(
            model,
            r=lora_cfg.get("r", 16),
            target_modules=lora_cfg.get("target_modules", ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]),
            lora_alpha=lora_cfg.get("lora_alpha", 32),
            lora_dropout=lora_cfg.get("lora_dropout", 0.05),
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=train_cfg.get("seed", 42),
        )

        def formatting_prompts_func(examples):
            convos = examples["messages"]
            texts = [tokenizer.apply_chat_template(convo, tokenize=False, add_generation_prompt=False) for convo in convos]
            return {"text": texts}

        train_dataset = dataset["train"].map(formatting_prompts_func, batched=True)
        eval_dataset = dataset["val"].map(formatting_prompts_func, batched=True)

        training_args = TrainingArguments(
            per_device_train_batch_size=train_cfg.get("per_device_train_batch_size", 2),
            gradient_accumulation_steps=train_cfg.get("gradient_accumulation_steps", 4),
            warmup_ratio=train_cfg.get("warmup_ratio", 0.05),
            num_train_epochs=train_cfg.get("num_train_epochs", 3),
            learning_rate=train_cfg.get("learning_rate", 2e-4),
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=train_cfg.get("logging_steps", 10),
            optim=train_cfg.get("optim", "paged_adamw_8bit"),
            weight_decay=train_cfg.get("weight_decay", 0.01),
            lr_scheduler_type=train_cfg.get("lr_scheduler_type", "cosine"),
            seed=train_cfg.get("seed", 42),
            output_dir=output_dir,
            save_strategy="epoch",
            eval_strategy="epoch",
            report_to="none"
        )

        trainer = SFTTrainer(
            model=model,
            tokenizer=tokenizer,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            dataset_text_field="text",
            max_seq_length=max_seq_length,
            dataset_num_proc=2,
            packing=False,
            args=training_args,
        )

        trainer.train()
        print(f"[SAVE] Saving Unsloth LoRA model to {output_dir}...")
        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)

    else:
        # -------------------------------------------------------------
        # Branch B: Standard Hugging Face PEFT + BitsAndBytes Path
        # -------------------------------------------------------------
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            TrainingArguments
        )
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        from trl import SFTTrainer

        compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type=model_cfg.get("bnb_4bit_quant_type", "nf4"),
            bnb_4bit_compute_dtype=compute_dtype,
            bnb_4bit_use_double_quant=model_cfg.get("bnb_4bit_use_double_quant", True),
        )

        print("[LOAD] Fetching model with 4-bit NF4 quantization...")
        tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )

        model = prepare_model_for_kbit_training(model)

        peft_config = LoraConfig(
            r=lora_cfg.get("r", 16),
            lora_alpha=lora_cfg.get("lora_alpha", 32),
            target_modules=lora_cfg.get("target_modules", ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]),
            lora_dropout=lora_cfg.get("lora_dropout", 0.05),
            bias="none",
            task_type="CAUSAL_LM"
        )

        model = get_peft_model(model, peft_config)
        model.print_trainable_parameters()

        def formatting_func(example):
            return tokenizer.apply_chat_template(example["messages"], tokenize=False, add_generation_prompt=False)

        training_args = TrainingArguments(
            output_dir=output_dir,
            per_device_train_batch_size=train_cfg.get("per_device_train_batch_size", 2),
            gradient_accumulation_steps=train_cfg.get("gradient_accumulation_steps", 4),
            learning_rate=train_cfg.get("learning_rate", 2e-4),
            num_train_epochs=train_cfg.get("num_train_epochs", 3),
            warmup_ratio=train_cfg.get("warmup_ratio", 0.05),
            logging_steps=train_cfg.get("logging_steps", 10),
            save_strategy="epoch",
            eval_strategy="epoch",
            bf16=torch.cuda.is_bf16_supported(),
            fp16=not torch.cuda.is_bf16_supported(),
            optim=train_cfg.get("optim", "paged_adamw_8bit"),
            gradient_checkpointing=True,
            report_to="none"
        )

        trainer = SFTTrainer(
            model=model,
            train_dataset=dataset["train"],
            eval_dataset=dataset["val"],
            peft_config=peft_config,
            formatting_func=formatting_func,
            max_seq_length=max_seq_length,
            tokenizer=tokenizer,
            args=training_args,
        )

        print("[TRAIN] Initiating training loop...")
        trainer.train()

        print(f"[SAVE] Saving PEFT LoRA adapter to {output_dir}...")
        trainer.model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)

    monitor.stop_background()
    monitor.print_summary("Post-Training Peak Hardware Telemetry")
    print("\n[SUCCESS] Fine-tuning completed successfully! Adapters saved to:", output_dir)

if __name__ == "__main__":
    train()
