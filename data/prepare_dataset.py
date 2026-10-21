"""Validate CodeGuardian v2 ChatML datasets before training."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas import ReviewReport
from data.dataset_generator import generate_dataset


def inspect_dataset(file_path: Path) -> bool:
    """Print token estimates and reject invalid schema or duplicate prompts."""
    if not file_path.exists():
        print(f"Error: {file_path} not found.")
        return False

    total_chars = max_chars = 0
    sample_count = invalid_count = duplicate_count = 0
    prompts: set[str] = set()

    for line_number, line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            sample = json.loads(line)
            messages = sample["messages"]
            if [message.get("role") for message in messages] != ["system", "user", "assistant"]:
                raise ValueError("expected exactly system, user, assistant messages")
            ReviewReport.model_validate(json.loads(messages[-1]["content"]))
            prompt_hash = hashlib.sha256(messages[1]["content"].encode("utf-8")).hexdigest()
            if prompt_hash in prompts:
                duplicate_count += 1
            prompts.add(prompt_hash)
            size = sum(len(message.get("content", "")) for message in messages)
            total_chars += size
            max_chars = max(max_chars, size)
            sample_count += 1
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, ValidationError) as exc:
            invalid_count += 1
            print(f"Line {line_number}: invalid sample: {exc}")

    average = total_chars / max(1, sample_count)
    print(f"\n--- Dataset audit: {file_path} ---")
    print(f"Valid samples:      {sample_count}")
    print(f"Invalid samples:    {invalid_count}")
    print(f"Duplicate prompts:  {duplicate_count}")
    print(f"Average length:     {int(average)} chars (~{int(average / 3.5)} rough tokens)")
    print(f"Maximum length:     {max_chars} chars (~{int(max_chars / 3.5)} rough tokens)")
    print("Token counts are estimates; validate against the selected model tokenizer before training.")
    return invalid_count == 0 and duplicate_count == 0 and sample_count > 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or validate CodeGuardian v2 datasets")
    parser.add_argument("--generate", action="store_true", help="regenerate the synthetic seed split")
    parser.add_argument("--count", type=int, default=8, help="independent synthetic samples, maximum 8")
    args = parser.parse_args()
    data_dir = Path(__file__).resolve().parent

    if args.generate:
        generate_dataset(output_dir=str(data_dir), total_samples=args.count)

    train_ok = inspect_dataset(data_dir / "sample_train.jsonl")
    val_ok = inspect_dataset(data_dir / "sample_val.jsonl")
    return 0 if train_ok and val_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
