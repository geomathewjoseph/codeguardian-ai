#!/bin/bash
# ==============================================================================
# CodeGuardian: Launch QLoRA Fine-Tuning
# ==============================================================================

set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Critical memory optimization for 8GB VRAM:
# Prevents CUDA out-of-memory errors due to fragmented blocks
export PYTORCH_CUDA_ALLOC_CONF="expandable_segments:True"

echo "=== Starting Fine-Tuning on RTX 5060 (8GB VRAM) ==="
python3 training/train_qlora.py
