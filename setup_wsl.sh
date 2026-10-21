#!/bin/bash
# ==============================================================================
# CodeGuardian: WSL2 Ubuntu Automated Setup
# Optimized for NVIDIA RTX 5060 Laptop (8GB VRAM) & CUDA Passthrough
# ==============================================================================

set -e

echo "=== [1/5] Verifying GPU and CUDA Passthrough in WSL2 ==="
if [ -f "/usr/lib/wsl/lib/nvidia-smi" ]; then
    /usr/lib/wsl/lib/nvidia-smi
else
    echo "Warning: /usr/lib/wsl/lib/nvidia-smi not found. Checking system nvidia-smi..."
    nvidia-smi
fi

echo "=== [2/5] Installing System Prerequisites ==="
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv git curl build-essential

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=== [3/5] Creating Python Virtual Environment (venv) ==="
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo "=== [4/5] Installing PyTorch with CUDA 12.4+ Acceleration ==="
pip install --upgrade pip
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

echo "=== [5/5] Installing Unsloth, Hugging Face, & Application Packages ==="
pip install "unsloth[cu124-torch250] @ git+https://github.com/unslothai/unsloth.git" || \
pip install "unsloth @ git+https://github.com/unslothai/unsloth.git" || \
echo "Unsloth installation skipped. Falling back to Hugging Face PEFT + BitsAndBytes pipeline."

pip install -r requirements.txt

echo "=== Generating Initial Dataset ==="
python3 data/dataset_generator.py

echo ""
echo "======================================================================"
echo " Setup Complete! CodeGuardian environment is ready."
echo " To activate your environment:"
echo "   source venv/bin/activate"
echo ""
echo " To start fine-tuning:"
echo "   bash train.sh"
echo ""
echo " To launch the Web UI:"
echo "   bash run_app.sh"
echo "======================================================================"
