#!/usr/bin/env bash
# ============================================================
# One-time installer: EMBA + Ollama for soc_gui_netscan
# Run as your normal user (sudo prompts will appear)
# ============================================================
set -euo pipefail

echo "=== Step 1: Install Ollama ==="
curl -fsSL https://ollama.com/install.sh | sh
echo "Ollama installed at $(which ollama)"

echo ""
echo "=== Step 2: Start Ollama service ==="
sudo systemctl enable --now ollama || {
  echo "systemctl not available, starting ollama in background..."
  nohup ollama serve &>/tmp/ollama.log &
  sleep 3
}

echo ""
echo "=== Step 3: Pull qwen3:4b model (~2.4 GB) ==="
ollama pull qwen3:4b
echo "Model ready."

echo ""
echo "=== Step 4: Clone EMBA to /opt/emba ==="
if [ -d /opt/emba ]; then
  echo "EMBA already cloned, pulling latest..."
  sudo git -C /opt/emba pull
else
  sudo git clone https://github.com/e-m-b-a/emba.git /opt/emba
fi

echo ""
echo "=== Step 5: Run EMBA installer (installs system deps) ==="
cd /opt/emba
sudo ./installer.sh -F

echo ""
echo "=== Step 6: Verify ==="
echo "EMBA: $(ls /opt/emba/emba)"
echo "Ollama: $(ollama list)"

echo ""
echo "====================================================="
echo "Installation complete! Run the following to rebuild:"
echo "  cd soc_gui_netscan && docker compose up -d --build"
echo "====================================================="
