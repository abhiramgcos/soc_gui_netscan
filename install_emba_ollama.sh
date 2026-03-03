#!/usr/bin/env bash
# ============================================================
# One-time installer: EMBA + Ollama for soc_gui_netscan
# Run as your normal user (sudo prompts will appear).
# All steps are idempotent — already-installed tools are skipped.
# ============================================================
set -euo pipefail

# ── 1. Ollama ────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
  echo "[SKIP] Ollama already installed: $(ollama --version 2>/dev/null || true)"
else
  echo "=== Installing Ollama ==="
  curl -fsSL https://ollama.com/install.sh | sh
  echo "Ollama installed."
fi

# ── 2. Ensure Ollama service is running ──────────────────────
if curl -sf http://localhost:11434/api/tags &>/dev/null; then
  echo "[SKIP] Ollama is already running on :11434"
else
  echo "=== Starting Ollama service ==="
  if systemctl is-enabled ollama &>/dev/null; then
    sudo systemctl start ollama
  else
    nohup ollama serve &>/tmp/ollama.log &
    sleep 4
  fi
  echo "Ollama service started."
fi

# ── 3. Pull qwen3:4b model if not already present ───────────
if ollama list 2>/dev/null | grep -q "qwen3:4b"; then
  echo "[SKIP] Model qwen3:4b already present."
else
  echo "=== Pulling qwen3:4b model (~2.4 GB) ==="
  ollama pull qwen3:4b
  echo "Model ready."
fi

# ── 4. EMBA ─────────────────────────────────────────────────
if [ -x /opt/emba/emba ]; then
  echo "[SKIP] EMBA already installed at /opt/emba/emba"
else
  echo "=== Cloning EMBA to /opt/emba ==="
  if [ -d /opt/emba ]; then
    sudo git -C /opt/emba pull --ff-only
  else
    sudo git clone https://github.com/e-m-b-a/emba.git /opt/emba
  fi

  echo "=== Running EMBA installer (installs system deps via apt-get) ==="
  cd /opt/emba
  sudo ./installer.sh -F
  echo "EMBA installed."
fi

# ── 5. Summary ───────────────────────────────────────────────
echo ""
echo "====================================================="
echo "All dependencies ready!"
echo "  EMBA  : /opt/emba/emba"
echo "  Ollama: $(ollama --version 2>/dev/null || true)"
echo "  Models: $(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | tr '\n' ' ')"
echo ""
echo "Now rebuild and restart the containers:"
echo "  cd $(dirname "$(realpath "$0")")"
echo "  docker compose up -d --build"
echo "====================================================="
