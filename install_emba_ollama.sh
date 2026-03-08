#!/usr/bin/env bash
# ============================================================
# One-time installer: EMBA + Ollama for soc_gui_netscan
# Run as your normal user (sudo prompts will appear).
# All steps are idempotent — already-installed tools are skipped.
# ============================================================
set -euo pipefail

EMBA_HOME="${EMBA_HOME:-${HOME}/emba}"
EMBA_PATH="${EMBA_PATH:-${EMBA_HOME}/emba}"
DISTROBOX_NAME="${DISTROBOX_NAME:-emba-box}"
DISTROBOX_IMAGE="${DISTROBOX_IMAGE:-docker.io/library/ubuntu:22.04}"

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
if [ -x "${EMBA_PATH}" ]; then
  echo "[SKIP] EMBA already installed at ${EMBA_PATH}"
else
  if ! command -v distrobox >/dev/null 2>&1; then
    echo "[ERROR] distrobox is required but not available in PATH."
    echo "[ERROR] Install distrobox and rerun this script."
    exit 1
  fi

  echo "=== Preparing EMBA directory at ${EMBA_HOME} (host path) ==="
  if [ -d "${EMBA_HOME}/.git" ]; then
    echo "[INFO] Existing EMBA git checkout found, pulling latest changes..."
    git -C "${EMBA_HOME}" pull --ff-only
  elif [ -d "${EMBA_HOME}" ]; then
    if [ -z "$(find "${EMBA_HOME}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
      echo "[INFO] Empty directory found at ${EMBA_HOME}, cloning EMBA..."
      git clone https://github.com/e-m-b-a/emba.git "${EMBA_HOME}"
    else
      backup_dir="${EMBA_HOME}.backup.$(date +%Y%m%d_%H%M%S)"
      echo "[INFO] Non-git directory exists at ${EMBA_HOME}; moving it to ${backup_dir}"
      mv "${EMBA_HOME}" "${backup_dir}"
      git clone https://github.com/e-m-b-a/emba.git "${EMBA_HOME}"
    fi
  else
    echo "[INFO] Cloning EMBA to ${EMBA_HOME}..."
    git clone https://github.com/e-m-b-a/emba.git "${EMBA_HOME}"
  fi

  if distrobox list --no-color 2>/dev/null | awk '{print $1}' | grep -Fxq "${DISTROBOX_NAME}"; then
    echo "[SKIP] Distrobox '${DISTROBOX_NAME}' already exists."
  else
    echo "=== Creating distrobox '${DISTROBOX_NAME}' (${DISTROBOX_IMAGE}) ==="
    distrobox create --name "${DISTROBOX_NAME}" --image "${DISTROBOX_IMAGE}" --yes
  fi

  echo "=== Running EMBA installer inside distrobox '${DISTROBOX_NAME}' ==="
  distrobox enter "${DISTROBOX_NAME}" -- bash -lc "cd '${EMBA_HOME}' && ./installer.sh -F"
  echo "EMBA installed via distrobox."
fi

# ── 5. Summary ───────────────────────────────────────────────
echo ""
echo "====================================================="
echo "All dependencies ready!"
echo "  EMBA  : ${EMBA_PATH}"
echo "  Ollama: $(ollama --version 2>/dev/null || true)"
echo "  Models: $(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | tr '\n' ' ')"
echo ""
echo "If your compose stack uses EMBA from host path, ensure env is set:"
echo "  export EMBA_HOME='${EMBA_HOME}'"
echo "  export EMBA_PATH='${EMBA_PATH}'"
echo ""
echo "Now rebuild and restart the containers:"
echo "  cd $(dirname "$(realpath "$0")")"
echo "  docker compose up -d --build"
echo "====================================================="
