#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

EMBA_HOME="${EMBA_HOME:-${HOME}/emba}"
DISTROBOX_NAME="${DISTROBOX_NAME:-emba-box}"
DISTROBOX_IMAGE="${DISTROBOX_IMAGE:-docker.io/library/ubuntu:22.04}"

echo "[1/5] Pulling latest registry images..."
docker compose pull

echo "[2/5] Rebuilding app images with latest base layers..."
docker compose build --pull api worker frontend

echo "[3/5] Restarting SOC stack..."
docker compose up -d

echo "[4/5] Refreshing EMBA and Ollama tooling..."
if ! command -v distrobox >/dev/null 2>&1; then
  echo "[WARN] distrobox not found; skipping EMBA refresh."
else
  if [ -d "${EMBA_HOME}/.git" ]; then
    git -C "${EMBA_HOME}" pull --ff-only || true
  elif [ -d "${EMBA_HOME}" ]; then
    if [ -z "$(find "${EMBA_HOME}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
      git clone https://github.com/e-m-b-a/emba.git "${EMBA_HOME}" || true
    else
      echo "[WARN] ${EMBA_HOME} exists and is not a git checkout; skipping clone."
    fi
  else
    git clone https://github.com/e-m-b-a/emba.git "${EMBA_HOME}" || true
  fi

  if distrobox list --no-color 2>/dev/null | awk '{print $1}' | grep -Fxq "${DISTROBOX_NAME}"; then
    :
  else
    distrobox create --name "${DISTROBOX_NAME}" --image "${DISTROBOX_IMAGE}" --yes || true
  fi

  if [ -d "${EMBA_HOME}" ] && distrobox list --no-color 2>/dev/null | awk '{print $1}' | grep -Fxq "${DISTROBOX_NAME}"; then
    distrobox enter "${DISTROBOX_NAME}" -- bash -lc "cd '${EMBA_HOME}' && ./installer.sh -F" || true
  fi
fi
if command -v ollama >/dev/null 2>&1; then
  ollama pull "${OLLAMA_MODEL:-qwen3:4b}" || true
fi

echo "[5/5] Health checks..."
docker compose ps
curl -fsS "http://localhost:${API_PORT:-8001}/health" >/dev/null
curl -fsS "http://localhost:${FRONTEND_PORT:-3000}" >/dev/null

echo "✅ SOC stack update complete (containers + tools)."
