#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

echo "[1/5] Pulling latest registry images..."
docker compose pull

echo "[2/5] Rebuilding app images with latest base layers..."
docker compose build --pull api worker frontend

echo "[3/5] Restarting SOC stack..."
docker compose up -d

echo "[4/5] Refreshing EMBA and Ollama tooling..."
if [ -d "${HOME}/emba/.git" ]; then
  git -C "${HOME}/emba" pull --ff-only || true
fi
docker pull embeddedanalyzer/emba:2.0.0c || true
if command -v ollama >/dev/null 2>&1; then
  ollama pull "${OLLAMA_MODEL:-qwen3:4b}" || true
fi

echo "[5/5] Health checks..."
docker compose ps
curl -fsS "http://localhost:${API_PORT:-8001}/health" >/dev/null
curl -fsS "http://localhost:${FRONTEND_PORT:-3000}" >/dev/null

echo "✅ SOC stack update complete (containers + tools)."
