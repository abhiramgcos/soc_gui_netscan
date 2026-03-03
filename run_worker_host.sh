#!/usr/bin/env bash
# ============================================================
# Run the firmware worker NATIVELY on the host (not in Docker)
# This is required because EMBA needs access to system tools
# (git, lsmod, modprobe) that are not available in a container.
# ============================================================
set -euo pipefail

PROJ=/home/cos777/Desktop/soc_analys_FIRMAI/soc_gui_netscan
BACKEND=${PROJ}/backend

cd "${BACKEND}"

export PYTHONPATH="${BACKEND}"
export DATABASE_URL="postgresql+asyncpg://soc_admin:changeme_in_production@localhost:5434/soc_network"
export DATABASE_URL_SYNC="postgresql://soc_admin:changeme_in_production@localhost:5434/soc_network"
export REDIS_URL="redis://localhost:6379/0"
export OLLAMA_URL="http://localhost:11434"
export OLLAMA_MODEL="qwen3:4b"
export EMBA_HOME="${EMBA_HOME:-/home/cos777/emba}"
export EMBA_PATH="${EMBA_PATH:-${EMBA_HOME}/emba}"
export EMBA_TIMEOUT="7200"
export EMBA_GPT_LEVEL="1"
export LOG_LEVEL="info"
export WORKER_CONCURRENCY="1"
# Override container-only paths to writable host directories
export FIRMWARE_DIR="/tmp/soc_firmware"
export EMBA_LOGS_DIR="/tmp/soc_emba_logs"
export ONLY_DEP="2"
export FORCE="1"

mkdir -p "${FIRMWARE_DIR}" "${EMBA_LOGS_DIR}"

echo "Starting EMBA firmware worker on HOST..."
echo "  EMBA:   ${EMBA_PATH}"
echo "  Ollama: ${OLLAMA_URL}"
echo "  Redis:  ${REDIS_URL}"
echo ""

python3 -m app.worker.main
