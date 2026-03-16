# SOC Network Discovery Platform

Full-stack network discovery, asset inventory, and **firmware security analysis** tool built for SOC teams. Runs an async 4-stage network scanning pipeline (nmap → ARP → RustScan → deep scan) and a 3-stage firmware analysis pipeline (Download → EMBA → AI Triage) with real-time WebSocket progress, PostgreSQL persistence, Ollama-powered local LLM inference, and a modern dark-themed React dashboard.

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌───────────┐
│  React SPA  │◄────►│  FastAPI API │◄────►│ PostgreSQL│
│  (Vite/TS)  │  WS  │              │      │           │
└─────────────┘      └──────┬───────┘      └───────────┘
                            │
                     ┌──────▼───────┐      ┌───────────┐
                     │    Worker    │◄────►│   Redis   │
                     │  (Pipeline)  │      │  (Queue)  │
                     └──────┬───────┘      └───────────┘
                            │
                     ┌──────▼───────┐      ┌───────────┐
                     │   EMBA       │      │  Ollama   │
                     │  (Firmware)  │      │  (LLM)    │
                     └──────────────┘      └───────────┘
```

### Network Scanning Pipeline (4 Stages)

| Stage | Tool       | Purpose                         |
|-------|-----------|----------------------------------|
| 1     | nmap -sn  | Ping sweep — discover live hosts |
| 2     | arp-scan  | ARP lookup — MAC + vendor info   |
| 3     | RustScan  | Fast port scan (all 65535 ports) |
| 4     | nmap -sV  | Deep scan — service/OS detection |

### Firmware Analysis Pipeline (3 Stages)

| Stage | Component          | Purpose                                              |
|-------|--------------------|------------------------------------------------------|
| A     | httpx downloader   | Stream firmware binary from `fw_url`, compute SHA-256 |
| B     | EMBA scanner       | Static/dynamic firmware analysis (CVEs, crypto, etc.) |
| C     | Ollama AI triage   | LLM reads EMBA findings → risk report + score (0-10)  |

The firmware pipeline uses **Ollama** for local LLM inference (default model: `qwen3:4b`), making it fully air-gapped / edge-deployable — no cloud API keys needed. The stack supports both host Ollama and fully Dockerized Ollama.

## Tech Stack

- **Backend:** Python 3.12, FastAPI 0.115, SQLAlchemy 2.0 (async), asyncpg, httpx, structlog
- **Frontend:** React 18, TypeScript 5.6, Vite 5.4, lucide-react
- **Database:** PostgreSQL 16
- **Queue:** Redis 7 (RPUSH/BLPOP + pub/sub)
- **Scanning:** nmap, RustScan 2.1.1, arp-scan
- **Firmware:** EMBA (embedded firmware analyser), Ollama (local LLM)
- **Infra:** Docker, Docker Compose, nginx

## Hardware Requirements

### Minimum (CPU-only Ollama)

- 4-core CPU, 8 GB RAM, 20 GB disk
- AI triage will run but slowly (~2-5 min per analysis)

### Recommended (GPU-accelerated)

- Any NVIDIA GPU with ≥ 6 GB VRAM (e.g. RTX 3060, RTX 4060, **RTX 5060**, Jetson Orin)
- NVIDIA driver ≥ 535 + [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html)
- AI triage runs in seconds with GPU offload

The RTX 5060 (8 GB VRAM) handles Qwen3 4B comfortably at full speed. For larger models like Mistral 7B or Llama3 8B, it still runs well within the VRAM budget.

## Deployment Modes

- **Fully Dockerized (current recommended):** run `db`, `redis`, `api`, `worker`, `frontend`, and `ollama` as containers.
- **Hybrid mode:** run Ollama on host and keep the rest in Docker.

Both modes work with the same backend config (`OLLAMA_URL=http://localhost:11435`) because `api`/`worker` use `network_mode: host` and the Ollama container is published on `${OLLAMA_PORT:-11435}`.

## Quick Start

### Prerequisites

- Docker & Docker Compose v2+
- NVIDIA Container Toolkit (optional, for GPU acceleration)
- Network scanning requires `NET_RAW` / `NET_ADMIN` capabilities (handled by docker-compose)

### 0. One-time host setup (EMBA path + helper script)

Run this once to prepare EMBA and baseline dependencies:

```bash
chmod +x install_emba_ollama.sh
./install_emba_ollama.sh
```

If you are using fully Dockerized Ollama, this still sets up EMBA correctly; Ollama runtime can then be provided by the `ollama` compose service.

### 1. Clone and configure

```bash
git clone https://github.com/abhiramgcos/soc_gui_netscan.git 
cd soc_gui_netscan
cp .env.example .env
# Edit .env if you need to change database credentials or ports
```

### 2. Launch with Docker Compose

```bash
docker compose up -d --build
```

This starts all core services with `restart: unless-stopped`:

| Service    | Port  | Description                      |
|-----------|-------|----------------------------------|
| `db`      | 5434  | PostgreSQL 16                    |
| `redis`   | 6379  | Redis 7 (queue + pub/sub)        |
| `api`     | 8001  | FastAPI backend                  |
| `worker`  | —     | Scan + firmware pipeline worker  |
| `frontend`| 3000  | React SPA (nginx)                |
| `ollama`  | 11435 | Local LLM service (container `11434`) |
| `emba`    | —     | EMBA runtime container           |

### 3. Run database migrations

```bash
docker compose exec -T api alembic upgrade head
```

### 4. Pull Ollama model (required for AI triage)

```bash
docker compose exec -T ollama ollama pull qwen3:4b
docker compose exec -T ollama ollama list
```

### 5. Verify stack health

```bash
docker compose ps
curl -fsS http://localhost:8001/health
curl -fsS http://localhost:3000 >/dev/null && echo frontend_ok
curl -fsS http://localhost:11435/api/tags >/dev/null && echo ollama_ok
```

### 6. (Optional) Seed initial data

```bash
docker compose exec -T api python -m seed_data
```

### 7. Open the dashboard

Navigate to [http://localhost:3000](http://localhost:3000)

Interactive API docs: [http://localhost:8001/api/docs](http://localhost:8001/api/docs)

### Start / stop behavior

- Stop all services: `docker compose down`
- Start again: `docker compose up -d`
- Services auto-restart on daemon/host restart unless manually stopped (`restart: unless-stopped`).

To use another model, set `OLLAMA_MODEL` in `.env` and pull it in the Ollama container.

## Update Containers and Tools

For full SOC stack maintenance (containers + EMBA + Ollama model), run:

```bash
./update_soc_stack.sh
```

This will:
- pull latest registry images (`postgres`, `redis`)
- rebuild app containers (`api`, `worker`, `frontend`) with latest base layers
- restart the stack with Docker Compose
- refresh EMBA and the configured Ollama model
- run API/frontend health checks

## GPU Setup (NVIDIA)

Fully Dockerized mode (with containerized Ollama):

1. Install NVIDIA driver + NVIDIA Container Toolkit on host.
2. Enable `ollama` service GPU reservation in `docker-compose.yml`.
3. Restart and verify:

```bash
docker compose up -d --build
docker compose exec ollama ollama run qwen3:4b "Hello"
```

Hybrid host mode is also supported:

```bash
ollama run qwen3:4b "Hello"
```

With a working NVIDIA stack, the RTX 5060 (8 GB VRAM) can run:

| Model      | Params | VRAM Usage | Speed      |
|------------|--------|------------|------------|
| qwen3:4b   | 4B     | ~3 GB      | Very fast  |
| phi3:mini  | 3.8B   | ~2.5 GB    | Very fast  |
| mistral    | 7B     | ~5 GB      | Fast       |
| llama3     | 8B     | ~6 GB      | Fast       |

If you prefer CPU-only execution, the same commands work without GPU setup.

## Development

### Backend (without Docker)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001

# Start worker (separate terminal)
python -m app.worker.main
```

### Frontend

```bash
cd frontend
npm install
npm run dev       # Vite dev server with API proxy
npm run build     # Production build
npm run test      # Run vitest
```

### Running tests

```bash
# Backend
cd backend && pytest -v

# Frontend
cd frontend && npm test
```

## API Endpoints

Base URL: `/api`

### Scans

| Method   | Path                    | Description           |
|----------|------------------------|-----------------------|
| `GET`    | `/scans`               | List scans (filterable) |
| `POST`   | `/scans`               | Create & enqueue scan |
| `GET`    | `/scans/:id`           | Scan detail + logs    |
| `PATCH`  | `/scans/:id`           | Update metadata       |
| `DELETE` | `/scans/:id`           | Delete scan           |
| `POST`   | `/scans/:id/cancel`    | Cancel running scan   |

### Firmware Analysis

| Method   | Path                          | Description                     |
|----------|-------------------------------|---------------------------------|
| `POST`   | `/firmware`                   | Start analysis for a host       |
| `POST`   | `/firmware/batch`             | Start batch (all hosts with fw_url) |
| `GET`    | `/firmware`                   | List analyses (filter by status/host) |
| `GET`    | `/firmware/summary`           | Aggregate statistics            |
| `GET`    | `/firmware/:id`               | Analysis detail                 |
| `GET`    | `/firmware/:id/report`        | Raw AI triage report (markdown) |
| `POST`   | `/firmware/:id/cancel`        | Cancel running analysis         |
| `DELETE` | `/firmware/:id`               | Delete analysis record          |

### Hosts

| Method   | Path                          | Description          |
|----------|-------------------------------|----------------------|
| `GET`    | `/hosts`                      | List hosts (search, filter) |
| `GET`    | `/hosts/:id`                  | Host detail + ports  |
| `POST`   | `/hosts/:id/tags/:tagId`      | Add tag to host      |
| `DELETE` | `/hosts/:id/tags/:tagId`      | Remove tag           |

### Tags

| Method   | Path          | Description    |
|----------|---------------|----------------|
| `GET`    | `/tags`       | List all tags  |
| `POST`   | `/tags`       | Create tag     |
| `DELETE` | `/tags/:id`   | Delete tag     |

### Dashboard & Export

| Method  | Path                          | Description              |
|---------|-------------------------------|--------------------------|
| `GET`   | `/dashboard/stats`            | Aggregate stats (+ firmware) |
| `GET`   | `/export/scans/:id?format=`   | Export scan (csv/json)   |
| `GET`   | `/export/hosts?format=`       | Export all hosts         |

### WebSocket

| Path                      | Description                         |
|---------------------------|-------------------------------------|
| `/ws/scans/:id`           | Real-time progress for a scan       |
| `/ws/firmware/:id`        | Real-time progress for FW analysis  |
| `/ws/live`                | All scan progress events            |

## Project Structure

```
soc_firmai/
├── docker-compose.yml
├── .env.example
├── nginx/nginx.conf
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/
│   │       ├── 001_initial_schema.py
│   │       └── 003_firmware_analysis.py
│   ├── seed_data.py
│   ├── app/
│   │   ├── main.py                        # FastAPI app
│   │   ├── config.py                      # Settings (Pydantic) — Ollama, EMBA config
│   │   ├── database.py                    # Async SQLAlchemy engine
│   │   ├── models/
│   │   │   ├── host.py                    # Host + firmware fields
│   │   │   ├── firmware.py                # FirmwareAnalysis model
│   │   │   └── ...                        # scan, port, tag
│   │   ├── schemas/
│   │   │   ├── firmware.py                # Firmware Pydantic schemas
│   │   │   └── ...
│   │   ├── api/
│   │   │   ├── firmware.py                # Firmware CRUD + batch endpoints
│   │   │   ├── dashboard.py               # Stats (inc. firmware)
│   │   │   ├── ws.py                      # WebSocket (scans + firmware)
│   │   │   └── ...
│   │   ├── services/
│   │   │   ├── scanner.py                 # 4-stage network pipeline
│   │   │   ├── scheduler.py               # Redis queue (scan + firmware)
│   │   │   ├── firmware_download.py       # Stage A — async firmware download
│   │   │   ├── emba_scanner.py            # Stage B — EMBA analysis
│   │   │   ├── ai_triage.py              # Stage C — Ollama AI triage
│   │   │   └── firmware_pipeline.py       # Master firmware orchestrator
│   │   ├── worker/main.py                 # Background worker (scan + firmware)
│   │   └── utils/logging.py
│   └── tests/
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   ├── src/
│   │   ├── App.tsx                        # Routes (inc. /firmware)
│   │   ├── types/index.ts                 # TypeScript types (inc. Firmware*)
│   │   ├── api/client.ts                  # REST client (inc. firmwareApi)
│   │   ├── styles/global.css
│   │   ├── hooks/useData.ts
│   │   ├── utils/formatters.ts
│   │   └── components/
│   │       ├── Layout/Layout.tsx          # Nav (inc. Firmware link)
│   │       ├── Dashboard/Dashboard.tsx    # Stats (inc. firmware cards)
│   │       ├── Firmware/FirmwareList.tsx   # Firmware analysis list
│   │       ├── Firmware/FirmwareDetail.tsx # Analysis detail + AI report
│   │       ├── Scans/ScanList.tsx
│   │       ├── Scans/ScanDetail.tsx
│   │       ├── Hosts/HostTable.tsx
│   │       └── Hosts/HostDetail.tsx       # Host detail (inc. firmware section)
│   └── tests/
├── db/devices/                            # Device fingerprint JSON files
└── nginx/nginx.conf
```

## Environment Variables

| Variable              | Default                     | Description                          |
|-----------------------|-----------------------------|--------------------------------------|
| `POSTGRES_DB`         | `soc_network`               | Database name                        |
| `POSTGRES_USER`       | `soc_admin`                 | Database user                        |
| `POSTGRES_PASSWORD`   | `changeme_in_production`    | Database password                    |
| `DB_PORT`             | `5434`                      | PostgreSQL external port             |
| `REDIS_PORT`          | `6379`                      | Redis external port                  |
| `API_PORT`            | `8001`                      | FastAPI external port                |
| `FRONTEND_PORT`       | `3000`                      | Frontend external port               |
| `OLLAMA_URL`          | `http://localhost:11434`    | Ollama API endpoint                  |
| `OLLAMA_MODEL`        | `qwen3:4b`                  | LLM model for AI triage              |
| `OLLAMA_PORT`         | `11434`                     | Ollama external port                 |
| `EMBA_HOME`           | `/opt/emba`                 | Host path mounted to `/opt/emba`     |
| `EMBA_PATH`           | `/opt/emba/emba`            | Path to EMBA binary                  |
| `EMBA_TIMEOUT`        | `7200`                      | EMBA scan timeout (seconds)          |
| `EMBA_GPT_LEVEL`      | `1`                         | EMBA GPT-assisted scan level (0-5)   |
| `LOG_LEVEL`           | `info`                      | Log level                            |
| `API_WORKERS`         | `2`                         | Uvicorn worker count                 |

## License

Internal SOC tool — proprietary.
