# SOC Network Discovery Platform

Full-stack network discovery and asset inventory tool built for SOC teams. Runs an async 4-stage scanning pipeline (nmap → ARP → RustScan → deep scan) with real-time progress via WebSocket, PostgreSQL persistence, and a modern dark-themed React dashboard.

## Architecture

```
┌─────────────┐      ┌──────────────┐      ┌───────────┐
│  React SPA  │◄────►│  FastAPI API  │◄────►│ PostgreSQL│
│  (Vite/TS)  │  WS  │              │      │           │
└─────────────┘      └──────┬───────┘      └───────────┘
                            │
                     ┌──────▼───────┐      ┌───────────┐
                     │    Worker     │◄────►│   Redis    │
                     │  (Pipeline)   │      │  (Queue)   │
                     └──────────────┘      └───────────┘
```

### Scanning Pipeline (4 Stages)

| Stage | Tool       | Purpose                          |
|-------|-----------|----------------------------------|
| 1     | nmap -sn  | Ping sweep — discover live hosts |
| 2     | arp-scan  | ARP lookup — MAC + vendor info   |
| 3     | RustScan  | Fast port scan (all 65535 ports)  |
| 4     | nmap -sV  | Deep scan — service/OS detection |

## Tech Stack

- **Backend:** Python 3.12, FastAPI 0.115, SQLAlchemy 2.0 (async), asyncpg, structlog
- **Frontend:** React 18, TypeScript 5.6, Vite 5.4, lucide-react
- **Database:** PostgreSQL 16
- **Queue:** Redis 7 (RPUSH/BLPOP + pub/sub)
- **Scanning:** nmap, RustScan 2.1.1, arp-scan
- **Infra:** Docker, docker-compose, nginx

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Network scanning requires `NET_RAW` / `NET_ADMIN` capabilities (handled by docker-compose)

### 1. Clone and configure

```bash
cp .env.example .env
# Edit .env if you need to change database credentials or ports
```

### 2. Launch with Docker Compose

```bash
docker compose up -d --build
```

This starts 5 services:

| Service    | Port  | Description            |
|-----------|-------|------------------------|
| `db`      | 5432  | PostgreSQL             |
| `redis`   | 6379  | Redis                  |
| `api`     | 8000  | FastAPI backend        |
| `worker`  | —     | Scan pipeline worker   |
| `frontend`| 5173  | Vite dev server / SPA  |

The nginx reverse proxy (if configured) unifies everything on port 80.

### 3. Run database migrations

```bash
docker compose exec api alembic upgrade head
```

### 4. Seed initial data (optional)

```bash
docker compose exec api python -m seed_data
```

### 5. Open the dashboard

Navigate to [http://localhost:5173](http://localhost:5173)

## Development

### Backend (without Docker)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

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
| `GET`   | `/dashboard/stats`            | Aggregate statistics     |
| `GET`   | `/export/scans/:id?format=`   | Export scan (csv/json)   |
| `GET`   | `/export/hosts?format=`       | Export all hosts         |

### WebSocket

| Path                  | Description                      |
|-----------------------|----------------------------------|
| `/ws/scans/:id`       | Real-time progress for a scan    |
| `/ws/live`            | All scan progress events         |

Interactive API docs: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)

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
│   │   └── versions/001_initial_schema.py
│   ├── seed_data.py
│   ├── app/
│   │   ├── main.py              # FastAPI app
│   │   ├── config.py            # Settings (Pydantic)
│   │   ├── database.py          # Async SQLAlchemy engine
│   │   ├── models/              # ORM models (scan, host, port, tag)
│   │   ├── schemas/             # Pydantic schemas
│   │   ├── api/                 # Route handlers
│   │   ├── services/
│   │   │   ├── scanner.py       # 4-stage pipeline
│   │   │   └── scheduler.py     # Redis job queue
│   │   ├── worker/main.py       # Background scan worker
│   │   └── utils/logging.py     # Structured logging
│   └── tests/
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── types/index.ts
│   │   ├── styles/global.css    # SOC dark theme
│   │   ├── api/client.ts        # REST client
│   │   ├── hooks/useData.ts     # useFetch, usePolling, useWebSocket
│   │   ├── utils/formatters.ts
│   │   └── components/
│   │       ├── Layout/Layout.tsx
│   │       ├── Dashboard/Dashboard.tsx
│   │       ├── Scans/ScanList.tsx
│   │       ├── Scans/ScanDetail.tsx
│   │       ├── Hosts/HostTable.tsx
│   │       └── Hosts/HostDetail.tsx
│   └── tests/
```

## License

Internal SOC tool — proprietary.
