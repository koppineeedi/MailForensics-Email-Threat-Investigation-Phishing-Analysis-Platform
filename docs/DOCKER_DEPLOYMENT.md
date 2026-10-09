# MailForensics — Production Docker Deployment Architecture

## 1. Overview & Service Topology

MailForensics provides an enterprise containerized deployment via Docker Compose with 5 coordinated services:

```
                      [ Analyst Browser ]
                              │
                    Port 80 / 5173 (HTTP)
                              ▼
                   ┌─────────────────────┐
                   │      FRONTEND       │
                   │  Nginx + React SPA  │
                   └──────────┬──────────┘
                              │ Reverse Proxy (/api, /ws)
                              ▼
                   ┌─────────────────────┐
                   │       BACKEND       │
                   │    FastAPI ASGI     │
                   └─────┬─────────┬─────┘
                         │         │
          Database Write │         │ Redis Task Queue
                         ▼         ▼
     ┌───────────────────────┐   ┌───────────────────────┐
     │       POSTGRES        │   │         REDIS         │
     │     PostgreSQL 16     │   │     Redis 7 Broker    │
     └───────────────────────┘   └──────────┬────────────┘
                                            │
                                            ▼
                                 ┌─────────────────────┐
                                 │    CELERY-WORKER    │
                                 │ Analysis Pipeline   │
                                 └─────────────────────┘
```

---

## 2. Container Service Inventory

| Service | Base Image | Purpose | Health Check |
| :--- | :--- | :--- | :--- |
| `postgres` | `postgres:16-alpine` | Primary transactional relational database | `pg_isready -U postgres` |
| `redis` | `redis:7-alpine` | Celery message broker & result backend | `redis-cli ping` |
| `backend` | Python 3.11-slim (`Dockerfile.backend`) | REST API, WebSockets, Alembic migrations | `curl -f http://localhost:8000/health` |
| `celery-worker` | Python 3.11-slim (`Dockerfile.backend`) | Distributed asynchronous email analysis | Subscribes to broker tasks |
| `frontend` | Node 20 / Nginx alpine (`Dockerfile.frontend`) | Reverse proxy, static asset delivery | Nginx process liveness |

---

## 3. Persistent Volumes & Data Retention

- `postgres_data`: Preserves all PostgreSQL tables, users, cases, and analysis records.
- `redis_data`: Preserves Redis operational state.
- `mailforensics_storage`: Shared volume between `backend` and `celery-worker` storing quarantined `.eml` raw artifacts, extracted attachments, and generated PDF reports.

---

## 4. Deployment Commands

```bash
# 1. Validate Docker Compose configuration
docker compose config

# 2. Build and launch all 5 services in detached mode
docker compose up -d --build

# 3. Monitor container health and status
docker compose ps

# 4. View live logs from the backend or worker
docker compose logs -f backend
docker compose logs -f celery-worker

# 5. Gracefully stop services
docker compose down
```

---

## 5. Host Compatibility Note

If Docker Desktop is not installed or the Docker daemon is inactive on the local host (as noted in `docs/REAL_ENVIRONMENT_STATUS.md`), MailForensics runs in **Local Synchronous Mode** using SQLite and the FastAPI application loop. All features (YARA, RFC parsing, risk engine, PDF reports, STIX export) are 100% operational in local mode.
