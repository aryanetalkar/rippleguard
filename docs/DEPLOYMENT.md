# RippleGuard Deployment Guide

This guide documents the minimal, production-ready deployment configuration for the RippleGuard modular monolith without unnecessary infrastructure complexity (no Redis, no Kafka, no Kubernetes, no microservices).

---

## Architecture Topology

```text
               ┌───────────────────────────────┐
               │    Next.js Frontend (Node)    │
               │    Port 3000 / Edge CDN       │
               └──────────────┬────────────────┘
                              │ HTTPS / CORS
                              ▼
               ┌───────────────────────────────┐
               │     FastAPI Backend (Python)  │
               │     Port 8000 / Uvicorn       │
               └──────────────┬────────────────┘
                              │ SQLAlchemy 2.0
                              ▼
               ┌───────────────────────────────┐
               │     Managed PostgreSQL DB     │
               └───────────────────────────────┘
```

---

## Required Environment Variables

### Backend Configuration

| Variable | Required | Example Value | Description |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | **Yes** | `postgresql+psycopg://user:pass@host:5432/rippleguard` | PostgreSQL connection string |
| `ENVIRONMENT` | **Yes** | `production` | Deployment environment mode |
| `CORS_ORIGIN` | **Yes** | `https://rippleguard.example.com` | Allowed frontend origin for CORS |
| `HOST` | No | `0.0.0.0` | Bind host address |
| `PORT` | No | `8000` | Bind port |
| `OSV_API_URL` | No | `https://api.osv.dev/v1` | Official OSV intelligence endpoint |
| `GEMINI_MODEL` | No | `gemini-3.8-flash` | Selected Gemini explanation model |
| `GEMINI_API_KEY` | Optional | `AIza...` | Google GenAI API key for explanations |

### Frontend Configuration

| Variable | Required | Example Value | Description |
| :--- | :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | Optional | `https://api.rippleguard.example.com` | Backend API base URL (defaults to `http://localhost:8000`) |

---

## Standard Production Run Commands

### 1. Database Migration
```bash
cd backend
alembic upgrade head
```

### 2. Backend Server (Uvicorn / Gunicorn)
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
```

### 3. Frontend Production Build & Serve
```bash
cd frontend
npm run build
npm run start -- -p 3000
```

---

## Health & Monitoring Checks

- **Liveness probe**: `GET /api/v1/health` (HTTP 200 `{"status": "ok", "service": "rippleguard-api"}`)
- **Readiness probe**: `GET /health` (HTTP 200 `{"status": "ok", "service": "rippleguard"}`)
- **Fail-Safe Behavior**: In the absence of `GEMINI_API_KEY` or during upstream AI spikes, the application continues to provide 100% of deterministic graph, ripple propagation, and structural risk calculations.
