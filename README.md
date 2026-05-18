# Honeypot Central

Centralized management for distributed RDP honeypot nodes.

Each honeypot node runs a lightweight agent that periodically submits its `blocklist.txt` and analytics to the central server. You review incoming submissions in the web UI, approve them, then deploy a merged blocklist to your mirror.

```
Node 1 ──┐
Node 2 ──┼──► Central Server (web UI) ──► blocklist.txt (mirror)
Node N ──┘
```

## Features

- **Node registry** — register nodes, get unique auth tokens
- **Online/offline status** — nodes are marked offline after 15 min without a heartbeat
- **Submission review** — all incoming data lands in *pending* state; you approve or reject before anything is deployed
- **Merged deploy** — one click merges approved blocklists from all nodes, deduplicates IPs and writes the result to your mirror path
- **Deployment history** — audit log of every deploy
- **Docker image** — published to `ghcr.io/robulanetteam/honeypot-central`

---

## Quick start — Central Server

```bash
git clone https://github.com/robulanetteam/rdp-honeypot-central
cd rdp-honeypot-central/central

cp .env.example .env
nano .env          # set ADMIN_TOKEN

# pull pre-built image and start
IMAGE=ghcr.io/robulanetteam/honeypot-central docker compose up -d
```

Web UI available at `http://your-server:8100`

### Environment variables (`central/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_TOKEN` | ✓ | — | Secret for web UI login |
| `ONLINE_SECS` | | `900` | Seconds before a node is considered offline |

---

## Agent — install on each honeypot node

The agent reads `blocklist.txt` and `analytics.jsonl` from the honeypot data directory and submits them to the central server every 15 minutes via a systemd timer.

### 1. Register the node in the UI

Open the web UI → **Settings** → **Register New Node** → enter a node ID and label → copy the generated token.

### 2. Add variables to your honeypot `.env`

```bash
# Append to your existing honeypot .env (see agent/.env.example)
CENTRAL_URL=http://your-server:8100
CENTRAL_NODE_ID=rdp-home
CENTRAL_TOKEN=<token from UI>
CENTRAL_DATA_DIR=/home/homeserver/rdp_honeypot/rdp_honeypot/data
```

### 3. Install

```bash
# copy agent/ to the node, then:
sudo bash agent/install.sh
# installer auto-detects .env location, or:
sudo ENV_FILE=/path/to/.env bash agent/install.sh
```

This installs `/opt/honeypot-agent/agent.py` and a systemd timer that runs every 15 minutes.

### Agent environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CENTRAL_URL` | ✓ | — | URL of the central server |
| `CENTRAL_NODE_ID` | ✓ | — | Node identifier (must match the one registered in UI) |
| `CENTRAL_TOKEN` | ✓ | — | Auth token from the UI |
| `CENTRAL_DATA_DIR` | ✓ | — | Path to honeypot `data/` directory |
| `CENTRAL_INSECURE` | | `0` | Set to `1` to skip TLS verification |
| `CENTRAL_ANALYTICS_DAYS` | | `7` | How many days of analytics to include |

### Manual run / test

```bash
python3 /opt/honeypot-agent/agent.py

# heartbeat only (no data upload):
python3 /opt/honeypot-agent/agent.py --heartbeat

# check timer:
systemctl status honeypot-agent.timer
journalctl -u honeypot-agent.service -n 30
```

---

## Review workflow

```
node submits data
      ↓
  status: pending   ← visible in UI → Submissions
      ↓
  ✓ Approve  /  ✗ Reject
      ↓
  status: approved
      ↓
  Deploy → merged blocklist.txt written to ./central/data/public/
      ↓
  status: deployed
```

---

## Build Docker image manually

```bash
# Docker Hub
docker login
IMAGE=youruser/honeypot-central bash central/build-push.sh

# GHCR
docker login ghcr.io
IMAGE=ghcr.io/youruser/honeypot-central bash central/build-push.sh

# local build only (no push)
PUSH=0 bash central/build-push.sh
```

## CI/CD

Every push to `main` and every version tag (`v*`) triggers `.github/workflows/docker.yml` which builds a multi-arch image (`linux/amd64` + `linux/arm64`) and pushes it to `ghcr.io/robulanetteam/honeypot-central`.

---

## Repository layout

```
central/
  server.py            ← FastAPI + SQLite backend
  static/app.html      ← single-page web UI
  requirements.txt
  Dockerfile
  docker-compose.yml
  build-push.sh        ← manual build & push helper
  .env.example
agent/
  agent.py             ← honeypot node agent
  install.sh           ← systemd installer
  honeypot-agent.service
  honeypot-agent.timer
  .env.example         ← variables to add to honeypot .env
.github/workflows/
  docker.yml           ← GitHub Actions CI/CD
```
