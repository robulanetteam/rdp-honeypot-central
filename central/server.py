#!/usr/bin/env python3
"""
Honeypot Central Management Server

Collects data from distributed honeypot nodes, provides review workflow
and merged deployment to mirror.

Env vars:
  DB_PATH             – path to SQLite database (default: /data/central.db)
  DEPLOY_PATH         – directory where merged files are written (default: /data/public)
  STATIC_PATH         – path to static/ directory with app.html (default: /app/static)
  ADMIN_TOKEN         – admin secret for web UI (default: change-me)
  ONLINE_SECS         – seconds before node is considered offline (default: 900)
  MIKROTIK_LIST_NAME  – RouterOS address-list name (default: honeypot-block)
"""

import json
import hashlib
import time
import os
import secrets
import signal
import sqlite3
import time
import asyncio
import subprocess
import threading
import urllib.request
import urllib.parse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────────

DB_PATH            = Path(os.environ.get("DB_PATH",            "/data/central.db"))
DEPLOY_PATH        = Path(os.environ.get("DEPLOY_PATH",        "/data/public"))
STATIC_PATH        = Path(os.environ.get("STATIC_PATH",        "/app/static"))
ADMIN_TOKEN        = os.environ.get("ADMIN_TOKEN",             "change-me")
ONLINE_SECS        = int(os.environ.get("ONLINE_SECS",         "900"))
MIKROTIK_LIST_NAME = os.environ.get("MIKROTIK_LIST_NAME",      "honeypot-block")
HEARTBEAT_INTERVAL = int(os.environ.get("CENTRAL_HEARTBEAT_INTERVAL", "60"))  # agent HB period seconds

# Effective admin token: may be overridden from DB
_effective_admin_token: str = ADMIN_TOKEN


def _load_admin_token_from_db() -> None:
    """On startup: if admin_token is stored in settings DB, use it instead of env var."""
    global _effective_admin_token
    try:
        with get_db() as c:
            row = c.execute("SELECT value FROM settings WHERE key='admin_token'").fetchone()
        if row and row["value"]:
            _effective_admin_token = row["value"]
    except Exception:
        pass

# ── Database ───────────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            id                   TEXT PRIMARY KEY,
            label                TEXT NOT NULL,
            token                TEXT NOT NULL UNIQUE,
            last_seen            REAL,
            last_ip              TEXT,
            last_error           TEXT,
            auto_approve         INTEGER DEFAULT 0,
            auto_deploy          INTEGER DEFAULT 0,
            auto_score_threshold REAL    DEFAULT 70,
            created              REAL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id      TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
            submitted_at REAL DEFAULT (unixepoch()),
            content_hash TEXT NOT NULL,
            blocklist    TEXT,
            analytics    TEXT,
            status       TEXT DEFAULT 'pending',
            reviewed_at  REAL,
            note         TEXT,
            score        REAL
        );

        CREATE INDEX IF NOT EXISTS ix_sub_status ON submissions(status);
        CREATE INDEX IF NOT EXISTS ix_sub_node   ON submissions(node_id);

        CREATE TABLE IF NOT EXISTS deployments (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at REAL DEFAULT (unixepoch()),
            sub_ids    TEXT,
            ip_count   INTEGER,
            path       TEXT
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            ip       TEXT PRIMARY KEY,
            note     TEXT DEFAULT '',
            added_at REAL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         REAL DEFAULT (unixepoch()),
            node_id    TEXT,
            level      TEXT DEFAULT 'INFO',
            event      TEXT,
            detail     TEXT
        );

        CREATE INDEX IF NOT EXISTS ix_logs_ts      ON logs(ts DESC);
        CREATE INDEX IF NOT EXISTS ix_logs_node    ON logs(node_id);

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        """)


init_db()

# ── DB Migrations (safe ALTER TABLE for existing databases) ───────────────────
for _mig in [
    "ALTER TABLE nodes ADD COLUMN auto_approve         INTEGER DEFAULT 0",
    "ALTER TABLE nodes ADD COLUMN auto_deploy          INTEGER DEFAULT 0",
    "ALTER TABLE nodes ADD COLUMN auto_score_threshold REAL    DEFAULT 70",
    "ALTER TABLE submissions ADD COLUMN score          REAL",
    "ALTER TABLE nodes ADD COLUMN last_error           TEXT",
    "ALTER TABLE nodes ADD COLUMN agent_version        TEXT",
    "ALTER TABLE nodes ADD COLUMN last_auto_approved_at REAL",
    "ALTER TABLE nodes ADD COLUMN last_auto_deployed_at REAL",
    "ALTER TABLE nodes ADD COLUMN pending_cmd          TEXT",
]:
    try:
        with get_db() as _c:
            _c.execute(_mig)
    except sqlite3.OperationalError:
        pass  # column already exists

DEPLOY_PATH.mkdir(parents=True, exist_ok=True)
_load_admin_token_from_db()

# ── Offline-alert state (in-memory) ──────────────────────────────────────────
# node_id -> unix timestamp when offline alert was last sent
_offline_alerted: dict = {}

async def _check_node_heartbeats() -> None:
    """Background task: alert via Telegram when a node misses ≥2 heartbeats."""
    while True:
        await asyncio.sleep(HEARTBEAT_INTERVAL)
        try:
            now = time.time()
            threshold = 2 * HEARTBEAT_INTERVAL  # seconds without HB = "missed 2+"
            with get_db() as c:
                nodes = c.execute(
                    "SELECT id, label, last_seen FROM nodes"
                ).fetchall()
            for row in nodes:
                nid   = row["id"]
                label = row["label"] or nid
                ls    = row["last_seen"]
                offline = ls is None or (now - ls) > threshold
                if offline and nid not in _offline_alerted:
                    # First detection → send alert
                    ago = int(now - ls) if ls else None
                    ago_str = f"{ago // 60} мин {ago % 60} сек" if ago else "никогда"
                    notify_telegram(
                        f"\u26a0\ufe0f <b>Нода недоступна: {label}</b>\n"
                        f"ID: <code>{nid}</code>\n"
                        f"Последний heartbeat: {ago_str} назад\n"
                        f"(порог: {threshold}с / {threshold//60} мин)"
                    )
                    _offline_alerted[nid] = now
                    write_log(nid, "WARN", "offline_alert",
                              f"no heartbeat for {ago or 'unknown'}s")
                elif not offline and nid in _offline_alerted:
                    # Node recovered
                    del _offline_alerted[nid]
                    notify_telegram(
                        f"\u2705 <b>Нода восстановлена: {label}</b>\n"
                        f"ID: <code>{nid}</code>"
                    )
                    write_log(nid, "INFO", "online_recovery", "heartbeat resumed")
        except Exception as _e:
            pass  # never crash the loop


from contextlib import asynccontextmanager

@asynccontextmanager
async def _lifespan(app_):
    task = asyncio.create_task(_check_node_heartbeats())
    yield
    task.cancel()


# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Honeypot Central", docs_url=None, redoc_url=None, lifespan=_lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_PATH)), name="static")
app.mount("/pub",    StaticFiles(directory=str(DEPLOY_PATH)), name="public")

# ── Auth state ────────────────────────────────────────────────────────────────
# In-memory rate limiting: ip -> list of failure timestamps
_fail_times: dict = defaultdict(list)
RATE_WINDOW   = 300   # seconds
RATE_MAX_FAIL = 5     # max failures per window before lockout

# Track last successful admin login
_last_admin_login: dict = {}   # {"ip": ..., "ts": ...}

# ── Auth ───────────────────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[0].strip() if xff else (request.client.host or "unknown")


def require_admin(request: Request):
    tok = (request.headers.get("x-admin-token") or
           request.cookies.get("admin_token", ""))
    if not secrets.compare_digest(tok, _effective_admin_token):
        raise HTTPException(401, "Unauthorized")


def node_from_token(token: str) -> dict:
    with get_db() as c:
        row = c.execute("SELECT * FROM nodes WHERE token=?", (token,)).fetchone()
    if not row:
        raise HTTPException(403, "Unknown node token")
    return dict(row)


def write_log(node_id: Optional[str], level: str, event: str, detail: str = ""):
    with get_db() as c:
        c.execute(
            "INSERT INTO logs (node_id, level, event, detail) VALUES (?,?,?,?)",
            (node_id, level, event, detail[:2000]),
        )
        if level == "ERROR" and node_id:
            c.execute("UPDATE nodes SET last_error=? WHERE id=?", (detail[:500], node_id))


def _build_analytics_stats(events: list) -> dict:
    """Compute bruteforcer/scanner counts and top countries from analytics events."""
    types     = Counter(e.get("classification", "unknown") for e in events)
    countries = Counter(
        e.get("country", "") for e in events
        if e.get("country") and e.get("country") not in ("—", "")
    )
    top_c = ", ".join(f"{c}:{n}" for c, n in countries.most_common(5))
    return {
        "bruteforcers": types.get("bruteforcer", 0),
        "scanners":     types.get("scanner", 0),
        "countries":    top_c or "—",
    }


def _telegram_send_sync(bot_token: str, chat_id: str, text: str) -> None:
    try:
        url  = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id":    chat_id,
            "text":       text,
            "parse_mode": "HTML",
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        urllib.request.urlopen(req, timeout=6)
    except Exception as exc:
        write_log(None, "WARN", "telegram_error", str(exc)[:300])


def notify_telegram(text: str) -> None:
    """Fire-and-forget Telegram notification (reads token/chat from DB)."""
    try:
        with get_db() as c:
            tok = c.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
            cid = c.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
        if not tok or not cid or not tok["value"] or not cid["value"]:
            return
        threading.Thread(
            target=_telegram_send_sync,
            args=(tok["value"], cid["value"], text),
            daemon=True,
        ).start()
    except Exception:
        pass


def calculate_score(blocklist: str, analytics: list | None, deployed_ips: set) -> float:
    """Quality score 0–100 used for auto-approval decisions.

    Factors:
      +30  analytics data present
      +30  ≥20 unique IPs  |  +20  ≥5  |  +10  ≥1
      +25  ≥50% IPs are new (not yet deployed)  |  +10  ≥20%  |  -20  <5% (near-duplicate)
      +15  analytics density ≥5 events/IP  |  +8  ≥2
    """
    ips      = list({l.strip() for l in (blocklist or "").splitlines()
                     if l.strip() and not l.startswith("#")})
    ip_count = len(ips)
    an_count = len(analytics or [])
    score    = 0.0

    if an_count > 0:
        score += 30

    if ip_count >= 20:
        score += 30
    elif ip_count >= 5:
        score += 20
    elif ip_count >= 1:
        score += 10

    if ip_count > 0:
        new_count = len(set(ips) - deployed_ips) if deployed_ips else ip_count
        new_ratio = new_count / ip_count
        if new_ratio >= 0.5:
            score += 25
        elif new_ratio >= 0.2:
            score += 10
        elif new_ratio < 0.05 and deployed_ips:
            score -= 20  # almost all IPs already deployed — low value

    if ip_count > 0 and an_count > 0:
        density = an_count / ip_count
        if density >= 5:
            score += 15
        elif density >= 2:
            score += 8

    return round(max(0.0, min(100.0, score)), 1)

# ── Models ─────────────────────────────────────────────────────────────────────

class SubmitPayload(BaseModel):
    node_id:       str
    blocklist:     Optional[str]  = None   # raw text content of blocklist.txt
    analytics:     Optional[list] = None   # list of analytics event dicts
    agent_version: Optional[str]  = None   # e.g. "1.0.1"


class NodeAutoConfig(BaseModel):
    auto_approve:          Optional[bool]  = None
    auto_deploy:           Optional[bool]  = None
    auto_score_threshold:  Optional[float] = None

# ── Static UI ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return FileResponse(str(STATIC_PATH / "app.html"))

# ── Auth API ───────────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
async def api_login(request: Request):
    ip = _client_ip(request)
    now = time.time()

    # Purge old entries
    _fail_times[ip] = [t for t in _fail_times[ip] if now - t < RATE_WINDOW]

    if len(_fail_times[ip]) >= RATE_MAX_FAIL:
        retry_after = int(RATE_WINDOW - (now - _fail_times[ip][0]))
        write_log(None, "WARN", "login_blocked",
                  f"ip={ip} failures={len(_fail_times[ip])} retry_after={retry_after}s")
        raise HTTPException(429, f"Too many failed attempts. Try again in {retry_after}s")

    body = await request.json()
    tok  = str(body.get("token", ""))

    if not secrets.compare_digest(tok, _effective_admin_token):
        _fail_times[ip].append(now)
        remaining = max(0, RATE_MAX_FAIL - len(_fail_times[ip]))
        write_log(None, "WARN", "login_failed", f"ip={ip} attempts_left={remaining}")
        raise HTTPException(401, f"Invalid token. Attempts left: {remaining}")

    # Success — clear failures, record last login
    _fail_times.pop(ip, None)
    _last_admin_login["ip"] = ip
    _last_admin_login["ts"] = now
    write_log(None, "INFO", "login_success", f"ip={ip}")
    return {"ok": True}


@app.post("/api/auth/clear-fails")
async def api_auth_clear_fails(request: Request):
    """Clear all in-memory failed login attempts (unblock all IPs)."""
    require_admin(request)
    cleared = len(_fail_times)
    _fail_times.clear()
    write_log(None, "INFO", "login_fails_cleared", f"by={_client_ip(request)} count={cleared}")
    return {"cleared": cleared}


@app.post("/api/auth/change-token")
async def api_auth_change_token(request: Request):
    """Change the admin token (stored in DB, survives restarts)."""
    global _effective_admin_token
    require_admin(request)
    body = await request.json()
    new_token = str(body.get("new_token", "")).strip()
    if len(new_token) < 12:
        raise HTTPException(400, "Token must be at least 12 characters")
    with get_db() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_token', ?)", (new_token,))
    _effective_admin_token = new_token
    write_log(None, "INFO", "admin_token_changed", f"by={_client_ip(request)}")
    return {"ok": True}


@app.get("/api/auth/status")
async def api_auth_status(request: Request):
    require_admin(request)
    ip = _client_ip(request)
    now = time.time()

    # Recent failed IPs (within last 24h from logs)
    with get_db() as c:
        fail_rows = c.execute(
            """SELECT detail, ts FROM logs
               WHERE event='login_failed' AND ts > ?
               ORDER BY ts DESC LIMIT 50""",
            (now - 86400,),
        ).fetchall()

    fail_ips: dict = {}
    for r in fail_rows:
        # detail = "ip=1.2.3.4 attempts_left=N"
        for part in r["detail"].split():
            if part.startswith("ip="):
                fip = part[3:]
                if fip not in fail_ips:
                    fail_ips[fip] = {"ip": fip, "last_ts": r["ts"], "count": 0}
                fail_ips[fip]["count"] += 1

    blocked_ips = []
    for fip, ftimes in _fail_times.items():
        clean = [t for t in ftimes if now - t < RATE_WINDOW]
        if len(clean) >= RATE_MAX_FAIL:
            blocked_ips.append({"ip": fip, "until": int(clean[0] + RATE_WINDOW)})

    return {
        "client_ip":    ip,
        "last_login":   _last_admin_login.copy() if _last_admin_login else None,
        "failed_ips":   list(fail_ips.values()),
        "blocked_ips":  blocked_ips,
    }

# ═══════════════════════════════════════════════════════════════════════════════
# NODE API  (called by honeypot agents)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/submit")
async def api_submit(
    payload: SubmitPayload,
    request: Request,
    x_node_token: str = Header(...),
):
    """Honeypot node submits its current blocklist + analytics."""
    node = node_from_token(x_node_token)
    if node["id"] != payload.node_id:
        write_log(payload.node_id, "ERROR", "submit_rejected", "Token/node_id mismatch")
        raise HTTPException(403, "Token/node_id mismatch")

    content_hash = hashlib.sha256(
        json.dumps(
            {"b": payload.blocklist, "a": payload.analytics},
            sort_keys=True,
        ).encode()
    ).hexdigest()

    bl_count = len([l for l in (payload.blocklist or "").splitlines() if l.strip() and not l.startswith("#")])
    an_count = len(payload.analytics or [])

    with get_db() as c:
        # Update heartbeat + clear last_error on successful contact
        if payload.agent_version:
            c.execute(
                "UPDATE nodes SET last_seen=unixepoch(), last_ip=?, last_error=NULL, agent_version=? WHERE id=?",
                (request.client.host, payload.agent_version, node["id"]),
            )
        else:
            c.execute(
                "UPDATE nodes SET last_seen=unixepoch(), last_ip=?, last_error=NULL WHERE id=?",
                (request.client.host, node["id"]),
            )

        # Skip duplicate (same content already pending/approved)
        dup = c.execute(
            """SELECT id FROM submissions
               WHERE node_id=? AND content_hash=?
                 AND status NOT IN ('rejected','deployed')""",
            (node["id"], content_hash),
        ).fetchone()
        if dup:
            write_log(node["id"], "INFO", "submit_duplicate", f"sub_id={dup['id']} bl={bl_count} an={an_count}")
            return {"status": "duplicate", "submission_id": dup["id"]}

        cur = c.execute(
            """INSERT INTO submissions
               (node_id, content_hash, blocklist, analytics)
               VALUES (?,?,?,?)""",
            (
                node["id"],
                content_hash,
                payload.blocklist,
                json.dumps(payload.analytics) if payload.analytics else None,
            ),
        )
        sub_id = cur.lastrowid

    write_log(node["id"], "INFO", "submit_accepted", f"sub_id={sub_id} bl={bl_count} an={an_count}")

    # ── Calculate quality score ──────────────────────────────────────────────────
    deployed_ips: set = set()
    _dep_file = DEPLOY_PATH / "blocklist.txt"
    if _dep_file.exists():
        for _ln in _dep_file.read_text(encoding="utf-8", errors="replace").splitlines():
            _ip = _ln.strip()
            if _ip and not _ip.startswith("#"):
                deployed_ips.add(_ip)

    score = calculate_score(payload.blocklist or "", payload.analytics, deployed_ips)
    with get_db() as c:
        c.execute("UPDATE submissions SET score=? WHERE id=?", (score, sub_id))

    # ── Auto-approve / auto-deploy ─────────────────────────────────────────────
    auto_approve = bool(node.get("auto_approve", 0))
    auto_deploy  = bool(node.get("auto_deploy",  0))
    threshold    = float(node.get("auto_score_threshold") or 70)

    if auto_approve and score >= threshold:
        with get_db() as c:
            c.execute(
                "UPDATE submissions SET status='approved', reviewed_at=unixepoch() WHERE id=?",
                (sub_id,),
            )
        with get_db() as c:
            c.execute("UPDATE nodes SET last_auto_approved_at=unixepoch() WHERE id=?", (node["id"],))
        write_log(node["id"], "INFO", "auto_approved",
                  f"sub_id={sub_id} score={score} threshold={threshold}")

        # Telegram notification for auto-approve
        _st = _build_analytics_stats(payload.analytics or [])
        notify_telegram(
            f"✅ <b>Auto-approved</b>: {node['label']}\n"
            f"📋 Sub #{sub_id} | Score: {score}\n"
            f"🔒 IP: {bl_count}\n"
            f"🤖 Bruteforcers: {_st['bruteforcers']} | Scanners: {_st['scanners']}\n"
            f"🌍 {_st['countries']}"
        )

        if auto_deploy:
            try:
                dr = _do_deploy_internal(triggered_by=node["id"])
                with get_db() as c:
                    c.execute("UPDATE nodes SET last_auto_deployed_at=unixepoch() WHERE id=?", (node["id"],))
                # Auto-prune expired IPs after each auto-deploy
                try:
                    _do_prune_internal()
                except Exception as _pe:
                    write_log(node["id"], "WARN", "auto_prune_failed", str(_pe)[:200])
                return {
                    "status":        "auto_deployed",
                    "submission_id": sub_id,
                    "score":         score,
                    "deployed_ips":  dr["deployed_ips"],
                }
            except Exception as _e:
                write_log(node["id"], "WARN", "auto_deploy_failed",
                          f"sub_id={sub_id} error={str(_e)[:200]}")
        return {"status": "auto_approved", "submission_id": sub_id, "score": score}


    return {"status": "accepted", "submission_id": sub_id, "score": score}


@app.post("/api/tg/relay")
async def api_tg_relay(
    request: Request,
    x_node_token: str = Header(...),
):
    """Relay a Telegram notification from a honeypot node through the central server.
    Node sends: {"text": "...", "node_id": "..."}
    Central prepends the node label and forwards via notify_telegram().
    Deduplication: identical (node_id, text) ignored within 60 seconds.
    """
    node = node_from_token(x_node_token)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")
    text = str(body.get("text", "")).strip()
    if not text:
        raise HTTPException(400, "text is required")

    # Simple dedup: store hash of (node_id, text) with TTL=60s
    dedup_key = hashlib.sha256(f"{node['id']}:{text}".encode()).hexdigest()
    now_ts = time.time()
    # Clean old entries and check
    _tg_relay_dedup[dedup_key] = _tg_relay_dedup.get(dedup_key, 0)
    if now_ts - _tg_relay_dedup.get(dedup_key, 0) < 60:
        return {"status": "dedup_skip"}
    _tg_relay_dedup[dedup_key] = now_ts

    label = node.get("label") or node["id"]
    full_text = f"[<b>{label}</b>]\n{text}"
    notify_telegram(full_text)
    write_log(node["id"], "INFO", "tg_relay", text[:200])
    return {"status": "sent"}


# In-memory dedup store for tg relay (node_id+text hash -> timestamp)
_tg_relay_dedup: dict = {}


@app.post("/api/heartbeat")
async def api_heartbeat(
    request: Request,
    x_node_token: str = Header(...),
):
    """Lightweight heartbeat – updates last_seen without a full submission."""
    node = node_from_token(x_node_token)
    try:
        body = await request.json()
    except Exception:
        body = {}
    agent_version = body.get("agent_version") if body else None
    with get_db() as c:
        if agent_version:
            c.execute(
                "UPDATE nodes SET last_seen=unixepoch(), last_ip=?, last_error=NULL, agent_version=? WHERE id=?",
                (request.client.host, agent_version, node["id"]),
            )
        else:
            c.execute(
                "UPDATE nodes SET last_seen=unixepoch(), last_ip=?, last_error=NULL WHERE id=?",
                (request.client.host, node["id"]),
            )
        row = c.execute("SELECT pending_cmd FROM nodes WHERE id=?", (node["id"],)).fetchone()
        pending_cmd = row["pending_cmd"] if row else None
        if pending_cmd:
            c.execute("UPDATE nodes SET pending_cmd=NULL WHERE id=?", (node["id"],))
    write_log(node["id"], "INFO", "heartbeat", f"ip={request.client.host}")
    resp: dict = {"ok": True}
    if pending_cmd == "restart":
        resp["cmd"] = "restart"
        write_log(node["id"], "INFO", "cmd_delivered", "restart")
    elif pending_cmd == "update_agent":
        agent_url = str(request.url).split("/api/")[0] + "/pub/agent_dist/agent.py"
        resp["cmd"] = "update_agent"
        resp["agent_url"] = agent_url
        write_log(node["id"], "INFO", "cmd_delivered", "update_agent")
    return resp

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN API
# ═══════════════════════════════════════════════════════════════════════════════

# ── Nodes ──────────────────────────────────────────────────────────────────────

@app.get("/api/nodes")
async def api_get_nodes(request: Request):
    require_admin(request)
    now = time.time()
    with get_db() as c:
        rows = c.execute("""
            SELECT n.*,
                   COUNT(CASE WHEN s.status='pending'  THEN 1 END) AS pending_count,
                   COUNT(CASE WHEN s.status='approved' THEN 1 END) AS approved_count
            FROM nodes n
            LEFT JOIN submissions s ON s.node_id = n.id
            GROUP BY n.id
            ORDER BY n.last_seen DESC
        """).fetchall()

    result = []
    for r in rows:
        d = dict(r)
        d["online"] = bool(r["last_seen"] and (now - r["last_seen"]) < ONLINE_SECS)
        d["last_seen_ago"] = int(now - r["last_seen"]) if r["last_seen"] else None
        result.append(d)
    return result


@app.post("/api/nodes")
async def api_add_node(request: Request):
    require_admin(request)
    body = await request.json()
    node_id = str(body.get("node_id", "")).strip()
    label   = str(body.get("label",   "")).strip()
    if not node_id or not label:
        raise HTTPException(400, "node_id and label are required")

    token = secrets.token_hex(32)
    try:
        with get_db() as c:
            c.execute(
                "INSERT INTO nodes (id, label, token) VALUES (?,?,?)",
                (node_id, label, token),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Node ID already exists")

    write_log(node_id, "INFO", "node_registered", f"label={label}")
    return {"node_id": node_id, "token": token}


@app.delete("/api/nodes/{node_id}")
async def api_del_node(node_id: str, request: Request):
    require_admin(request)
    with get_db() as c:
        c.execute("DELETE FROM nodes WHERE id=?", (node_id,))
    write_log(node_id, "INFO", "node_deleted", "")
    return {"deleted": node_id}


@app.put("/api/nodes/{node_id}")
async def api_rename_node(node_id: str, request: Request):
    """Rename node_id and/or label. Updates all related rows in a transaction."""
    require_admin(request)
    body = await request.json()
    new_id    = str(body.get("node_id", "")).strip()
    new_label = str(body.get("label",   "")).strip()
    if not new_id or not new_label:
        raise HTTPException(400, "node_id and label are required")
    with get_db() as c:
        row = c.execute("SELECT id FROM nodes WHERE id=?", (node_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Node not found")
        if new_id != node_id:
            existing = c.execute("SELECT id FROM nodes WHERE id=?", (new_id,)).fetchone()
            if existing:
                raise HTTPException(409, f"Node ID '{new_id}' already exists")
            # Rename with FK temporarily disabled so cascade isn't needed
            c.execute("PRAGMA foreign_keys=OFF")
            c.execute("UPDATE nodes       SET id=?, label=? WHERE id=?", (new_id, new_label, node_id))
            c.execute("UPDATE submissions SET node_id=?    WHERE node_id=?", (new_id, node_id))
            c.execute("UPDATE logs        SET node_id=?    WHERE node_id=?", (new_id, node_id))
            c.execute("PRAGMA foreign_keys=ON")
        else:
            c.execute("UPDATE nodes SET label=? WHERE id=?", (new_label, node_id))
    write_log(new_id, "INFO", "node_renamed", f"old_id={node_id} label={new_label}")
    return {"node_id": new_id, "label": new_label}


@app.get("/api/nodes/{node_id}/token")
async def api_node_get_token(node_id: str, request: Request):
    """Return the node's CENTRAL_TOKEN (admin only)."""
    require_admin(request)
    with get_db() as c:
        row = c.execute("SELECT token FROM nodes WHERE id=?", (node_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Node not found")
    return {"node_id": node_id, "token": row["token"]}


@app.post("/api/nodes/{node_id}/token/regen")
async def api_node_regen_token(node_id: str, request: Request):
    """Generate a new token for the node. The old token stops working immediately."""
    require_admin(request)
    new_token = secrets.token_hex(32)
    with get_db() as c:
        rows_affected = c.execute(
            "UPDATE nodes SET token=? WHERE id=?", (new_token, node_id)
        ).rowcount
    if not rows_affected:
        raise HTTPException(404, "Node not found")
    write_log(node_id, "INFO", "node_token_regen", f"by_admin=true")
    return {"node_id": node_id, "token": new_token}


@app.patch("/api/nodes/{node_id}")
async def api_update_node(node_id: str, cfg: NodeAutoConfig, request: Request):
    """Update auto-approve / auto-deploy settings for a node."""
    require_admin(request)
    updates: list = []
    values:  list = []
    if cfg.auto_approve is not None:
        updates.append("auto_approve=?")
        values.append(int(cfg.auto_approve))
    if cfg.auto_deploy is not None:
        updates.append("auto_deploy=?")
        values.append(int(cfg.auto_deploy))
    if cfg.auto_score_threshold is not None:
        t = max(0.0, min(100.0, float(cfg.auto_score_threshold)))
        updates.append("auto_score_threshold=?")
        values.append(t)
    if not updates:
        raise HTTPException(400, "Nothing to update")
    values.append(node_id)
    with get_db() as c:
        c.execute(f"UPDATE nodes SET {', '.join(updates)} WHERE id=?", values)
    write_log(node_id, "INFO", "node_config",
              f"auto_approve={cfg.auto_approve} auto_deploy={cfg.auto_deploy} threshold={cfg.auto_score_threshold}")
    return {"updated": node_id}


@app.get("/api/nodes/{node_id}/ping")
async def api_ping_node(node_id: str, request: Request):
    """Ping the node's last known IP and return latency."""
    require_admin(request)
    with get_db() as c:
        row = c.execute("SELECT last_ip FROM nodes WHERE id=?", (node_id,)).fetchone()
    if not row or not row["last_ip"]:
        raise HTTPException(404, "No IP known for this node")
    ip = row["last_ip"]
    try:
        t0 = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", "2", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        elapsed = time.monotonic() - t0
        output = stdout.decode(errors="replace")
        reachable = proc.returncode == 0
        # parse avg rtt from ping output e.g. "rtt min/avg/max/mdev = 1.2/2.3/3.4/0.5 ms"
        avg_ms = None
        for line in output.splitlines():
            if "avg" in line and "=" in line:
                try:
                    avg_ms = float(line.split("=")[1].strip().split("/")[1])
                except Exception:
                    pass
        write_log(node_id, "INFO", "ping", f"ip={ip} reachable={reachable} avg_ms={avg_ms}")
        return {"ip": ip, "reachable": reachable, "avg_ms": avg_ms, "output": output}
    except asyncio.TimeoutError:
        write_log(node_id, "WARN", "ping_timeout", f"ip={ip}")
        return {"ip": ip, "reachable": False, "avg_ms": None, "output": "Timeout"}


# ── Logs ───────────────────────────────────────────────────────────────────────

@app.get("/api/logs")
async def api_get_logs(request: Request, node_id: str = "", limit: int = 200):
    require_admin(request)
    limit = min(limit, 1000)
    with get_db() as c:
        if node_id:
            rows = c.execute(
                "SELECT * FROM logs WHERE node_id=? ORDER BY ts DESC LIMIT ?",
                (node_id, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM logs ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]

# ── Whitelist ─────────────────────────────────────────────────────────────────

@app.get("/api/whitelist")
async def api_get_whitelist(request: Request):
    require_admin(request)
    with get_db() as c:
        rows = c.execute("SELECT ip, note, added_at FROM whitelist ORDER BY added_at DESC").fetchall()
    return [dict(r) for r in rows]


class WhitelistEntry(BaseModel):
    ip:   str
    note: str = ""


@app.post("/api/whitelist")
async def api_add_whitelist(entry: WhitelistEntry, request: Request):
    require_admin(request)
    ip = entry.ip.strip()
    if not ip:
        raise HTTPException(400, "IP is required")
    with get_db() as c:
        c.execute(
            "INSERT OR REPLACE INTO whitelist (ip, note) VALUES (?,?)",
            (ip, entry.note[:200]),
        )
    return {"added": ip}


@app.delete("/api/whitelist/{ip:path}")
async def api_del_whitelist(ip: str, request: Request):
    require_admin(request)
    with get_db() as c:
        c.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
    return {"removed": ip}


# ── Submissions ────────────────────────────────────────────────────────────────

@app.get("/api/submissions")
async def api_get_submissions(request: Request, status: str = "pending"):
    require_admin(request)
    allowed = {"pending", "approved", "rejected", "deployed"}
    if status not in allowed:
        raise HTTPException(400, "Invalid status")
    # "approved" tab shows approval history: both approved-and-waiting and already-deployed
    # (auto-approve+deploy transitions approved→deployed instantly, leaving tab empty otherwise)
    if status == "approved":
        where_clause = "s.status IN ('approved', 'deployed')"
        params: tuple = ()
    else:
        where_clause = "s.status = ?"
        params = (status,)
    with get_db() as c:
        rows = c.execute(f"""
            SELECT s.id, s.node_id, s.submitted_at, s.content_hash,
                   s.status, s.reviewed_at, s.note, s.score,
                   n.label AS node_label,
                   length(s.blocklist)  AS bl_size,
                   CASE WHEN s.analytics IS NOT NULL
                        THEN json_array_length(s.analytics) END AS analytics_count
            FROM submissions s
            JOIN nodes n ON s.node_id = n.id
            WHERE {where_clause}
            ORDER BY s.submitted_at DESC
            LIMIT 500
        """, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/submissions/{sub_id}")
async def api_get_submission(sub_id: int, request: Request):
    require_admin(request)
    with get_db() as c:
        row = c.execute("""
            SELECT s.*, n.label AS node_label
            FROM submissions s
            JOIN nodes n ON s.node_id = n.id
            WHERE s.id = ?
        """, (sub_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Submission not found")
    return dict(row)


@app.post("/api/submissions/{sub_id}/approve")
async def api_approve(sub_id: int, request: Request):
    require_admin(request)
    with get_db() as c:
        c.execute(
            "UPDATE submissions SET status='approved', reviewed_at=unixepoch() WHERE id=?",
            (sub_id,),
        )
    return {"approved": sub_id}


@app.post("/api/submissions/{sub_id}/reject")
async def api_reject(sub_id: int, request: Request):
    require_admin(request)
    body = await request.json()
    note = str(body.get("note", ""))[:500]
    with get_db() as c:
        c.execute(
            "UPDATE submissions SET status='rejected', reviewed_at=unixepoch(), note=? WHERE id=?",
            (note, sub_id),
        )
    return {"rejected": sub_id}


@app.patch("/api/submissions/{sub_id}")
async def api_update_submission(sub_id: int, request: Request):
    """Edit blocklist content of a pending submission."""
    require_admin(request)
    body = await request.json()
    blocklist = str(body.get("blocklist", ""))
    with get_db() as c:
        row = c.execute("SELECT status FROM submissions WHERE id=?", (sub_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Submission not found")
        if row["status"] != "pending":
            raise HTTPException(400, "Only pending submissions can be edited")
        c.execute("UPDATE submissions SET blocklist=? WHERE id=?", (blocklist, sub_id))
    return {"updated": sub_id}


@app.get("/api/submissions/{sub_id}/overlap")
async def api_overlap(sub_id: int, request: Request):
    """Return IP overlap stats with deployed blocklist and other pending/approved submissions."""
    require_admin(request)

    def parse_ips(text: str) -> set:
        if not text:
            return set()
        return {l.strip() for l in text.splitlines() if l.strip() and not l.startswith('#')}

    with get_db() as c:
        row = c.execute(
            "SELECT blocklist, node_id FROM submissions WHERE id=?", (sub_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Submission not found")

        sub_ips = parse_ips(row["blocklist"])

        deployed_ips: set = set()
        deployed_file = DEPLOY_PATH / "blocklist.txt"
        if deployed_file.exists():
            deployed_ips = parse_ips(
                deployed_file.read_text(encoding="utf-8", errors="replace")
            )

        others = c.execute("""
            SELECT s.id, s.blocklist, n.label AS node_label
            FROM submissions s JOIN nodes n ON s.node_id = n.id
            WHERE s.id != ? AND s.status IN ('pending','approved') AND s.blocklist IS NOT NULL
        """, (sub_id,)).fetchall()

    overlapping = []
    for o in others:
        o_ips = parse_ips(o["blocklist"])
        ov = len(sub_ips & o_ips)
        if ov:
            overlapping.append({"id": o["id"], "node_label": o["node_label"], "overlap": ov})

    new_ip_set = sub_ips - deployed_ips
    return {
        "total_ips":        len(sub_ips),
        "deployed_total":   len(deployed_ips),
        "deployed_overlap": len(sub_ips & deployed_ips),
        "new_ips":          len(new_ip_set),
        "new_ip_list":      sorted(new_ip_set),
        "other_submissions": overlapping,
    }

# ── Deploy ─────────────────────────────────────────────────────────────────────

@app.get("/api/deploy/preview")
async def api_deploy_preview(request: Request):
    """Show what a deploy would produce without writing anything."""
    require_admin(request)
    with get_db() as c:
        rows = c.execute("""
            SELECT s.blocklist, n.label
            FROM submissions s
            JOIN nodes n ON s.node_id = n.id
            WHERE s.status = 'approved'
        """).fetchall()
        wl = {r["ip"] for r in c.execute("SELECT ip FROM whitelist").fetchall()}

    ips: dict[str, str] = {}
    sources: set[str] = set()
    for row in rows:
        if row["blocklist"]:
            sources.add(row["label"])
            for line in row["blocklist"].splitlines():
                ip = line.strip()
                if ip and not ip.startswith("#") and ip not in wl:
                    ips.setdefault(ip, row["label"])

    return {
        "ip_count": len(ips),
        "sources":  sorted(sources),
    }


# ── Block-until metadata ───────────────────────────────────────────────────────

def _load_block_meta() -> dict:
    """Load {ip: block_until_iso_or_null} from blocklist_meta.json."""
    meta_file = DEPLOY_PATH / "blocklist_meta.json"
    if not meta_file.exists():
        return {}
    try:
        return json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_block_meta(meta: dict) -> None:
    (DEPLOY_PATH / "blocklist_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _scope_to_days(scope: int) -> int:
    if scope >= 70: return 60
    if scope >= 50: return 30
    if scope >= 25: return 7
    return 0


def _get_bu(val) -> Optional[str]:
    """Extract block_until ISO string from either old (str) or new (dict) meta format."""
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return val.get("until")


def _meta_from_analytics(rows) -> dict:
    """Build {ip: meta_entry} from analytics columns of submission rows.
    meta_entry = {"until": ISO, "at": ISO, "score": int, "days": int}
    Keeps the entry with the LONGEST block_until per IP.
    """
    meta: dict = {}
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    for row in rows:
        if not row["analytics"]:
            continue
        try:
            an_list = json.loads(row["analytics"]) or []
        except Exception:
            continue
        for entry in an_list:
            ip = entry.get("source_ip")
            bu = entry.get("block_until")
            if ip and bu:
                score = int(entry.get("scope") or 0)
                days  = _scope_to_days(score)
                if ip not in meta or bu > _get_bu(meta[ip]):
                    meta[ip] = {"until": bu, "at": now_iso, "score": score, "days": days}
    return meta


def _meta_merge(meta: dict, new_meta: dict) -> None:
    """Merge new_meta into meta, keeping the LONGEST block_until per IP."""
    for ip, new_val in new_meta.items():
        new_bu = _get_bu(new_val)
        old_bu = _get_bu(meta.get(ip))
        if old_bu is None or (new_bu and new_bu > old_bu):
            meta[ip] = new_val
        # else: keep old (longer) entry as-is


@app.post("/api/deploy")
async def api_deploy(request: Request):
    """Merge all approved submissions → write blocklist files → mark as deployed."""
    require_admin(request)
    return _do_deploy_internal()


def _do_deploy_internal(triggered_by: Optional[str] = None) -> dict:
    """Shared deploy logic. Called from api_deploy() and auto-deploy in api_submit()."""
    with get_db() as c:
        rows = c.execute("""
            SELECT s.id, s.blocklist, s.analytics, n.label
            FROM submissions s
            JOIN nodes n ON s.node_id = n.id
            WHERE s.status = 'approved'
        """).fetchall()

    if not rows:
        raise HTTPException(400, "No approved submissions to deploy")

    with get_db() as c:
        wl = {r["ip"] for r in c.execute("SELECT ip FROM whitelist").fetchall()}

    ips: dict[str, str] = {}
    now_ts = time.time()

    # Load block_until metadata from previous deploys
    meta = _load_block_meta()

    # Update meta from new submission analytics — keep longest block_until per IP
    new_meta = _meta_from_analytics(rows)
    _meta_merge(meta, new_meta)

    # Seed with currently deployed IPs — skip expired ones
    existing = DEPLOY_PATH / "blocklist.txt"
    _prev_ips: set = set()
    if existing.exists():
        for line in existing.read_text(encoding="utf-8", errors="replace").splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#") or ip in wl:
                continue
            block_until = _get_bu(meta.get(ip))
            if block_until:
                try:
                    if datetime.fromisoformat(block_until).timestamp() <= now_ts:
                        continue  # expired — remove from list
                except (ValueError, TypeError):
                    pass
            _prev_ips.add(ip)
            ips.setdefault(ip, "deployed")

    for row in rows:
        if row["blocklist"]:
            for line in row["blocklist"].splitlines():
                ip = line.strip()
                if not ip or ip.startswith("#") or ip in wl:
                    continue
                # Skip if IP is already known to be expired
                block_until = _get_bu(meta.get(ip))
                if block_until:
                    try:
                        if datetime.fromisoformat(block_until).timestamp() <= now_ts:
                            continue  # expired — do not re-add from submission
                    except (ValueError, TypeError):
                        pass
                ips.setdefault(ip, row["label"])

    # Ensure all IPs have a meta entry (null = no known expiry)
    for ip in ips:
        meta.setdefault(ip, None)

    DEPLOY_PATH.mkdir(parents=True, exist_ok=True)
    _save_block_meta(meta)
    sorted_ips = sorted(ips.keys())
    sources    = sorted({v for v in ips.values()})
    generated  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # ── plain text (one IP per line) ──────────────────────────────────────────
    (DEPLOY_PATH / "blocklist.txt").write_text(
        "\n".join(sorted_ips) + "\n"
    )

    # ── pfBlockerNG (plain IPs with header comment) ───────────────────────────
    pf_lines = [
        f"# Honeypot Central – pfBlockerNG blocklist",
        f"# Generated : {generated}",
        f"# Sources   : {', '.join(sources)}",
        f"# IPs       : {len(sorted_ips)}",
        "",
    ] + sorted_ips + [""]
    (DEPLOY_PATH / "blocklist_pfblocker.txt").write_text("\n".join(pf_lines))

    # ── MikroTik RouterOS script ──────────────────────────────────────────────
    mt_lines = [
        f"# Honeypot Central – MikroTik address-list",
        f"# Generated : {generated}",
        f"# Sources   : {', '.join(sources)}",
        f"# IPs       : {len(sorted_ips)}",
        f"# List name : {MIKROTIK_LIST_NAME}",
        "",
        f"/ip firewall address-list",
        f"remove [find list={MIKROTIK_LIST_NAME}]",
    ] + [
        f'add address={ip} list={MIKROTIK_LIST_NAME} comment="honeypot-central"'
        for ip in sorted_ips
    ] + [""]
    (DEPLOY_PATH / "blocklist_mikrotik.rsc").write_text("\n".join(mt_lines))

    sub_ids = [r["id"] for r in rows]
    placeholders = ",".join("?" * len(sub_ids))
    with get_db() as c:
        c.execute(
            f"UPDATE submissions SET status='deployed', reviewed_at=unixepoch() WHERE id IN ({placeholders})",
            sub_ids,
        )
        c.execute(
            "INSERT INTO deployments (sub_ids, ip_count, path) VALUES (?,?,?)",
            (json.dumps(sub_ids), len(ips), str(DEPLOY_PATH / "blocklist.txt")),
        )

    write_log(triggered_by, "INFO", "deploy",
              f"deployed_ips={len(ips)} sub_ids={sub_ids} triggered_by={triggered_by or 'admin'}")

    # Telegram notification for deploy
    _all_an: list = []
    for _row in rows:
        if _row["analytics"]:
            try:
                _all_an.extend(json.loads(_row["analytics"]) or [])
            except Exception:
                pass
    _st = _build_analytics_stats(_all_an)

    # Build per-IP info from analytics (last seen entry wins)
    _ip_info: dict = {}
    for _e in _all_an:
        _sip = (_e.get("source_ip") or "").strip()
        if not _sip:
            continue
        _ip_info[_sip] = {
            "country": (_e.get("country") or "")[:2].upper() or "??",
            "asn":     str(_e.get("asn") or ""),
            "cls":     _e.get("classification") or "unknown",
            "scope":   int(_e.get("scope") or 0),
        }

    # New IPs = added in this deploy that weren't in the previous blocklist
    _new_ips = sorted(set(ips.keys()) - _prev_ips)

    # Build IP list block (top 20 new IPs, sorted by scope desc)
    _new_with_info = []
    for _ip in _new_ips:
        _inf = _ip_info.get(_ip, {})
        _bu  = _get_bu(meta.get(_ip))  # block_until ISO string or None
        _bu_short = ""
        if _bu:
            try:
                _bu_short = datetime.fromisoformat(_bu).strftime("%d.%m.%Y")
            except Exception:
                _bu_short = _bu[:10]
        _new_with_info.append((_ip, _inf.get("scope", 0), _inf.get("country", "??"),
                               _inf.get("asn", ""), _inf.get("cls", "unknown"), _bu_short))
    _new_with_info.sort(key=lambda x: -x[1])
    _ip_lines = []
    for _ip, _scope, _country, _asn, _cls, _bu_short in _new_with_info[:20]:
        _asn_short = _asn.split(" ")[0] if _asn else "—"
        _until_str = f"  до {_bu_short}" if _bu_short else ""
        _block_days = 60 if _scope >= 70 else (30 if _scope >= 50 else (7 if _scope >= 25 else 0))
        _score_str = f"s{_scope}" + (f"/🕒{_block_days}d" if _block_days else "")
        _ip_lines.append(f"  <code>{_ip}</code>  {_country}  {_asn_short}  <i>{_cls}</i>  [{_score_str}]{_until_str}")
    _new_block = ""
    if _ip_lines:
        _more = len(_new_ips) - 20 if len(_new_ips) > 20 else 0
        _new_block = "\n<b>Новые IP (" + str(len(_new_ips)) + "):</b>\n" + "\n".join(_ip_lines)
        if _more:
            _new_block += f"\n  <i>...и ещё {_more}</i>"

    notify_telegram(
        "\U0001f680 <b>Deployed</b>"
        + (f" (auto: {triggered_by})" if triggered_by else " (manual)") + "\n"
        f"\U0001f512 IP в блоклисте: {len(ips)} (+{len(_new_ips)} новых)\n"
        f"\U0001f916 Bruteforcers: {_st['bruteforcers']} | Scanners: {_st['scanners']}\n"
        f"\U0001f30d {_st['countries']}"
        + _new_block
    )

    return {
        "deployed_ips":     len(ips),
        "files": {
            "plain":      "/pub/blocklist.txt",
            "pfblocker":  "/pub/blocklist_pfblocker.txt",
            "mikrotik":   "/pub/blocklist_mikrotik.rsc",
        },
        "from_submissions": sub_ids,
    }


def _do_prune_internal() -> dict:
    """Remove expired IPs from deployed blocklist. Returns result dict."""
    meta = _load_block_meta()
    if not meta:
        return {"pruned": 0, "remaining": 0, "message": "No metadata — nothing to prune"}

    with get_db() as c:
        wl = {r["ip"] for r in c.execute("SELECT ip FROM whitelist").fetchall()}

    now_ts = time.time()
    existing = DEPLOY_PATH / "blocklist.txt"
    if not existing.exists():
        return {"pruned": 0, "remaining": 0, "message": "No deployed blocklist found"}

    all_ips: list[str] = []
    for line in existing.read_text(encoding="utf-8", errors="replace").splitlines():
        ip = line.strip()
        if ip and not ip.startswith("#") and ip not in wl:
            all_ips.append(ip)

    active: list[str] = []
    pruned_ips: list[tuple] = []  # (ip, block_until_iso)
    for ip in all_ips:
        block_until = _get_bu(meta.get(ip))
        if block_until:
            try:
                if datetime.fromisoformat(block_until).timestamp() <= now_ts:
                    pruned_ips.append((ip, block_until))
                    continue
            except (ValueError, TypeError):
                pass
        active.append(ip)

    pruned_count = len(pruned_ips)
    if pruned_count == 0:
        return {"pruned": 0, "remaining": len(active), "message": "No expired IPs found"}

    sorted_ips = sorted(active)
    generated  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    (DEPLOY_PATH / "blocklist.txt").write_text("\n".join(sorted_ips) + "\n")
    pf_lines = [
        "# Honeypot Central – pfBlockerNG blocklist",
        f"# Generated : {generated}",
        f"# IPs       : {len(sorted_ips)}", "",
    ] + sorted_ips + [""]
    (DEPLOY_PATH / "blocklist_pfblocker.txt").write_text("\n".join(pf_lines))
    mt_lines = [
        "# Honeypot Central – MikroTik address-list",
        f"# Generated : {generated}",
        f"# IPs       : {len(sorted_ips)}",
        f"# List name : {MIKROTIK_LIST_NAME}", "",
        f"/ip firewall address-list",
        f"remove [find list={MIKROTIK_LIST_NAME}]",
    ] + [f'add address={ip} list={MIKROTIK_LIST_NAME} comment="honeypot-central"'
         for ip in sorted_ips] + [""]
    (DEPLOY_PATH / "blocklist_mikrotik.rsc").write_text("\n".join(mt_lines))

    # Clean meta: remove pruned IPs
    for ip, _ in pruned_ips:
        if ip in meta:
            del meta[ip]
    _save_block_meta(meta)

    write_log(None, "INFO", "prune_expired",
              f"pruned={pruned_count} remaining={len(active)}")

    # Telegram: notify about removed IPs
    _prune_lines = []
    for _ip, _bu in pruned_ips[:25]:
        try:
            _bu_fmt = datetime.fromisoformat(_bu).strftime("%d.%m.%Y")
        except Exception:
            _bu_fmt = str(_bu)[:10]
        _prune_lines.append(f"  <code>{_ip}</code>  (до {_bu_fmt})")
    _prune_block = "\n".join(_prune_lines)
    _more_pruned = pruned_count - 25 if pruned_count > 25 else 0
    if _more_pruned:
        _prune_block += f"\n  <i>...и ещё {_more_pruned}</i>"
    notify_telegram(
        f"\U0001f513 <b>Prune: разблокировано {pruned_count} IP</b>\n"
        f"\U0001f512 Остаётся в блоклисте: {len(active)}\n"
        + _prune_block
    )

    return {
        "pruned":      pruned_count,
        "pruned_ips":  [ip for ip, _ in pruned_ips],
        "remaining":   len(active),
        "message":     f"Removed {pruned_count} expired IP(s), {len(active)} remain",
    }


@app.post("/api/deploy/prune")
async def api_deploy_prune(request: Request):
    """Remove expired IPs from deployed blocklist without requiring new submissions."""
    require_admin(request)
    return _do_prune_internal()


@app.get("/api/blocklist/expiry")
async def api_blocklist_expiry(request: Request):
    """Return blocklist IPs with their block_until dates, enriched with analytics."""
    require_admin(request)
    meta = _load_block_meta()
    if not meta:
        return {"entries": [], "next_expiry": None}
    now_ts = time.time()

    # Build per-IP analytics index: ip -> {node_id, node_label, scope, classification}
    _ip_an: dict = {}
    with get_db() as c:
        rows_an = c.execute("""
            SELECT s.node_id, n.label AS node_label, s.analytics
            FROM submissions s JOIN nodes n ON s.node_id = n.id
            WHERE s.analytics IS NOT NULL
            ORDER BY s.submitted_at DESC
        """).fetchall()
    for row in rows_an:
        try:
            an_list = json.loads(row["analytics"]) or []
        except Exception:
            continue
        for e in an_list:
            sip = (e.get("source_ip") or "").strip()
            if not sip or sip in _ip_an:
                continue
            _ip_an[sip] = {
                "node_id":    row["node_id"],
                "node_label": row["node_label"] or row["node_id"],
                "scope":      int(e.get("scope") or 0),
                "cls":        e.get("classification") or "unknown",
            }

    entries = []
    for ip, val in meta.items():
        bu = _get_bu(val)
        if not bu:
            continue
        try:
            bu_ts = datetime.fromisoformat(bu).timestamp()
        except Exception:
            continue
        remaining_days = max(0, round((bu_ts - now_ts) / 86400, 1))
        # Extra fields from new-format meta entries
        blocked_at_iso  = val.get("at")  if isinstance(val, dict) else None
        block_score     = val.get("score") if isinstance(val, dict) else None
        block_days      = val.get("days")  if isinstance(val, dict) else None
        blocked_at_fmt  = ""
        if blocked_at_iso:
            try:
                blocked_at_fmt = datetime.fromisoformat(blocked_at_iso).strftime("%d.%m.%Y")
            except Exception:
                pass
        an = _ip_an.get(ip, {})
        entries.append({
            "ip":              ip,
            "block_until":     bu,
            "block_until_fmt": datetime.fromisoformat(bu).strftime("%d.%m.%Y"),
            "remaining_days":  remaining_days,
            "expired":         bu_ts <= now_ts,
            # Analytics (current)
            "node_id":         an.get("node_id", ""),
            "node_label":      an.get("node_label", "—"),
            "scope":           an.get("scope", 0),
            "cls":             an.get("cls", "unknown"),
            # Block origin (at deploy time)
            "blocked_at":      blocked_at_fmt,
            "block_score":     block_score,
            "block_days":      block_days,
        })
    entries.sort(key=lambda x: x["block_until"])
    next_expiry = None
    for e in entries:
        if not e["expired"]:
            next_expiry = e["block_until_fmt"]
            break
    return {"entries": entries, "next_expiry": next_expiry, "total": len(entries)}


def _rewrite_blocklist_without(remove_ips: set) -> int:
    """Remove IPs from deployed blocklist files and meta. Returns remaining count."""
    existing = DEPLOY_PATH / "blocklist.txt"
    if not existing.exists():
        return 0
    with get_db() as c:
        wl = {r["ip"] for r in c.execute("SELECT ip FROM whitelist").fetchall()}
    all_ips = []
    for line in existing.read_text(encoding="utf-8", errors="replace").splitlines():
        ip = line.strip()
        if ip and not ip.startswith("#"):
            all_ips.append(ip)
    active = [ip for ip in all_ips if ip not in remove_ips and ip not in wl]
    sorted_ips = sorted(set(active))
    generated  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    (DEPLOY_PATH / "blocklist.txt").write_text("\n".join(sorted_ips) + "\n")
    pf_lines = [
        "# Honeypot Central – pfBlockerNG blocklist",
        f"# Generated : {generated}",
        f"# IPs       : {len(sorted_ips)}", "",
    ] + sorted_ips + [""]
    (DEPLOY_PATH / "blocklist_pfblocker.txt").write_text("\n".join(pf_lines))
    mt_lines = [
        "# Honeypot Central – MikroTik address-list",
        f"# Generated : {generated}",
        f"# IPs       : {len(sorted_ips)}",
        f"# List name : {MIKROTIK_LIST_NAME}", "",
        f"/ip firewall address-list",
        f"remove [find list={MIKROTIK_LIST_NAME}]",
    ] + [f'add address={ip} list={MIKROTIK_LIST_NAME} comment="honeypot-central"'
         for ip in sorted_ips] + [""]
    (DEPLOY_PATH / "blocklist_mikrotik.rsc").write_text("\n".join(mt_lines))
    # Clean meta
    meta = _load_block_meta()
    for ip in remove_ips:
        meta.pop(ip, None)
    _save_block_meta(meta)
    return len(sorted_ips)


@app.delete("/api/blocklist/ip/{ip:path}")
async def api_blocklist_remove_ip(ip: str, request: Request):
    """Remove a single IP from the deployed blocklist immediately."""
    require_admin(request)
    ip = ip.strip()
    remaining = _rewrite_blocklist_without({ip})
    write_log(None, "INFO", "blocklist_remove", f"ip={ip} remaining={remaining}")
    return {"removed": ip, "remaining": remaining}


@app.get("/api/deployments")
async def api_deployments(request: Request):
    require_admin(request)
    with get_db() as c:
        rows = c.execute(
            "SELECT * FROM deployments ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    return [dict(r) for r in rows]


# ── Telegram settings ──────────────────────────────────────────────────────────

@app.get("/api/settings/telegram")
async def api_get_telegram_settings(request: Request):
    require_admin(request)
    with get_db() as c:
        tok = c.execute("SELECT value FROM settings WHERE key='telegram_bot_token'").fetchone()
        cid = c.execute("SELECT value FROM settings WHERE key='telegram_chat_id'").fetchone()
    return {
        "bot_token": tok["value"] if tok else "",
        "chat_id":   cid["value"] if cid else "",
    }


@app.post("/api/settings/telegram")
async def api_set_telegram_settings(request: Request):
    require_admin(request)
    body      = await request.json()
    bot_token = str(body.get("bot_token", "")).strip()
    chat_id   = str(body.get("chat_id",   "")).strip()
    with get_db() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_bot_token', ?)", (bot_token,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('telegram_chat_id', ?)",   (chat_id,))
    return {"ok": True}


@app.post("/api/settings/telegram/test")
async def api_test_telegram(request: Request):
    require_admin(request)
    notify_telegram("\U0001f9ea <b>Тест Honeypot Central</b>\nУведомления работают \u2713")
    return {"ok": True}


# ── Connections ────────────────────────────────────────────────────────────────

@app.get("/api/connections")
async def api_connections(request: Request, limit: int = 2000):
    """Return deduplicated analytics events from all submissions, sorted by timestamp DESC."""
    require_admin(request)
    limit = min(limit, 10000)
    with get_db() as c:
        rows = c.execute("""
            SELECT s.node_id, n.label AS node_label, s.analytics
            FROM submissions s
            JOIN nodes n ON s.node_id = n.id
            WHERE s.analytics IS NOT NULL
            ORDER BY s.submitted_at DESC
            LIMIT 200
        """).fetchall()

    seen: dict = {}   # ip -> event dict (first occurrence = most recent submission)
    for row in rows:
        try:
            an = json.loads(row["analytics"])
        except Exception:
            continue
        for e in an:
            ip = (e.get("source_ip") or "").strip()
            if not ip or ip in seen:
                continue
            ts = e.get("timestamp") or e.get("ts")
            seen[ip] = {
                "node_id":        row["node_id"],
                "node_label":     row["node_label"],
                "source_ip":      ip,
                "classification": e.get("classification", "unknown"),
                "country":        e.get("country") or "",
                "sessions_total": e.get("sessions_total"),
                "has_credentials": bool(e.get("has_credentials", False)),
                "ts":              ts,
            }

    events = sorted(seen.values(), key=lambda x: (x["ts"] or 0), reverse=True)
    return events[:limit]


# ── Reports ───────────────────────────────────────────────────────────────────

@app.get("/api/reports")
async def api_reports(request: Request):
    """Aggregate statistics for the Reports section."""
    require_admin(request)
    with get_db() as c:
        nodes = c.execute("SELECT id, label FROM nodes").fetchall()
        subs  = c.execute("""
            SELECT node_id, status, score, analytics, submitted_at
            FROM submissions
        """).fetchall()
        deps  = c.execute("SELECT sub_ids, ip_count, created_at FROM deployments ORDER BY created_at DESC").fetchall()

    # Per-node stats
    node_map = {n["id"]: {"id": n["id"], "label": n["label"],
                           "submissions": 0, "deployed": 0, "total_ips": 0,
                           "deploy_count": 0, "last_deployed": None} for n in nodes}

    # Count deployments per node
    for d in deps:
        sub_ids = json.loads(d["sub_ids"] or "[]")
        # approximate: find which nodes had subs deployed
        with get_db() as c2:
            for sid in sub_ids:
                sr = c2.execute("SELECT node_id FROM submissions WHERE id=?", (sid,)).fetchone()
                if sr and sr["node_id"] in node_map:
                    node_map[sr["node_id"]]["deploy_count"] += 1
                    node_map[sr["node_id"]]["total_ips"]    += d["ip_count"]
                    ts = d["created_at"]
                    prev = node_map[sr["node_id"]]["last_deployed"]
                    if prev is None or ts > prev:
                        node_map[sr["node_id"]]["last_deployed"] = ts

    for row in subs:
        nid = row["node_id"]
        if nid not in node_map:
            continue
        node_map[nid]["submissions"] += 1
        if row["status"] in ("deployed", "approved"):
            node_map[nid]["deployed"] += 1

    node_stats = sorted(node_map.values(), key=lambda x: -x["deploy_count"])

    # Global IP analytics from all submissions
    seen_ips: dict = {}
    local_ips: dict = {}
    for row in subs:
        if not row["analytics"]:
            continue
        try:
            an = json.loads(row["analytics"])
        except Exception:
            continue
        for e in an:
            ip = (e.get("source_ip") or "").strip()
            if not ip:
                continue
            is_local = bool(e.get("is_local", False))
            target = local_ips if is_local else seen_ips
            if ip not in target:
                target[ip] = {
                    "ip":             ip,
                    "count":          0,
                    "classification": e.get("classification", "unknown"),
                    "country":        e.get("country") or "",
                    "max_sessions":   0,
                    "has_credentials": False,
                    "node_id":        row["node_id"],
                    "last_seen":      e.get("timestamp") or "",
                }
            target[ip]["count"] += 1
            target[ip]["max_sessions"] = max(target[ip]["max_sessions"], e.get("sessions_total") or 0)
            if e.get("has_credentials"):
                target[ip]["has_credentials"] = True
            if e.get("timestamp") and e["timestamp"] > target[ip]["last_seen"]:
                target[ip]["last_seen"] = e["timestamp"]
            # last classification wins (most recent sub processed last — subs ordered DESC, so first is recent)

    top_ips = sorted(seen_ips.values(), key=lambda x: (-x["count"], -x["max_sessions"]))[:200]
    local_intruders = sorted(local_ips.values(), key=lambda x: (-x["count"], x["ip"]))[:200]

    # Global counters
    total_subs     = len(subs)
    total_deployed = sum(1 for s in subs if s["status"] in ("deployed", "approved"))
    deployed_ip_count = 0
    existing = DEPLOY_PATH / "blocklist.txt"
    if existing.exists():
        deployed_ip_count = sum(
            1 for line in existing.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.startswith("#")
        )
    cred_count = sum(
        1 for ip in seen_ips.values() if ip["has_credentials"]
    )

    # Classification breakdown across all analytics
    cls_counts: dict = {}
    for ip in seen_ips.values():
        c = ip["classification"] or "unknown"
        cls_counts[c] = cls_counts.get(c, 0) + 1

    # Country breakdown top-10
    country_counts: dict = {}
    for ip in seen_ips.values():
        co = ip["country"] or "Unknown"
        country_counts[co] = country_counts.get(co, 0) + 1
    top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:10]

    return {
        "global": {
            "total_submissions": total_subs,
            "total_deployed":    total_deployed,
            "deployed_ip_count": deployed_ip_count,
            "unique_ips_seen":   len(seen_ips),
            "cred_captures":     cred_count,
            "classification":    cls_counts,
            "top_countries":     [{"country": k, "count": v} for k, v in top_countries],
        },
        "nodes":   node_stats,
        "top_ips": top_ips,
        "local_intruders": local_intruders,
    }


# ── Node commands (restart / update_agent) ────────────────────────────────────

@app.post("/api/nodes/{node_id}/cmd")
async def api_node_cmd(node_id: str, request: Request):
    """Queue a command for a node (restart or update_agent). Delivered on next heartbeat."""
    require_admin(request)
    body = await request.json()
    cmd = body.get("cmd", "")
    if cmd not in ("restart", "update_agent"):
        raise HTTPException(400, "cmd must be 'restart' or 'update_agent'")
    if cmd == "update_agent":
        dist = DEPLOY_PATH / "agent_dist" / "agent.py"
        if not dist.exists():
            raise HTTPException(400, "No agent distribution uploaded yet")
    with get_db() as c:
        row = c.execute("SELECT id FROM nodes WHERE id=?", (node_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Node not found")
        c.execute("UPDATE nodes SET pending_cmd=? WHERE id=?", (cmd, node_id))
    write_log(node_id, "INFO", "cmd_queued", f"cmd={cmd}")
    return {"queued": cmd, "node_id": node_id}


# ── Agent distribution upload ─────────────────────────────────────────────────

@app.post("/api/agent-dist")
async def api_upload_agent_dist(request: Request, file: UploadFile = File(...)):
    """Upload a new agent.py to serve as distribution for honeypot nodes."""
    require_admin(request)
    if file.filename and not file.filename.endswith(".py"):
        raise HTTPException(400, "Only .py files accepted")
    content = await file.read()
    if len(content) > 500_000:
        raise HTTPException(400, "File too large (max 500 KB)")
    # Basic sanity: must look like Python
    if b"def " not in content and b"import " not in content:
        raise HTTPException(400, "File does not appear to be Python source")
    dist_dir = DEPLOY_PATH / "agent_dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "agent.py").write_bytes(content)
    # Extract AGENT_VERSION from the file if present
    version = "unknown"
    for line in content.decode(errors="replace").splitlines():
        if line.strip().startswith("AGENT_VERSION"):
            try:
                version = line.split("=")[1].strip().strip("\"'")
            except Exception:
                pass
            break
    write_log(None, "INFO", "agent_dist_uploaded", f"size={len(content)} version={version}")
    return {"ok": True, "version": version, "size": len(content)}


@app.get("/api/agent-dist/info")
async def api_agent_dist_info(request: Request):
    """Return info about the currently uploaded agent distribution."""
    require_admin(request)
    dist = DEPLOY_PATH / "agent_dist" / "agent.py"
    if not dist.exists():
        return {"available": False}
    stat = dist.stat()
    content = dist.read_text(errors="replace")
    version = "unknown"
    for line in content.splitlines():
        if line.strip().startswith("AGENT_VERSION"):
            try:
                version = line.split("=")[1].strip().strip("\"'")
            except Exception:
                pass
            break
    return {
        "available": True,
        "version":   version,
        "size":      stat.st_size,
        "updated_at": stat.st_mtime,
    }


# ── Central self-restart ──────────────────────────────────────────────────────

async def _delayed_restart():
    await asyncio.sleep(1.2)
    os.kill(os.getpid(), signal.SIGTERM)


@app.post("/api/admin/restart-central")
async def api_restart_central(request: Request):
    """Send SIGTERM to the current process (supervisord/Docker will restart it)."""
    require_admin(request)
    write_log(None, "WARN", "central_restart", "admin triggered restart")
    asyncio.create_task(_delayed_restart())
    return {"ok": True, "message": "Central restarting in ~1 second"}
