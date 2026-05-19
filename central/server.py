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
import os
import secrets
import sqlite3
import time
import asyncio
import subprocess
import threading
import urllib.request
import urllib.parse
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
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
]:
    try:
        with get_db() as _c:
            _c.execute(_mig)
    except sqlite3.OperationalError:
        pass  # column already exists

DEPLOY_PATH.mkdir(parents=True, exist_ok=True)

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Honeypot Central", docs_url=None, redoc_url=None)
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
    if tok != ADMIN_TOKEN:
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
    node_id:   str
    blocklist: Optional[str] = None   # raw text content of blocklist.txt
    analytics: Optional[list] = None  # list of analytics event dicts


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

    if not secrets.compare_digest(tok, ADMIN_TOKEN):
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


@app.post("/api/heartbeat")
async def api_heartbeat(
    request: Request,
    x_node_token: str = Header(...),
):
    """Lightweight heartbeat – updates last_seen without a full submission."""
    node = node_from_token(x_node_token)
    with get_db() as c:
        c.execute(
            "UPDATE nodes SET last_seen=unixepoch(), last_ip=?, last_error=NULL WHERE id=?",
            (request.client.host, node["id"]),
        )
    write_log(node["id"], "INFO", "heartbeat", f"ip={request.client.host}")
    return {"ok": True}

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
    with get_db() as c:
        rows = c.execute("""
            SELECT s.id, s.node_id, s.submitted_at, s.content_hash,
                   s.status, s.reviewed_at, s.note, s.score,
                   n.label AS node_label,
                   length(s.blocklist)  AS bl_size,
                   CASE WHEN s.analytics IS NOT NULL
                        THEN json_array_length(s.analytics) END AS analytics_count
            FROM submissions s
            JOIN nodes n ON s.node_id = n.id
            WHERE s.status = ?
            ORDER BY s.submitted_at DESC
            LIMIT 500
        """, (status,)).fetchall()
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


def _meta_from_analytics(rows) -> dict:
    """Build {ip: block_until_iso} from analytics columns of submission rows."""
    meta: dict = {}
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
                # Keep the latest (longest) block_until if multiple entries for same IP
                if ip not in meta or bu > meta[ip]:
                    meta[ip] = bu
    return meta


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

    # Update meta from new submission analytics (before seeding, so new data overrides old)
    new_meta = _meta_from_analytics(rows)
    meta.update(new_meta)

    # Seed with currently deployed IPs — skip expired ones
    existing = DEPLOY_PATH / "blocklist.txt"
    if existing.exists():
        for line in existing.read_text(encoding="utf-8", errors="replace").splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#") or ip in wl:
                continue
            block_until = meta.get(ip)
            if block_until:
                try:
                    if datetime.fromisoformat(block_until).timestamp() <= now_ts:
                        continue  # expired — remove from list
                except (ValueError, TypeError):
                    pass
            ips.setdefault(ip, "deployed")

    for row in rows:
        if row["blocklist"]:
            for line in row["blocklist"].splitlines():
                ip = line.strip()
                if not ip or ip.startswith("#") or ip in wl:
                    continue
                # Skip if IP is already known to be expired
                block_until = meta.get(ip)
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
    notify_telegram(
        f"\U0001f680 <b>Deployed</b>" + (f" (auto: {triggered_by})" if triggered_by else " (manual)") + "\n"
        f"\U0001f512 IP в блоклисте: {len(ips)}\n"
        f"\U0001f916 Bruteforcers: {_st['bruteforcers']} | Scanners: {_st['scanners']}\n"
        f"\U0001f30d {_st['countries']}"
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


@app.post("/api/deploy/prune")
async def api_deploy_prune(request: Request):
    """Remove expired IPs from deployed blocklist without requiring new submissions."""
    require_admin(request)

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
    pruned_count = 0
    for ip in all_ips:
        block_until = meta.get(ip)
        if block_until:
            try:
                if datetime.fromisoformat(block_until).timestamp() <= now_ts:
                    pruned_count += 1
                    continue
            except (ValueError, TypeError):
                pass
        active.append(ip)

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
    for ip in all_ips:
        if ip not in active and ip in meta:
            del meta[ip]
    _save_block_meta(meta)

    write_log(None, "INFO", "prune_expired",
              f"pruned={pruned_count} remaining={len(active)}")

    return {
        "pruned":    pruned_count,
        "remaining": len(active),
        "message":   f"Removed {pruned_count} expired IP(s), {len(active)} remain",
    }


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
