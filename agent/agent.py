#!/usr/bin/env python3
"""
Honeypot node agent

Reads blocklist.txt and analytics.jsonl from the local honeypot data directory
and submits them to the Honeypot Central server.

Configuration via environment variables (loaded by systemd EnvironmentFile
pointing to your honeypot's .env):

  CENTRAL_URL        URL of Honeypot Central server  (required)
  CENTRAL_NODE_ID    Unique node identifier           (required)
  CENTRAL_TOKEN      Auth token from Central UI       (required)
  CENTRAL_DATA_DIR   Path to honeypot data dir        (required)
  CENTRAL_INSECURE   Skip TLS verify (1/true)         (optional)
  CENTRAL_ANALYTICS_DAYS   How many days of analytics to send (default: 7)

Cache:  /var/lib/honeypot-agent/last_hash  (skip re-submit if data unchanged)
"""

import hashlib
import gzip
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

CACHE_PATH     = Path(os.environ.get("AGENT_CACHE", "/var/lib/honeypot-agent/last_hash"))
HEARTBEAT_ONLY = "--heartbeat" in sys.argv

# ── Logging ────────────────────────────────────────────────────────────────────

def log(level: str, msg: str):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {level:5s} {msg}", flush=True)


# ── Config loading from env ────────────────────────────────────────────────────

def load_config() -> dict:
    cfg = {
        "server_url":      os.environ.get("CENTRAL_URL", "").rstrip("/"),
        "node_id":         os.environ.get("CENTRAL_NODE_ID", ""),
        "token":           os.environ.get("CENTRAL_TOKEN", ""),
        "data_dir":        os.environ.get("CENTRAL_DATA_DIR", ""),
        "insecure_ssl":    os.environ.get("CENTRAL_INSECURE", "").lower() in ("1", "true", "yes"),
        "analytics_days":  int(os.environ.get("CENTRAL_ANALYTICS_DAYS", "7")),
    }
    missing = [k for k, v in cfg.items()
               if k in ("server_url", "node_id", "token", "data_dir") and not v]
    if missing:
        log("ERROR", f"Missing environment variables: {[k.upper().replace('_url','_URL').replace('node','NODE').replace('token','TOKEN').replace('data_dir','DATA_DIR') for k in missing]}")
        log("ERROR", "Add CENTRAL_URL / CENTRAL_NODE_ID / CENTRAL_TOKEN / CENTRAL_DATA_DIR to your .env")
        sys.exit(1)
    return cfg


# ── Data collection ────────────────────────────────────────────────────────────

def read_blocklist(data_dir: Path) -> str:
    """Return content of public/blocklist.txt, or empty string."""
    p = data_dir / "public" / "blocklist.txt"
    if not p.exists():
        log("WARN", f"blocklist.txt not found at {p}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace").strip()


def _rotate_analytics_log(p: Path, max_bytes: int = 5 * 1024 * 1024, keep_days: int = 1):
    """If analytics.jsonl exceeds max_bytes, gzip-archive it and keep only recent entries."""
    try:
        if p.stat().st_size <= max_bytes:
            return
        cutoff = time.time() - keep_days * 86400
        # Read all lines, split into recent (keep) and old (archive)
        recent_lines = []
        old_lines = []
        import datetime
        with p.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                keep = False
                try:
                    obj = json.loads(stripped)
                    ts = obj.get("timestamp") or obj.get("ts") or obj.get("time")
                    if ts is None:
                        keep = True
                    elif isinstance(ts, (int, float)):
                        keep = ts >= cutoff
                    else:
                        ts_epoch = datetime.datetime.fromisoformat(str(ts)[:19]).replace(
                            tzinfo=datetime.timezone.utc).timestamp()
                        keep = ts_epoch >= cutoff
                except Exception:
                    keep = True
                (recent_lines if keep else old_lines).append(stripped)
        # Archive old lines to a gzipped file
        archive_name = p.parent / f"analytics.{time.strftime('%Y%m%d_%H%M%S')}.jsonl.gz"
        with gzip.open(archive_name, "wt", encoding="utf-8") as gz:
            for line in old_lines:
                gz.write(line + "\n")
        # Rewrite analytics.jsonl with only recent lines
        p.write_text("\n".join(recent_lines) + ("\n" if recent_lines else ""), encoding="utf-8")
        log("INFO", f"Log rotated: archived {len(old_lines)} old events → {archive_name.name}, kept {len(recent_lines)} recent")
    except Exception as e:
        log("WARN", f"Log rotation failed: {e}")


def read_analytics(data_dir: Path, days: int = 7) -> list:
    """Return analytics events from the last `days` days."""
    p = data_dir / "logs" / "analytics.jsonl"
    if not p.exists():
        return []
    _rotate_analytics_log(p)
    cutoff = time.time() - days * 86400
    events = []
    try:
        with p.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Accept event if timestamp >= cutoff, or if no parseable ts
                    ts = obj.get("timestamp") or obj.get("ts") or obj.get("time")
                    if ts is None:
                        events.append(obj)
                    elif isinstance(ts, (int, float)):
                        if ts >= cutoff:
                            events.append(obj)
                    else:
                        # ISO string: parse epoch from first 19 chars "YYYY-MM-DDTHH:MM:SS"
                        try:
                            import datetime
                            ts_epoch = datetime.datetime.fromisoformat(str(ts)[:19]).replace(
                                tzinfo=datetime.timezone.utc).timestamp()
                            if ts_epoch >= cutoff:
                                events.append(obj)
                        except Exception:
                            events.append(obj)  # can't parse → include anyway
                except json.JSONDecodeError:
                    pass
    except OSError as e:
        log("WARN", f"Cannot read analytics.jsonl: {e}")
    return events


# ── Hash cache ─────────────────────────────────────────────────────────────────

def load_last_hash() -> str:
    try:
        return CACHE_PATH.read_text().strip()
    except OSError:
        return ""


def save_hash(h: str):
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(h)


def compute_hash(blocklist: str, analytics: list) -> str:
    raw = json.dumps({"b": blocklist, "a": analytics}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


# ── HTTP requests ──────────────────────────────────────────────────────────────

def make_ssl_ctx(insecure: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def post_json(url: str, token: str, body: dict, insecure: bool = False) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Node-Token": token,
        },
        method="POST",
    )
    ctx = make_ssl_ctx(insecure)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"HTTP {e.code}: {body_text}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection error: {e.reason}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    cfg = load_config()
    base_url = cfg["server_url"].rstrip("/")
    insecure = bool(cfg.get("insecure_ssl", False))

    if HEARTBEAT_ONLY:
        # Just ping the server to update last_seen without a full submission
        log("INFO", f"Sending heartbeat for node={cfg['node_id']}")
        try:
            post_json(f"{base_url}/api/heartbeat", cfg["token"], {}, insecure)
            log("INFO", "Heartbeat OK")
        except RuntimeError as e:
            log("ERROR", str(e))
            sys.exit(1)
        return

    log("INFO", f"Agent starting for node={cfg['node_id']}")

    data_dir  = Path(cfg["data_dir"])

    # Rotate connections.jsonl if it exceeds 5MB
    conn_log = data_dir / "logs" / "connections.jsonl"
    if conn_log.exists():
        _rotate_analytics_log(conn_log)

    blocklist = read_blocklist(data_dir)
    analytics = read_analytics(data_dir, days=cfg["analytics_days"])
    log("INFO", f"Collected {len(blocklist.splitlines())} blocklist lines, {len(analytics)} analytics events")

    current_hash = compute_hash(blocklist, analytics)
    if current_hash == load_last_hash():
        log("INFO", "Data unchanged since last submission — sending heartbeat only")
        try:
            post_json(f"{base_url}/api/heartbeat", cfg["token"], {}, insecure)
            log("INFO", "Heartbeat OK")
        except RuntimeError as e:
            log("ERROR", str(e))
            sys.exit(1)
        return

    try:
        result = post_json(
            f"{base_url}/api/submit",
            cfg["token"],
            {
                "node_id":   cfg["node_id"],
                "blocklist": blocklist,
                "analytics": analytics,
            },
            insecure,
        )
    except RuntimeError as e:
        log("ERROR", str(e))
        sys.exit(1)

    status = result.get("status")
    sub_id = result.get("submission_id")

    if status in ("accepted", "auto_approved", "auto_deployed"):
        save_hash(current_hash)
        log("INFO", f"Accepted  submission_id={sub_id} status={status}")
    elif status == "duplicate":
        save_hash(current_hash)
        log("INFO", f"Duplicate submission_id={sub_id} (already pending/approved)")
    else:
        log("ERROR", f"Unexpected response: {result}")
        sys.exit(1)


if __name__ == "__main__":
    main()
