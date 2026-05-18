#!/usr/bin/env sh
# Honeypot Central – entrypoint
# Generates TLS certificate (self-signed or Let's Encrypt) then starts uvicorn over HTTPS.
set -e

CERT_DIR="/data/certs"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

mkdir -p "$CERT_DIR"

# ── Certificate provisioning ──────────────────────────────────────────────────

if [ -n "$CERTBOT_DOMAIN" ] && [ -n "$CERTBOT_EMAIL" ]; then
    # ── Let's Encrypt via certbot ──────────────────────────────────────────
    echo "[entrypoint] Requesting Let's Encrypt certificate for $CERTBOT_DOMAIN ..."

    STAGING_FLAG=""
    if [ "${CERTBOT_STAGING:-0}" = "1" ]; then
        STAGING_FLAG="--staging"
        echo "[entrypoint] Using Let's Encrypt STAGING environment"
    fi

    # certbot standalone needs port 80 free; use --http-01-port if overridden
    HTTP01_PORT="${CERTBOT_HTTP_PORT:-80}"

    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$CERTBOT_EMAIL" \
        --domain "$CERTBOT_DOMAIN" \
        --http-01-port "$HTTP01_PORT" \
        $STAGING_FLAG

    LE_LIVE="/etc/letsencrypt/live/$CERTBOT_DOMAIN"
    cp "$LE_LIVE/fullchain.pem" "$CERT_FILE"
    cp "$LE_LIVE/privkey.pem"   "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo "[entrypoint] Certificate installed: $CERT_FILE"

    # Schedule renewal: re-exec this script after 12h (simple cron-free loop)
    (
        while true; do
            sleep 43200
            certbot renew --quiet --standalone --http-01-port "$HTTP01_PORT" $STAGING_FLAG \
                && cp "$LE_LIVE/fullchain.pem" "$CERT_FILE" \
                && cp "$LE_LIVE/privkey.pem"   "$KEY_FILE" \
                && chmod 600 "$KEY_FILE" \
                && echo "[renew] Certificate renewed"
        done
    ) &

else
    # ── Self-signed certificate (10 years) ────────────────────────────────
    if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
        echo "[entrypoint] Generating self-signed certificate (10 years) ..."
        SUBJ="/CN=${SSL_CN:-honeypot-central}/O=HoneypotCentral/OU=Self-Signed"
        openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
            -keyout "$KEY_FILE" \
            -out    "$CERT_FILE" \
            -subj   "$SUBJ" \
            -nodes
        echo "[entrypoint] Self-signed certificate generated: $CERT_FILE"
    else
        echo "[entrypoint] Reusing existing certificate: $CERT_FILE"
    fi
fi

# ── Start uvicorn with TLS ─────────────────────────────────────────────────────

echo "[entrypoint] Starting uvicorn (HTTPS) on port ${PORT:-8000} ..."
exec uvicorn server:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --ssl-certfile "$CERT_FILE" \
    --ssl-keyfile  "$KEY_FILE"
