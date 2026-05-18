FROM python:3.12-slim

WORKDIR /app

# Install system deps: openssl (self-signed) + certbot (Let's Encrypt) + ping
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        certbot \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY static/ ./static/
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DB_PATH=/data/central.db \
    DEPLOY_PATH=/data/public \
    STATIC_PATH=/app/static \
    ADMIN_TOKEN=change-me \
    ONLINE_SECS=900 \
    PORT=8000

VOLUME ["/data"]
EXPOSE 8000 80

ENTRYPOINT ["/entrypoint.sh"]
