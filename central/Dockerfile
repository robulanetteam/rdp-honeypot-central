FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY static/ ./static/

ENV DB_PATH=/data/central.db \
    DEPLOY_PATH=/data/public \
    STATIC_PATH=/app/static \
    ADMIN_TOKEN=change-me \
    ONLINE_SECS=900

VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
