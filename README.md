# Honeypot Central

Централизованное управление распределёнными RDP-honeypot нодами.

На каждой ноде работает лёгкий агент, который периодически отправляет `blocklist.txt` и аналитику на центральный сервер. В веб-интерфейсе вы проверяете входящие данные, одобряете или отклоняете их, затем одним кликом деплоите объединённый blocklist на своё зеркало.

```
Нода 1 ──┐
Нода 2 ──┼──► Центральный сервер (веб-интерфейс) ──► blocklist.txt (зеркало)
Нода N ──┘
```

## Возможности

- **Реестр нод** — регистрация нод, выдача уникальных токенов
- **Статус онлайн/оффлайн** — нода считается оффлайн через 15 минут без heartbeat
- **Проверка данных** — все входящие данные попадают в статус *pending*; перед деплоем вы одобряете или отклоняете их
- **Объединённый деплой** — одним кликом данные от всех одобренных нод объединяются, IP дедуплицируются и записываются в файл зеркала
- **История деплоев** — журнал всех выгрузок
- **Docker-образ** — публикуется в `ghcr.io/robulanetteam/honeypot-central`

---

## Быстрый старт — Центральный сервер

```bash
git clone https://github.com/robulanetteam/rdp-honeypot-central
cd rdp-honeypot-central/central

cp .env.example .env
nano .env          # установите ADMIN_TOKEN

# подтянуть готовый образ и запустить
IMAGE=ghcr.io/robulanetteam/honeypot-central docker compose up -d
```

Веб-интерфейс доступен по адресу `http://your-server:8100`

### Переменные окружения (`central/.env`)

| Переменная | Обязательна | По умолчанию | Описание |
|------------|-------------|--------------|----------|
| `ADMIN_TOKEN` | ✓ | — | Секрет для входа в веб-интерфейс |
| `ONLINE_SECS` | | `900` | Секунд до перехода ноды в статус оффлайн |

---

## Агент — установка на каждой ноде

Агент читает `blocklist.txt` и `analytics.jsonl` из папки данных honeypot и каждые 15 минут отправляет их на центральный сервер через systemd-таймер.

### 1. Зарегистрируйте ноду в интерфейсе

Откройте веб-интерфейс → **Settings** → **Register New Node** → введите ID и метку ноды → скопируйте выданный токен.

### 2. Добавьте переменные в `.env` вашего honeypot

```bash
# Дополните существующий .env файл honeypot (см. agent/.env.example)
CENTRAL_URL=http://your-server:8100
CENTRAL_NODE_ID=rdp-home
CENTRAL_TOKEN=<токен из интерфейса>
CENTRAL_DATA_DIR=/home/homeserver/rdp_honeypot/rdp_honeypot/data
```

### 3. Установите агент

```bash
# скопируйте папку agent/ на ноду, затем:
sudo bash agent/install.sh
# установщик автоматически найдёт .env, или укажите путь явно:
sudo ENV_FILE=/path/to/.env bash agent/install.sh
```

Устанавливает `/opt/honeypot-agent/agent.py` и systemd-таймер с запуском каждые 15 минут.

### Переменные окружения агента

| Переменная | Обязательна | По умолчанию | Описание |
|------------|-------------|--------------|----------|
| `CENTRAL_URL` | ✓ | — | URL центрального сервера |
| `CENTRAL_NODE_ID` | ✓ | — | Идентификатор ноды (должен совпадать с зарегистрированным в UI) |
| `CENTRAL_TOKEN` | ✓ | — | Токен авторизации из UI |
| `CENTRAL_DATA_DIR` | ✓ | — | Путь к папке `data/` honeypot |
| `CENTRAL_INSECURE` | | `0` | `1` — отключить проверку TLS-сертификата |
| `CENTRAL_ANALYTICS_DAYS` | | `7` | За сколько дней включать аналитику |

### Ручной запуск / отладка

```bash
python3 /opt/honeypot-agent/agent.py

# только heartbeat (без загрузки данных):
python3 /opt/honeypot-agent/agent.py --heartbeat

# статус таймера:
systemctl status honeypot-agent.timer
journalctl -u honeypot-agent.service -n 30
```

---

## Рабочий процесс проверки

```
нода отправляет данные
        ↓
  статус: pending   ← видно в UI → Submissions
        ↓
  ✓ Одобрить  /  ✗ Отклонить
        ↓
  статус: approved
        ↓
  Deploy → объединённый blocklist.txt записывается в ./central/data/public/
        ↓
  статус: deployed
```

---

## Сборка Docker-образа вручную

```bash
# Docker Hub
docker login
IMAGE=youruser/honeypot-central bash central/build-push.sh

# GHCR
docker login ghcr.io
IMAGE=ghcr.io/youruser/honeypot-central bash central/build-push.sh

# только локальная сборка (без push)
PUSH=0 bash central/build-push.sh
```

## CI/CD

Каждый push в `main` и каждый тег версии (`v*`) запускает `.github/workflows/docker.yml`, который собирает multi-arch образ (`linux/amd64` + `linux/arm64`) и публикует его в `ghcr.io/robulanetteam/honeypot-central`.

---

## Структура репозитория

```
central/
  server.py            ← бэкенд (FastAPI + SQLite)
  static/app.html      ← одностраничный веб-интерфейс
  requirements.txt
  Dockerfile
  docker-compose.yml
  build-push.sh        ← скрипт ручной сборки и публикации
  .env.example
agent/
  agent.py             ← агент для honeypot-ноды
  install.sh           ← установщик (systemd)
  honeypot-agent.service
  honeypot-agent.timer
  .env.example         ← переменные для добавления в .env honeypot
.github/workflows/
  docker.yml           ← GitHub Actions CI/CD
```
