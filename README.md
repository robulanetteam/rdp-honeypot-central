# Honeypot Central

Централизованное управление распределёнными RDP-honeypot нодами.

На каждой ноде работает лёгкий агент, который периодически отправляет `blocklist.txt` и аналитику на центральный сервер. В веб-интерфейсе вы проверяете входящие данные, одобряете или отклоняете их, затем одним кликом деплоите объединённый blocklist на своё зеркало.

```
Нода 1 ──┐
Нода 2 ──┼──► Центральный сервер (HTTPS, веб-интерфейс) ──► blocklist.txt (зеркало)
Нода N ──┘
```

## Возможности

- **HTTPS из коробки** — при старте контейнера автоматически генерируется самоподписанный сертификат на 10 лет; опционально — сертификат Let's Encrypt через certbot
- **Реестр нод** — регистрация нод, выдача уникальных токенов; карточки нод показывают внешний IP, статус онлайн/оффлайн, последнюю ошибку
- **Ping нод** — кнопка в UI отправляет ICMP ping к ноде и показывает задержку
- **Журнал событий** — вкладка Logs с фильтрацией по ноде и уровню (INFO/WARN/ERROR)
- **Проверка данных** — входящие данные попадают в статус *pending*; перед деплоем можно редактировать блоклист, смотреть аналитику и проверять пересечения с уже задеплоенными IP
- **Whitelist** — IP из белого списка автоматически исключаются из всех экспортов
- **Объединённый деплой** — IP дедуплицируются, сливаются с предыдущим деплоем и записываются в три формата: plain-text, pfBlockerNG, MikroTik RouterOS
- **Rate limiting** — не более 5 неверных попыток входа за 5 минут; после блокировки — ожидание
- **Статусная строка** — в шапке UI отображается IP клиента, время последнего входа и предупреждение о неудачных попытках
- **Docker-образ** — публикуется в `ghcr.io/robulanetteam/honeypot-central` (multi-arch: amd64 + arm64)

---

## Быстрый старт — Центральный сервер

```bash
git clone https://github.com/robulanetteam/rdp-honeypot-central
cd rdp-honeypot-central/central

cp .env.example .env
nano .env          # установите ADMIN_TOKEN

# подтянуть готовый образ и запустить
IMAGE=ghcr.io/robulanetteam/honeypot-central:latest docker compose up -d
```

Веб-интерфейс доступен по адресу `https://your-server:8100`

> При первом запуске в `/data/certs/` создаётся самоподписанный сертификат (RSA-4096, 10 лет).
> Браузер покажет предупреждение — это ожидаемо для self-signed. Сертификат сохраняется в volume и переживает пересборку образа.

### Переменные окружения (`central/.env`)

| Переменная | Обязательна | По умолчанию | Описание |
|------------|-------------|--------------|----------|
| `ADMIN_TOKEN` | ✓ | — | Секрет для входа в веб-интерфейс |
| `ONLINE_SECS` | | `900` | Секунд до перехода ноды в статус оффлайн |
| `MIKROTIK_LIST_NAME` | | `honeypot-block` | Имя address-list в MikroTik RouterOS |
| `SSL_CN` | | `honeypot-central` | CN в самоподписанном сертификате |
| `CERTBOT_DOMAIN` | | — | Домен для получения сертификата Let's Encrypt |
| `CERTBOT_EMAIL` | | — | Email для регистрации в Let's Encrypt |
| `CERTBOT_STAGING` | | `0` | `1` — тестовый режим LE (без лимитов) |
| `CERTBOT_HTTP_PORT` | | `80` | Порт для HTTP-01 challenge |

### Let's Encrypt (публичный домен)

Добавьте в `.env`:

```env
CERTBOT_DOMAIN=central.example.com
CERTBOT_EMAIL=admin@example.com
```

И пробросьте порт 80 (нужен для HTTP-01 challenge) — он уже объявлен в `docker-compose.yml`.
Сертификат будет автоматически обновляться каждые 12 часов.

---

## Форматы экспорта

После деплоя в `./data/public/` появляются три файла, доступные по `https://your-server:8100/pub/`:

| Файл | Формат | Назначение |
|------|--------|------------|
| `blocklist.txt` | один IP на строку | универсальный |
| `blocklist_pfblocker.txt` | `IP/32` на строку | pfBlockerNG (pfSense/OPNsense) |
| `blocklist_mikrotik.rsc` | `add address=IP list=…` | MikroTik RouterOS |

---

## Агент — установка на каждой ноде

Агент читает `blocklist.txt` и `analytics.jsonl` из папки данных honeypot и каждые 15 минут отправляет их на центральный сервер через systemd-таймер.

### 1. Зарегистрируйте ноду в интерфейсе

Откройте веб-интерфейс → **Settings** → **Register New Node** → введите ID и метку ноды → скопируйте выданный токен.

### 2. Добавьте переменные в `.env` вашего honeypot

```env
# Дополните существующий .env файл honeypot (см. agent/.env.example)
CENTRAL_URL=https://your-server:8100
CENTRAL_NODE_ID=rdp-home
CENTRAL_TOKEN=<токен из интерфейса>
CENTRAL_DATA_DIR=/home/homeserver/rdp_honeypot/rdp_honeypot/data

# Для самоподписанного сертификата:
CENTRAL_INSECURE=1
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
| `CENTRAL_URL` | ✓ | — | URL центрального сервера (`https://...`) |
| `CENTRAL_NODE_ID` | ✓ | — | ID ноды (должен совпадать с зарегистрированным в UI) |
| `CENTRAL_TOKEN` | ✓ | — | Токен авторизации из UI |
| `CENTRAL_DATA_DIR` | ✓ | — | Путь к папке `data/` honeypot |
| `CENTRAL_INSECURE` | | `0` | `1` — отключить проверку TLS-сертификата (для self-signed) |
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
  статус: pending   ← UI → Submissions
    ├── просмотр аналитики (страны, суbnets, учётные данные)
    ├── проверка пересечений с задеплоенными IP
    ├── редактирование блоклиста перед одобрением
    └── проверка по whitelist
        ↓
  ✓ Одобрить  /  ✗ Отклонить
        ↓
  статус: approved
        ↓
  Deploy → слияние с предыдущим деплоем, дедупликация, фильтрация whitelist
        ↓
  статус: deployed  →  /pub/blocklist.txt  |  pfblocker  |  mikrotik.rsc
```

---

## CI/CD

Каждый push в `main` и каждый тег версии (`v*`) запускает `.github/workflows/docker.yml`, который собирает multi-arch образ (`linux/amd64` + `linux/arm64`) и публикует его в `ghcr.io/robulanetteam/honeypot-central`.

---

## Структура репозитория

```
central/
  server.py              ← бэкенд (FastAPI + SQLite)
  static/app.html        ← одностраничный веб-интерфейс (тёмная тема)
  requirements.txt
  Dockerfile
  docker-compose.yml
  docker-entrypoint.sh   ← генерация TLS-сертификата + запуск uvicorn
  .env.example
agent/
  agent.py               ← агент для honeypot-ноды
  install.sh             ← установщик (systemd)
  honeypot-agent.service
  honeypot-agent.timer
  .env.example           ← переменные для добавления в .env honeypot
.github/workflows/
  docker.yml             ← GitHub Actions CI/CD (multi-arch)
```
