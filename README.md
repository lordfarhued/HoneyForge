# HoneyForge

HoneyForge — система централизованного управления honeypot-ловушками для обнаружения и анализа подозрительной активности в сети.

## Возможности

- Управление ловушками через веб-интерфейс.
- Low-interaction ловушки TCP/HTTP.
- Medium-interaction ловушки HTTP/SSH.
- Регистрация агентов и отслеживание их состояния.
- Сбор сетевых событий, попыток авторизации и команд.
- Защищённая передача данных через TLS/mTLS.
- Локальное сохранение событий при потере соединения.
- Просмотр событий в реальном времени.
- Разграничение доступа пользователей.

## Технологии

- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS, JavaScript
- **Database:** PostgreSQL
- **Proxy:** Nginx
- **Infrastructure:** Docker, Docker Compose

## Установка и запуск

Необходимы Docker и Docker Compose.

1. Создайте файл `.env` на основе `.env.example`.
2. Укажите собственные значения `POSTGRES_PASSWORD` и `SECRET_KEY`.
3. Запустите систему:

```bash
docker compose up -d --build
```

Для создания администратора:

```bash
docker compose exec api python -m app.cli create-user --username admin --email admin@example.com --role admin
```

Веб-интерфейс: http://127.0.0.1:8080

Для запуска локального агента с Low/Medium-ловушками:

```bash
docker compose --profile local-agent up -d --build
```

High SSH/HTTP запускается только по явному дополнительному профилю:

```bash
docker compose --profile local-agent --profile high up -d --build
```

## Архитектура

Система состоит из центрального сервера, агентов и изолированных ловушек.

Центральный сервер управляет конфигурациями и сохраняет события в PostgreSQL. Агенты запускают ловушки, получают команды и передают телеметрию по защищённому соединению.

Веб-интерфейс позволяет управлять профилями, отслеживать состояние агентов и анализировать события.

Для развёртывания агента на отдельном Ubuntu-устройстве используются `compose.ubuntu-agent.yaml` и инструкция по развёртыванию.

Целевая схема развёртывания: Windows Center → отдельный VPS Agent + Low/Medium/High; второй Ubuntu Agent необязателен. Матрица обязательных требований, границы доказательств и сценарий контролируемого пентеста приведены в [`docs/security-validation.md`](docs/security-validation.md). До его реального прохождения trap ports не должны публиковаться.

## Проверка

```bash
docker compose ps
docker compose --profile test run --rm tests
```

## Статус

Реализованы центральный сервер, управление агентами, Low/Medium-ловушки, сбор телеметрии и безопасный High SSH/HTTP-эмулятор с виртуальной файловой системой. Бонус FR-A5 с настоящей ОС, загрузкой инструментов и snapshot-revert остаётся отдельным этапом и текущим High-эмулятором не заявляется.

MASK-2 и MASK-4 реализованы частично: нейтральный transport/runtime подготовлен, но legacy endpoint и действующая PKI сохраняются до отдельной контролируемой миграции.
