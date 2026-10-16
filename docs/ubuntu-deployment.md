# Развёртывание отдельного Agent-узла на VPS или Ubuntu-lab

Утверждённая production-схема: Windows — единственный Center (FastAPI, PostgreSQL, Collector, UI), VPS — Agent и Low/Medium/High, лабораторный Ubuntu Agent необязателен. Код не выполняет enrollment, не меняет Windows/VPS firewall, маршруты, Tailscale, PKI или работающие контейнеры. Все сетевые действия ниже являются будущим ручным этапом и не считаются выполненными без сохранённых доказательств.

## Что подготовлено в 4.1

- Windows center: `compose.center.yaml`, project name `honeyforge`, прежние `postgres_data`, API, UI, gateway и PKI paths.
- Remote node: `compose.ubuntu-agent.yaml`, нейтральный project `system-metrics`, собственные volumes `ubuntu_agent_state`, `ubuntu_agent_bootstrap`, раздельные config/event spools и Medium/High host-key state.
- Gateway bind: `${AGENT_BIND_IP:-127.0.0.1}`. LOW bind: `${LOW_BIND_IP:-127.0.0.1}`. Medium binds: `${TRAP_BIND_IP:-127.0.0.1}`.
- Ubuntu подключается к `HONEYFORGE_CENTER_IP`, но TLS URL и проверяемое имя остаются `agent-gateway`. Проверяются CA chain, SAN hostname и SPKI pin.
- Один host/identity получает все связанные Low/Medium/High instances. Одинаковые protocol/port на одном host запрещены.
- Bootstrap token вводится интерактивно без echo в отдельном контейнере без сети. Существующий state не перезаписывается.
- Agent bridge имеет стабильное имя и host-firewall разрешает из него только TCP к точному адресу/порту Center. Public relay не может создавать исходящие соединения; Low/Medium/High bridges не могут обращаться к host.
- SQLite queue ограничена 10 000 событиями. При заполнении валидные engine events остаются в persistent spool; каждый spool ограничен 20 000 файлов и 256 MiB. По достижении обоих уровней новые события не сохраняются, чтобы не исчерпать диск — это контролируемая деградация, а не бесконечная гарантия хранения.

## Предварительная валидация без запуска и enrollment

На Windows:

```powershell
docker compose config --quiet
docker compose -f compose.center.yaml config --quiet
docker compose --profile local-agent ps
```

На VPS/Ubuntu после копирования репозитория:

```bash
cp ubuntu-agent.env.example ubuntu-agent.env
chmod 600 ubuntu-agent.env
docker compose --env-file ubuntu-agent.env -f compose.ubuntu-agent.yaml config --quiet
```

Пока `LOW_BIND_IP=127.0.0.1`, LOW не доступен второму ноутбуку. Medium дополнительно выключен profile-механизмом и использует `TRAP_BIND_IP=127.0.0.1`. Не используйте `0.0.0.0` как быстрый обход.

## Ручные действия на Windows Center

1. Сделать проверяемую резервную копию БД и каталогов `secrets/`, не удаляя volumes.
2. Подтвердить стабильный адрес только management-интерфейса Windows; не использовать trap-facing адрес.
3. В существующем `.env` задать `AGENT_BIND_IP=<CENTER_MANAGEMENT_IP>`, не менять `POSTGRES_PASSWORD`, `SECRET_KEY` и остальные secrets. Перезапустить только `agent-gateway` через center Compose.
4. Создать входящее Windows Firewall правило только для TCP/8443, local address `<CENTER_MANAGEMENT_IP>`, remote address `<AGENT_MANAGEMENT_IP>`, нужного профиля сети. Не разрешать subnet целиком и не открывать operator port 8080.
5. Проверить с Windows, что UI всё ещё слушает только `127.0.0.1:8080`, PostgreSQL не опубликован, а 8443 не привязан к `0.0.0.0`.
6. Передать Ubuntu только `secrets/pki-public/ca.crt` и `server.pin` через доверенный канал. Не копировать `ca.key`, server private key, `.env`, `secrets/agent` или Windows agent volume.
7. В UI открыть «Хосты» → «Зарегистрировать хост»: создать новый host `ubuntu-...` с точным management address агента, уникальным первым instance и коротким TTL. Это новая identity; не использовать существующий Windows host.
8. Для второго экземпляра открыть «Ловушки» → «Добавить ловушку», выбрать тот же Ubuntu host и другой профиль/свободные порты. Один host не может иметь конфликтующие listener ports.

## Ручные действия на VPS/Ubuntu Agent

1. Установить поддерживаемые Docker Engine и Compose plugin; включить запуск Docker после reboot. Сверить влияние Docker published ports на выбранный firewall backend.
2. Разместить репозиторий в отдельном каталоге. Создать `secrets/pki-public`, положить только `ca.crt` и `server.pin`, проверить ownership/permissions и сверить fingerprints/pin с Windows по отдельному каналу.
3. Скопировать `ubuntu-agent.env.example` в gitignored `ubuntu-agent.env`. Указать точный `CONTROL_ENDPOINT_IP=<CENTER_MANAGEMENT_IP>`. До готовности trap-facing интерфейса оставить `LOW_BIND_IP=127.0.0.1` и `TRAP_BIND_IP=127.0.0.1`.
4. Проверить DNS/route только до Windows 8443. Имя внутри контейнера задаётся `extra_hosts` как `agent-gateway → <CENTER_MANAGEMENT_IP>`; не заменять `HF_AGENT_BASE_URL` на IP и не отключать TLS verification.
5. Ввести свежий одноразовый token, не помещая его в shell history:

   ```bash
   docker compose --env-file ubuntu-agent.env -f compose.ubuntu-agent.yaml --profile bootstrap run --rm runtime-bootstrap
   ```

6. Запустить все уровни сначала только на loopback:

   ```bash
   docker compose --env-file ubuntu-agent.env -f compose.ubuntu-agent.yaml --profile medium --profile high up -d --build
   docker compose --env-file ubuntu-agent.env -f compose.ubuntu-agent.yaml ps
   ```

   После enrollment token удаляется, а key/certificate/identity и SQLite queue остаются в `ubuntu_agent_state`. Restart policy `unless-stopped` восстанавливает сервисы после Docker daemon/reboot.
7. Создать root-owned `/etc/default/system-metrics-egress` из `deploy/ubuntu/system-metrics-egress.default`. Указать точные `RUNTIME_PROJECT_NAME`, `CONTROL_ENDPOINT_IP` и `CONTROL_PORT`; network/bridge names должны совпадать с Compose. Установить правила с автоматическим rollback:

   ```bash
   sudo bash deploy/ubuntu/manage-system-metrics-egress install
   ```

   Не закрывая SSH, проверить вторую SSH-сессию, связь Agent→Center и отрицательные egress-тесты из relay/engine. Только после этого выполнить `sudo bash deploy/ubuntu/manage-system-metrics-egress confirm`. Команда `rollback` удаляет только цепочки `SME_*`. Отдельная Docker bridge, `internal: true` и UFW без этих проверок не являются доказательством MASK-3.
8. Только после настройки и проверки trap-facing интерфейса задать `LOW_BIND_IP` и `TRAP_BIND_IP` его конкретным адресом; не использовать `0.0.0.0`, если на VPS есть отдельный management address. Provider firewall и host INPUT должны разрешать только административный SSH с allowlist и нужные trap ports. Windows Center должен принимать 8443 только от management/VPN IP VPS.
9. Не монтировать `/var/run/docker.sock`, не добавлять `privileged`, host network или дополнительные сети engine-контейнерам.

## Проверки на Agent-узле и отдельной машине пентестера

На Ubuntu проверить `docker inspect`:

- Low/Medium/High подключены только к своим internal ingress networks;
- agent подключён только к egress network и не разделяет сеть с engines;
- у engines нет PKI, bootstrap, `.env`, agent state или Docker socket mounts;
- `ReadonlyRootfs=true`, `Privileged=false`, capabilities dropped;
- default seccomp и AppArmor действительно активны; CPU/RAM/PIDs и log rotation видны в `docker inspect`;
- volumes и identity переживают reboot, queue остаётся при недоступном gateway.

Со второго ноутбука атакующего:

1. Доступны только trap IP и разрешённые 8081/8082/2222; при отдельно включённом профиле High — также 8084/2223.
2. Недоступны Windows 8080/8443 (8443 разрешён firewall только от Ubuntu agent), PostgreSQL и Ubuntu management services.
3. Реальные HTTP/SSH взаимодействия создают `is_test=false` события именно нужного instance в Dashboard.
4. При временном блокировании Ubuntu→Windows 8443 события накапливаются; после восстановления и reboot Ubuntu досылаются без потерь и дублей.
5. Из Low/Medium/High containers не разрешаются DNS/соединения к Windows center, management subnet, Internet и Docker socket. Проверять и container namespace, и внешний packet capture.
6. Из Agent разрешён только TCP к точному `CONTROL_ENDPOINT_IP:CONTROL_PORT`; произвольный Internet, другие порты Center и host VPS недоступны.
7. При очереди до configured limit события переживают restart. При заполненной SQLite queue файлы остаются в spool; после восстановления Center очередь и spool дренируются в хронологическом порядке без повторов. При полном spool фиксируется ожидаемая потеря только новых событий и предупреждение без секрета.

## Критерии завершения 4.2

Распределённую схему и контролируемый пентест нельзя считать завершёнными, пока не подтверждены enrollment новой identity, mTLS/hostname/SPKI negative checks, reboot persistence, bounded outage/recovery, точные bind/firewall rules, process/path visibility и независимое сканирование со второй машины. Автотесты этих результатов не доказывают.

## План безопасного обновления агента до MASK P1-B

Этот раздел является планом; команды на физическом `ubuntu-lab-02` в ходе разработки P1-B не выполнялись.

Runtime-файлы для переноса из проверенного revision:

- `agent/client.py`, `agent/config.py`, `agent/main.py`, `agent/pki.py`, новый `agent/transport.py`;
- `compose.ubuntu-agent.yaml`;
- `ubuntu-agent.env.example` только как справка — не заменять им действующий `ubuntu-agent.env`;
- `Dockerfile.agent` и `requirements-agent.txt` должны переноситься вместе с revision, хотя их содержимое P1-B не менялось.

Безопасная последовательность:

1. Оставить `AGENT_CLIENT_TRANSPORT_PREFIX=/agent`. Переключение prefix выполнять только отдельным изменением после успешного обновления клиента.
2. Зафиксировать текущие `docker compose ps`, image ID и checksum действующих Compose/env-файлов. Не выводить содержимое env, identity или pin.
3. Пометить текущий agent image локальным rollback-tag. Скопировать действующие Compose/env-файлы в каталог backup с mode `0700/0600`.
4. Остановить только `runtime-worker`; Low/Medium/High могут продолжать писать в event spool. Не выполнять `down`, `down -v`, prune или удаление volumes.
5. Создать архив named volume `ubuntu_agent_state` в закрытом backup-каталоге. Архив содержит private agent key и должен иметь mode `0600`, не передаваться и не попадать в Git. Зафиксировать SHA-256 архива без вывода его содержимого.
6. Перенести проверенный revision и выполнить `docker compose --env-file ubuntu-agent.env -f compose.ubuntu-agent.yaml config --quiet`, затем собрать только `runtime-worker`.
7. До замены сервиса запустить candidate one-shot с state volume read-only и выполнить только heartbeat/config/jobs через legacy prefix. Проверить CA/hostname/SPKI и отсутствие записи в state.
8. Выполнить `docker compose ... up -d --no-deps runtime-worker`. Проверить health, свежий `last_success`, неизменную identity, queue depth, heartbeat/config/jobs/status и досылку накопленного spool.
9. Проверить в Center, что host/traps не созданы повторно, event external IDs уникальны, а PostgreSQL получает накопленные события. Затем выполнить управляемый короткий обрыв 8443 и recovery без потерь/дублей.
10. Rollback: остановить только `runtime-worker`, вернуть прежние Compose/env и rollback image, запустить `up -d --no-deps runtime-worker`. Старый клиент совместим с неизменённой SQLite schema, поэтому backup state обычно не восстанавливать — это сохранило бы события, накопленные после обновления. Восстановление volume из архива допустимо только при подтверждённой порче и с отдельным решением о сохранении более новых queued events.

После стабильной работы на legacy отдельным окном можно изменить только `AGENT_CLIENT_TRANSPORT_PREFIX=/assets/runtime`, пересоздать только agent и подтвердить те же проверки. Старый `/agent/v1/*` на gateway остаётся rollback-путём.
