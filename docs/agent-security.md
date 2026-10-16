# Agent channel: выдача сертификатов, pinning и ротация

## Что реализовано сейчас

При первом `docker compose up` одноразовый `pki-init` создаёт локальный EC CA и server certificate, только если полный комплект ещё отсутствует. Частично заполненный PKI-каталог считается ошибкой и автоматически не перезаписывается. Private keys находятся в `secrets/pki/`, public CA и server SPKI pin — в `secrets/pki-public/`; оба каталога исключены из Git и build context.

После MASK P0 каталоги PKI не монтируются целиком в постоянно работающие сервисы. Доступ разделён по ролям:

- `pki-init` видит private/public PKI только во время идемпотентной проверки или первичного создания;
- FastAPI получает read-only только `ca.crt` и `ca.key`, потому что подписывает agent CSR при enrollment/reissue;
- agent gateway получает read-only только `server.crt`, `server.key` и публичный `ca.crt` для TLS/mTLS verification;
- `ca.key` отсутствует внутри gateway, а `server.key` отсутствует внутри FastAPI;
- agent private key остаётся исключительно в persistent state volume соответствующего агента.

Не копируйте private CA/server keys на Ubuntu-agent и не добавляйте их в image, `.env`, bootstrap volume или логи. Для Ubuntu передаются только `ca.crt`, `server.pin`, одноразовый enrollment token и затем локально созданная agent identity.

Оператор создаёт enrollment в UI. Token показывается ровно в ответе создания, хранится в БД только как SHA-256 hash, имеет TTL и после успешной транзакции получает `used_at`. Агент генерирует private key/CSR локально. Центр выдаёт отдельный client certificate с `clientAuth`, identity URI и host URI. Повтор token, просроченный token или второй identity того же host отклоняются.

На каждом обычном запросе Nginx проверяет client certificate по локальному CA. FastAPI сверяет SHA-256 fingerprint и serial с активной `agent_identities`, сроком действия и host. Это не operator identity и не даёт доступа к `/api/v1/*` или UI.

Gateway передаёт результат TLS-проверки FastAPI только через private `agent_backend`. FastAPI не принимает эти заголовки только по их наличию: он сначала проверяет реальный TCP peer как контейнер `agent-gateway`; обработка общих proxy headers в Uvicorn отключена. Публичный health endpoint удалён, внутренний healthcheck доступен только на loopback самого gateway-контейнера.

MASK P1-A добавляет только gateway-side alias `${AGENT_TRANSPORT_PREFIX}/v1/*`. Он не создаёт новую identity или схему авторизации: обычные операции по обоим prefixes требуют валидный client certificate, а enrollment по обоим prefixes — одноразовый token. Текущие агенты продолжают использовать `/agent/v1/*`; изменение agent URL в рамках P1-A не выполняется.

После MASK P1-B отдельный TLS preflight удалён из рабочего цикла. Агент создаёт `SSLContext` с обязательными CA validation и hostname verification, а custom transport проверяет SHA-256 SPKI pin в `NetworkStream.start_tls()` фактического соединения до отправки HTTP headers/body. Проверка выполняется для каждого нового и повторно установленного соединения; уже проверенное соединение может безопасно использоваться connection pool. Redirects не следуются. Неверный pin закрывает TLS stream до первого HTTP-запроса.

Решение рассчитано на зафиксированные `httpx==0.28.1` и `httpcore==1.0.9`: `httpcore.ConnectionPool` использует подменяемый `NetworkBackend`, а TLS stream предоставляет `ssl_object`. При обновлении любой из этих зависимостей обязательны transport integration tests; при несовместимом внутреннем API агент завершается с ошибкой, а не отключает pinning.

## Первичная выдача для текущего local-agent

1. В UI открыть «Хосты» → «Зарегистрировать хост».
2. Указать уникальные host/instance names, management address `local-agent`, профиль и TTL.
3. Скопировать показанный token один раз в `secrets/agent/enrollment.token`, не помещая его в командную строку, чат или журнал.
4. Запустить `docker compose --profile local-agent up -d --build local-agent`.
5. После успешной выдачи агент удаляет token file; key/certificate остаются в `agent_state` volume.

Текущий стенд уже содержит зарегистрированный `stage2-local-test`, поэтому эти шаги нужны только для нового отдельного agent state, а не для повторной регистрации существующей identity.

## Pinning

Pin — base64 SHA-256 от DER `SubjectPublicKeyInfo` server key. Он является дополнительной проверкой после обычной CA + hostname validation, а не заменой PKI. Public pin доставляется локальному Compose-agent read-only. Для физического устройства CA certificate и pin должны передаваться по отдельному доверенному bootstrap-каналу; этот процесс ещё не проводился.

## Ротация: реализовано и осталось

Есть аутентифицированный mTLS endpoint, который принимает новый CSR и перевыпускает сертификат той же identity. Клиент проверяет соответствие полученного certificate текущему private key, атомарно заменяет certificate и создаёт новый pinned pool. Ручная серверная операция аудируется.

До подключения физических устройств необходимо добавить:

- автоматическое создание нового key/CSR до expiry;
- overlap window, чтобы потерянный ответ ротации не заблокировал старый certificate;
- recovery/overlap при потере ответа после server-side rotation;
- операторский revoke/rotate UI и список отозванных identities;
- ротацию server certificate/CA с двумя pins/CA на переходный период;
- expiry monitoring и тесты recovery/revocation.

Текущий reissue endpoint поэтому не считается завершённым production lifecycle ротации.

## Безопасный bootstrap отдельного Ubuntu-agent

`compose.ubuntu-agent.yaml` не монтирует Windows `agent_state` и использует новый project-scoped `ubuntu_agent_state`. Публичные `ca.crt` и `server.pin` доставляются на Ubuntu отдельно; private CA/server keys не копируются.

Одноразовый token вводится без echo командой `python -m agent.bootstrap` в контейнере `bootstrap-agent`. Команда не принимает token аргументом, создаёт `enrollment.token` эксклюзивно с mode `0600` и отказывается работать, если token-файл или любой identity-файл уже существует. Bootstrap-контейнер имеет `network_mode: none`, read-only root filesystem, `cap_drop: ALL` и видит agent state только read-only. После успешного enrollment основной агент удаляет token; private key/certificate/identity остаются в отдельном persistent volume.

Удалённый agent использует URL `https://agent-gateway:8443` и отдельную настройку host mapping на IP Windows. Проверки CA, SAN hostname `agent-gateway` и SPKI pin выполняются в прежнем коде и не имеют режима отключения. Физическая передача public CA/pin и token, открытие конкретного Windows bind-address и узкий firewall rule относятся к этапу 4.2 и пока не выполнялись.
## Изменения границы доверия в этапе 3

Agent mTLS protocol, первичная выдача сертификатов, CA/hostname/SPKI pinning и ограничения ротации не изменялись. Low/Medium контейнеры не получают CA, server pin, agent certificate/private key, enrollment token или operator session. Они обмениваются с агентом только через раздельные config/event volumes; общей Docker-сети между агентом и движками нет.

Локальные ingress-relay контейнеры также не получают PKI или управляющие volumes. Они публикуют trap ports только на `127.0.0.1` и передают source metadata движкам по PROXY v1. Это решение проверено в Docker Desktop на Windows и не заменяет Ubuntu firewall/egress policy или физическое разделение management/trap interfaces.
