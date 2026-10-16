# MUST-13 и план контролируемого пентеста

Документ отделяет наличие реализации от доказательства в утверждённой распределённой схеме: Windows Center → VPS Agent + Low/Medium/High. Статус «автотест» не означает прохождение независимого пентеста. Никакие ловушки нельзя публиковать, пока обязательные сетевые проверки ниже не имеют PASS-доказательств.

## Матрица обязательных требований

| ID | Реализация | Автоматизированное доказательство | Распределённое доказательство | Итоговый статус до пентеста |
|---|---|---|---|---|
| FR-C1 | CRUD профилей и версии конфигурации в API/UI | `tests/test_app.py`, `tests/test_stage2.py` | Не требуется для базовой логики; UI нужно повторить через tunnel | Реализовано, проверено локально |
| FR-C2 | Host, HoneypotInstance, status/last-seen, enrollment identity | `tests/test_app.py`, `tests/test_stage2.py` | Реальный VPS heartbeat/reboot ещё не зафиксирован | Реализовано, распределённо частично |
| FR-C3 | mTLS Agent API выдаёт config/jobs и принимает telemetry/status | `tests/test_agent_transport.py`, `tests/test_stage2.py`, ownership/size/dedup tests | Windows↔VPS delivery/outage/negative identity ещё не выполнены | Реализовано, распределённо не подтверждено |
| FR-C4 | PostgreSQL Event, filters по instance/time/source/type, pagination/export limits | `tests/test_app.py`, database-safety tests | Проверить на backup/restore и реальном потоке | Реализовано, проверено локально |
| FR-C5 | Session auth, CSRF, admin/operator/observer RBAC и redaction | `tests/test_app.py`, `tests/test_mask_gateway.py` | Повторить с внешнего браузера только через tunnel | Реализовано, проверено локально |
| FR-A1 | Low и Medium engines; High emulator дополнительно | `tests/test_stage3.py`, `tests/test_high.py` с реальными localhost HTTP/SSH | Реальные off-host подключения к VPS ещё не выполнялись | Реализовано, распределённо не подтверждено |
| FR-A2 | connection/auth/request/command/source metadata с флагами capture | `tests/test_stage2.py`, `tests/test_stage3.py`, `tests/test_high.py`; secret regression | Истинный source IP через VPS relay и packet capture ещё не доказан | Реализовано, распределённо частично |
| FR-A3 | heartbeat, config polling, status и allowlisted jobs | agent transport/controller tests | Продолжительная работа Windows↔VPS ещё не измерена | Реализовано, распределённо не подтверждено |
| FR-A4 | SQLite WAL/FULL, stable external ID, retry/backoff/ack; queue 10k + persistent spools 20k/256 MiB | restart, failed delivery, ordering, backpressure и recovery tests | Длительный реальный outage, reboot и drain ещё не выполнены | Реализовано в пределах ёмкости, распределённо не подтверждено |
| MASK-1 | TLS 1.2/1.3, mTLS, CA/hostname/SPKI, no redirects, re-pin reconnect | transport/gateway negative tests | Реальный сертификат, SNI, packet capture и отказ wrong pin на VPS ещё не сохранены | Реализовано, распределённо не подтверждено |
| MASK-2 | нейтральный `/assets/runtime`, одинаковый 404, скрытие backend headers; поддержаны нейтральные имена нового PKI | `tests/test_mask_gateway.py` | Legacy `/agent` и существующий PKI `agent-gateway` остаются до контролируемой ротации | Частично; TLS сам по себе маскировкой не считается |
| MASK-3 | Agent/relay/engines разнесены; host policy блокирует relay egress, host access High/Low/Medium и разрешает Agent только к Center:port | `tests/test_mask3_isolation.py`, Compose layout tests | nftables/iptables/UFW/provider ACL, reboot и независимый scan ещё не проверены | Частично до Linux-проверки |
| MASK-4 | `system-metrics`, `/opt/system-metrics`, neutral wrapper/comm/logs; client cert subject нейтрален; новый PKI может быть нейтральным | `tests/test_mask_runtime.py`, PKI tests | `ps`, `/proc`, systemd, Docker metadata и сетевой fingerprint на VPS ещё не сняты; privileged Docker operator всё равно видит image labels/source | Частично; это уменьшение заметности, не security boundary |

FR-A5 — бонус: текущий High является эмулятором с виртуальной ФС и allowlist-интерпретатором. У него нет реальной гостевой ОС, установки инструментов, snapshot/revert или поведенческой VM-изоляции, поэтому FR-A5 не реализован и не заявляется.

## Анализ выхода из High

High не передаёт команды в shell: обработчик разбирает строку через `shlex`, выбирает встроенную команду и читает только словарь виртуальной ФС. В модуле нет `subprocess`, `os.system`, `popen`, `eval` или `exec`; `curl/wget` возвращают статическую имитацию и не создают исходящее соединение. Метасимволы, oversized команды, число команд, общий SSH deadline, HTTP request/body, session count и output имеют пределы.

Контейнер High видит только read-only config, свой event spool и host-key state; Agent, PKI, Docker socket и management network отсутствуют. Root filesystem read-only, пользователь непривилегированный, capabilities сброшены, включены `no-new-privileges`, CPU/RAM/PIDs. Relay отделён от engine и не получает volumes.

Оставшийся риск не нулевой: уязвимость Python/Paramiko/socketserver или Docker kernel/runtime может дать выполнение внутри контейнера, а затем попытку container escape. Default seccomp/AppArmor и host firewall уменьшают последствия, но требуют фактической проверки на Linux и актуального vulnerability scan образов. Thread-per-connection ограничен cgroup PIDs, но контролируемый exhaustion-тест всё равно обязателен.

## Контролируемый пентест

Каждый шаг выполняется в отдельном окне, с backup, двумя административными SSH-сессиями и заранее согласованными source IP/портами. Для каждого шага сохраняются UTC-время, revision/image digest, sanitized command, stdout/stderr, packet capture или screenshot, соответствующие Event/Alert IDs и итог PASS/FAIL. Секреты, token, private keys и полные credential payload в доказательства не попадают.

1. **Предусловия и стоп-критерии.** PASS: backup PostgreSQL/PKI/Agent state проверен, `docker compose config` сохранён, рабочие Windows/Ubuntu узлы не в scope, trap bind остаётся loopback. FAIL: нет rollback, неизвестный image или dirty deployment не соответствует revision.
2. **Фактическая container policy.** Проверить `docker inspect`: user не root, `Privileged=false`, `ReadonlyRootfs=true`, `CapDrop=ALL`, `no-new-privileges`, Seccomp/AppArmor, лимиты и mounts. PASS: Docker socket/Center secrets/agent state отсутствуют у engines/relays. Любое расхождение — FAIL.
3. **MASK-3 сеть.** Установить `system-metrics-egress` с пятиминутным rollback, подтвердить правила в nft/iptables. Из relay и каждого engine проверить VPS host, management/VPN subnet, Windows UI/DB, произвольный Internet и DNS; из Agent — Center:8443 PASS, любой иной адрес/порт FAIL. Одновременно входящие trap sessions должны работать. Любой неожиданный SYN/packet — FAIL.
4. **MASK-1/2 transport.** Снять pcap без payload secrets. PASS: только разрешённый Center endpoint, `/assets/runtime`, mTLS; wrong CA/hostname/pin/cert/expired identity/redirect отвергаются до telemetry. Legacy path или product-bearing certificate в выбранном production profile — FAIL для MASK-2, даже если TLS корректен.
5. **MASK-4 видимость.** Непривилегированным локальным пользователем проверить `ps`, `/proc`, systemd, paths и журналы. PASS: runtime виден как утверждённые нейтральные name/path и логи не содержат token/password/product-control hints. Docker root/operator исключён из обещания скрытности, но его доступ должен быть административно ограничен.
6. **Авторизация и ownership.** Попытаться подменить gateway headers, identity/host/instance, повторить enrollment token, вызвать protected routes без session/CSRF или с observer/operator. PASS: 401/403/404 по политике, чужое событие не принимается, admin-only операции недоступны, redaction неизменна.
7. **Опасный ввод High.** Передать shell metacharacters, traversal, oversized/unterminated SSH command, несколько команд в одном chunk, malformed HTTP, huge Content-Length, forged cookie и honeytoken marker. PASS: нет host-файла/процесса/исходящего packet, соединение ограниченно завершается, секрет не попадает в Event/API/export.
8. **Ресурсные пределы.** Только малой контролируемой нагрузкой проверить session/PID/CPU/RAM limits, request/output caps, log rotation, queue 10k и spool policy на уменьшенных test limits. PASS: host и Center остаются responsive; контейнер не выходит за cgroup; после снятия нагрузки восстанавливается. DoS-нагрузка вне scope.
9. **FR-A4 outage/recovery.** Блокировать только Agent→Center, создать пронумерованные реальные события в пределах capacity, перезапустить Agent/VPS, восстановить связь. PASS: порядок сохранён, external IDs без потерь/дублей, queue/spool дренированы, PostgreSQL содержит исходные события один раз. Отдельно заполнить уменьшенную тестовую queue: spool не удаляется; при полном spool ожидаемо отклоняются только новые events с предупреждением.
10. **FR-A2 end-to-end.** Со второй машины выполнить Low HTTP/UDP, Medium HTTP/SSH и High HTTP/SSH. PASS: source IP равен наблюдаемому адресу relay (не объявляется личностью), auth/request/commands хронологичны, Alert/Timeline связаны, admin видит разрешённый оригинал, operator/observer — redacted данные.
11. **Persistence и rollback.** Перезагрузить Docker/VPS. PASS: identity/queue/host keys сохраняются, firewall снова активен до публикации ports, лишние listeners не появились. Проверить rollback firewall без изменения SSH/UFW/чужих chains.

Публичное открытие trap ports, Corporate Network и GitHub-публикация остаются запрещены до PASS всех обязательных пунктов 1–11. Итог «пентест пройден» может выдать только независимый исполнитель после реального испытания; этот репозиторий предоставляет сценарий и автоматизированные регрессии, но не такой итог.

## Шесть результатов сдачи

1. Репозиторий и Compose: реализованы локальный Center и отдельный Agent Compose; production Windows↔VPS требует физической валидации.
2. README/API/архитектура/профили: реализованы; security runbook и ограничения добавлены.
3. Демонстрация Center + Low/Medium: реализована локально; распределённая демонстрация ещё не записана.
4. Архитектура и схема БД: описаны в `docs/architecture.md`; соответствие миграциям проверяется тестами, restore rehearsal ещё не выполнен.
5. Сценарий атака → Center: автоматизирован локально; off-host VPS evidence ещё отсутствует.
6. Презентация: существующий итоговый PDF сохранён; актуальность к финальному revision требует ручной проверки.
