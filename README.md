# vUPF (C++): 5G User Plane Function

Репозиторий реализует прототип UPF в том же стиле построения, что и проект SMF: разделение на ядро, адаптеры, runtime-конфиг, CLI и тесты.

## Что реализовано

- `UpfNode` как оркестратор состояния и жизненного цикла пользовательских сессий
- Модуль `SessionTable` для хранения контекстов PDU-сессий
- Интерфейсы и адаптеры N3/N4/N6/N9 + SBI
- N6 egress для IPv4, IPv6 и Ethernet с учётом DNN и регистрацией N6-сессий
- N6 downlink path: трафик из data network принимается отдельным listener на `n6_bind`, складывается в явный `N6PacketBuffer` и затем возвращается в UE через N3 с bounded wait на ожидание внешнего пакета
- Обработка PFCP establish/modify/delete через N4
- Uplink/downlink forwarding accounting (N3<->N6)
- Heartbeat-логика и переход `RUNNING -> DEGRADED -> RUNNING`
- Runtime config loader: поддерживается только простой key-value формат (`key: value`, один уровень, без вложенности, без массивов)
- CLI с candidate/running моделью (`set`, `commit`, `show`)
- Набор тестов для ядра, конфигурации, CLI и трафик-флоу

## PR-2.1: N6 Packet Buffer Layer

Первый инкремент PR-2.1 вынес буферизацию downlink-пакетов N6 из `NetworkN6Adapter` в отдельный модуль `N6PacketBuffer`.

- буфер теперь оформлен как явный слой, а не как внутренняя `std::queue` внутри адаптера
- буфер ведёт packet-level state по PDU-session key
- используется bounded per-session buffering: при переполнении вытесняется самый старый пакет в рамках конкретной сессии
- при удалении N6-сессии её buffered state очищается отдельно от остального adapter state
- listener N6 больше не создаёт очереди для неизвестных сессий

Текущий scope PR-2.1 покрывает downlink buffering layer и для сетевого, и для console N6 адаптера. Следующие шаги можно строить поверх этого слоя: policy по backpressure/drop reason, явные buffer metrics/export и более детальную observability по buffer occupancy.

Во втором инкременте PR-2.1 поверх этого слоя добавлены live buffer metrics в `UpfNode::status()` и CLI (`show status`, `show n6-buffer`), а также явная overflow policy с поддержкой `drop_oldest` и `drop_newest`.

Следующий инкремент добавляет per-session inspection через `show n6-buffer session <imsi> <pdu>` и включает live N6 buffer metrics в payload `notify_sbi("nupf-event-exposure", ...)`.

Новый контракт для SBI event exposure теперь структурирован: `notify_sbi(...)` формирует JSON payload с полями `message`, `status` и `n6_buffer`, а `NetworkSbiAdapter` отправляет его как JSON value внутри HTTP body.

Отдельный review-checklist для PR-2.1 вынесен в `docs/PR-2.1-review-checklist.md`.

## Структура

- `include/upf` — публичные интерфейсы и заголовки
- `include/upf/modules` — небольшие stateful-модули ядра, включая `N6PacketBuffer`
- `src` — реализация ядра, адаптеров, CLI и config
- `tests` — unit/integration-like тесты
- `config` — примеры runtime-конфигов

## N6 Конфиг

- `n6_bind` — локальная точка привязки N6
- `n6_remote_host` — удалённый peer/data-network host для сетевого N6 адаптера
- `n6_remote_port` — удалённый peer/data-network port для сетевого N6 адаптера
- `n6_default_protocol` — `ipv4`, `ipv6` или `ethernet` для default policy в демонстрационном запуске/CLI
- `n6_downlink_wait_timeout_ms` — максимальное время ожидания внешнего downlink-пакета в очереди N6 перед возвратом `timeout`
- `n6_buffer_capacity` — максимальное количество buffered N6 downlink-пакетов на одну PDU-сессию
- `n6_buffer_overflow_policy` — policy переполнения буфера; поддерживаются `drop_oldest` и `drop_newest`

Демонстрационный `upf` binary использует `NetworkN6Adapter` и берёт `n6_bind`/`n6_remote_host`/`n6_remote_port` напрямую из runtime-конфига. Встроенная инъекция downlink из `main.cpp` убрана: для внешней подачи N6-пакета используйте отдельный `n6_traffic_tool`.

Для PR-2.2 важно, что `n6_bind` и `n6_remote_port` больше по умолчанию разделены: `upf` слушает внешний downlink на `30000`, а uplink отправляет на `30001`. Это убирает ложный self-loop, когда собственный uplink ошибочно возвращался как downlink.

По умолчанию и `NetworkN6Adapter`, и `ConsoleN6Adapter` используют bounded N6 packet buffer с capacity `16` пакетов на одну PDU-сессию и policy `drop_oldest`. Для observability доступны live-команды `show status` и `show n6-buffer`, которые экспортируют occupancy, per-policy drops и rejected-by-policy counters.

Для локальной диагностики конкретной PDU-сессии используйте `show n6-buffer session <imsi> <pdu>`. Команда возвращает DNN, protocol mode flags, per-session counters `enqueued`/`dequeued`/`dropped`, breakdown `dropped_oldest`/`dropped_newest`/`dropped_session_removed`, per-session `rejected_by_policy`, текущее `buffered` и `last_updated` для выбранной N6-сессии.

Для machine-friendly сценариев та же команда поддерживает structured output: `show n6-buffer session <imsi> <pdu> json` возвращает JSON object с теми же полями.

Глобальные live-команды тоже поддерживают structured output:

- `show status json`
- `show n6-buffer json`
JSON schema markers теперь разделены по payload family: `upf.runtime-config.v1`, `upf.status.v1`, `upf.n6-buffer.v1`, `upf.n6-session.v1`, `upf.sbi-event.v1` и `upf.sbi-envelope.v1`.
Кроме того, `show running json` и `show candidate json` теперь используют тот же общий serializer module, что и остальная observability/output логика.

SBI request body composition и базовые PFCP response/detail helpers вынесены из network adapter implementation в отдельный transport serializer/helper layer.
PFCP session request wire encoding тоже вынесен на protocol-level в `pfcp_wire`, поэтому `NetworkN4Adapter` больше не собирает session request IE набор inline.

`unknown_session` остаётся только глобальным счётчиком в `show n6-buffer`: такой drop возникает до подтверждения/нахождения валидной session key, поэтому корректно привязать его к конкретной PDU-сессии нельзя.

Для внешней интеграции через SBI это означает, что observability больше не завязана на ad-hoc key-value строку: `payload` в HTTP request теперь может быть либо простым JSON string, либо структурированным JSON object.

## Сборка

```bash
cmake --preset default
cmake --build --preset default
ctest --preset default
```

## Быстрый запуск

```bash
cmake --build --preset default --target upf
./build/upf --session
```

Preset `default` пишет все исполняемые файлы прямо в каталог `build`, а не в `build/default`.

## Windows Quick Start

```powershell
cd C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF
cmake --preset default
cmake --build --preset default --target upf n4_mock_peer n6_traffic_tool
```

Терминал 1:

```powershell
.\build\n4_mock_peer.exe
```

Терминал 2:

```powershell
.\build\upf.exe --interactive
```

Терминал 3, для реального N6 downlink в PR-2.2 сценарии:

```powershell
.\build\n6_traffic_tool.exe --delay-ms 200 --count 5 --interval-ms 120
```


Пример REPL:

```text
session establish
session downlink-tool 1200
show status json
show n6-buffer json
exit
```


`session downlink-tool [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]` сам запускает `n6_traffic_tool` с коротким burst и затем выполняет реальный downlink для уже установленной сессии. Для полного one-shot сценария в REPL доступен `session full-tool [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`.


По умолчанию REPL использует встроенную сессию `250200123456789/10`, но теперь любую session-команду можно направить в конкретную сессию. Примеры:

```text
session establish 250200123450001 21
session uplink 1500 250200123450001 21
session downlink-tool 1200 250200123450001 21
session release 250200123450001 21
```


Для быстрого переключения N6 traffic-profile без изменения `n6_default_protocol` используйте named options:

```text
session establish 250200123450002 22 dnn=ims profile=ipv6
session full-tool 1200 250200123450002 22 dnn=ims profile=ipv6
session downlink-tool 900 250200123450003 23 dnn=enterprise profile=ethernet
```

Отдельный preset-вариант задаёт и `dnn`, и protocol одной опцией. Поддерживаются:

```text
internet-ipv4
internet-ipv6
ims-ipv4
ims-ipv6
enterprise-ipv4
enterprise-ipv6
enterprise-ethernet
```


Примеры:

```text
session validate 250200123450002 22 preset=ims-ipv6
session validate 1440 250200123450002 22 preset=ims-ipv6
session validate 250200123450002 22 preset=ims-ipv6 json
session validate 1440 250200123450002 22 preset=ims-ipv6 json
session validate tool-cmd 1440 250200123450002 22 preset=ims-ipv6
session validate tool-cmd 1440 250200123450002 22 preset=ims-ipv6 json
session validate 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6
session validate tool-cmd 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6 json
session compare 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6
session compare tool-cmd 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6 json
session establish 250200123450002 22 preset=ims-ipv6
session full-tool 1200 250200123450002 22 preset=ims-ipv6
session downlink-tool 900 250200123450003 23 preset=enterprise-ethernet
show presets
show presets json
show matrix
show matrix json
show matrix 250200123450002 22 1440
show matrix 250200123450002 22 1440 json
show matrix 250200123450002 22 1440 tool-cmd
show matrix 250200123450002 22 1440 tool-cmd json
show matrix 250200123450002 22 1440 preset=ims-ipv6
show matrix 250200123450002 22 1440 preset=ims-ipv6 tool-cmd json
show matrix 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6
show matrix 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6 json
show compare 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6
show compare 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6 tool-cmd json
```

Legacy shortcut `profile=ims-ipv6` тоже остаётся валидным, но основной рекомендуемый вариант теперь `preset=...`.


`show presets` печатает доступные preset-ы и их разворот в `dnn=... profile=...`, чтобы сценарий можно было подобрать прямо из REPL без просмотра README.

`show presets json` возвращает schema-tagged JSON (`upf.presets.v1`) с массивом `presets`, где каждый элемент содержит `name`, `dnn` и `profile`.

`show matrix` строит полный derived preview для всех preset-ов на дефолтной сессии (`250200123456789` / `10`, `1200` bytes), чтобы быстро сравнить `teid`, UE addresses и profile-specific поля между `internet`, `ims` и `enterprise`.

Если передать `imsi pdu` и опционально `bytes`, матрица будет построена для этой сессии, а не для дефолтной пары.

Опция `preset=<name>` ограничивает вывод одной preset-строкой. Для совместимости поддерживается и alias `only=<name>`.

Опция `compare=<preset1,preset2>` ограничивает вывод двумя preset-ами в указанном порядке. Она взаимоисключающая с `preset=` / `only=`.

`show matrix json` возвращает schema-tagged JSON (`upf.matrix.v1`) с top-level `imsi`, `pdu`, `bytes` и массивом `entries` по всем preset-ам.

Режим `show matrix ... tool-cmd` разворачивает ту же матрицу, но для каждой preset-строки дополнительно показывает resolved `tool_path`, `config_path` и итоговую shell-команду запуска `n6_traffic_tool`. Для JSON-режима используется отдельная схема `upf.matrix-tool-command.v1`.

`show compare` даёт такой же preview-only compare output, но в отдельной локальной команде без привязки к `session validate` или `session compare`. Он требует `compare=<preset1,preset2>`, принимает тот же набор `imsi pdu [bytes]`, а также поддерживает `tool-cmd` и `json` с теми же схемами `upf.compare.v1` и `upf.compare-tool-command.v1`.

`session validate ...` не создает PFCP/N6/N3 трафик, а только показывает итоговый resolved target после применения `preset=...`, `dnn=...` и `profile=...`: bytes preview, IMSI, PDU, DNN, protocol profile, TEID, UE addresses/MAC и `request_id`.

Если первый positional аргумент задан числом, он трактуется как preview payload size для `full-tool` / `downlink-tool`; без него используется тот же default `1200` bytes.

Суффикс `json` переключает этот же вывод в schema-tagged JSON (`upf.session-target.v1`) с полями `bytes`, `imsi`, `pdu`, `dnn`, `profile`, `teid`, `ue_ipv4`, `ue_ipv6`, `ue_mac` и `request_id`.

Режим `session validate tool-cmd ...` использует тот же target/bytes preview, но дополнительно показывает resolved `tool_path`, `config_path` и итоговую shell-команду запуска `n6_traffic_tool`. Для JSON-режима используется отдельная схема `upf.session-tool-command.v1`.

Опция `compare=<preset1,preset2>` переключает `session validate` в режим `compare`: вместо одного resolved target выводятся две compare-entries для указанных preset-ов на одной IMSI/PDU/bytes-паре. Этот режим взаимоисключающий с `preset=`, `dnn=` и `profile=`. Для `tool-cmd json` используется схема `upf.compare-tool-command.v1`.


Команда `session compare ...` является коротким alias для этого compare-preview режима и использует тот же вывод, те же JSON-схемы и те же ограничения аргументов.


Compare examples:

```text
session compare 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6
show compare 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6
session compare tool-cmd 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6 json
show compare 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6 tool-cmd json
```


Ограничения `session compare` такие же строгие:

```text
session compare 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6
session compare tool-cmd 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6 json
```


Недопустимые варианты:

```text
session compare 1440 250200123450002 22 preset=ims-ipv6 compare=ims-ipv4,ims-ipv6
# ERR: compare cannot be combined with preset, dnn, or profile

session compare 1440 250200123450002 22 compare=ims-ipv6
# ERR: compare must be preset1,preset2
```


Одноразовый запуск без REPL:

```powershell
.\build\n6_traffic_tool.exe --delay-ms 200 --count 5 --interval-ms 120
.\build\upf.exe
```

## Интерактивный запуск

Для локального успешного PFCP/N4 сценария сначала поднимите mock peer:

```bash
cmake --build --preset default --target n4_mock_peer
./build/n4_mock_peer
```

В другом терминале запустите REPL:

```bash
./build/upf --interactive
```

Доступные команды:

- `help`
- `show running`
- `show running json`
- `show status`
- `show status json`
- `show n6-buffer`
- `show n6-buffer json`
- `set <key> <value>`
- `commit`

- `session full [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session full-tool [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session establish [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session modify [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session uplink [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session downlink [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session downlink-tool [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]`
- `session notify session-up`
- `session release [imsi pdu]`
- `tick`
- `clear-stats`
- `exit`

### PowerShell Example

Сборка:

```powershell
cd C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF
cmake --preset default
cmake --build --preset default --target upf n4_mock_peer n6_traffic_tool
```

Если вы запускаете команды из корня репозитория, используйте пути через `build`.

В первом терминале:

```powershell
.\build\n4_mock_peer.exe
```

Во втором терминале:

```powershell
.\build\upf.exe --interactive
```

В третьем терминале, чтобы дать реальный внешний downlink-пакет в N6 listener:

```powershell
.\build\n6_traffic_tool.exe --delay-ms 200 --count 5 --interval-ms 120
```

Если вы уже находитесь в каталоге `build`, используйте короткие команды:

```powershell
cd C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF\build
.\n4_mock_peer.exe
```

И во втором терминале:

```powershell
cd C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF\build
.\upf.exe --interactive
```

Для одноразового session-прогона без REPL:

```powershell
cd C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF
.\build\upf.exe
```

или из `build`:

```powershell
cd C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF\build
.\upf.exe
```


Пример ручной сессии с реальным внешним N6 packet:

```text
session validate 250200123450001 21 preset=ims-ipv6
session validate 1440 250200123450001 21 preset=ims-ipv6
session validate 250200123450001 21 preset=ims-ipv6 json
session validate 1440 250200123450001 21 preset=ims-ipv6 json
session validate tool-cmd 1440 250200123450001 21 preset=ims-ipv6
session validate tool-cmd 1440 250200123450001 21 preset=ims-ipv6 json
session validate 1440 250200123450001 21 compare=ims-ipv4,ims-ipv6
session validate tool-cmd 1440 250200123450001 21 compare=ims-ipv4,ims-ipv6 json
session establish 250200123450001 21 preset=ims-ipv6
session downlink-tool 1200 250200123450001 21 preset=ims-ipv6
show presets
show presets json
show matrix
show matrix json
show matrix 250200123450001 21 1440
show matrix 250200123450001 21 1440 json
show matrix 250200123450001 21 1440 tool-cmd
show matrix 250200123450001 21 1440 tool-cmd json
show matrix 250200123450001 21 1440 preset=ims-ipv6
show matrix 250200123450001 21 1440 preset=ims-ipv6 tool-cmd json
show matrix 250200123450001 21 1440 compare=ims-ipv4,ims-ipv6
show matrix 250200123450001 21 1440 compare=ims-ipv4,ims-ipv6 json
show status json
show n6-buffer json
exit
```

Недопустимые варианты для `show compare`:

```text
show compare 250200123450002 22 1440 preset=ims-ipv6 compare=ims-ipv4,ims-ipv6
# ERR: compare cannot be combined with preset, dnn, or profile

show compare 250200123450002 22 1440 compare=ims-ipv6
# ERR: compare must be preset1,preset2
```

`session full` в PR-2.2 сценарии тоже зависит от внешнего N6 packet. Если `n6_traffic_tool` не запущен и никакой другой peer не шлёт datagram в `n6_bind`, downlink завершится `timeout`.

Если `n4_mock_peer.exe` не запущен, `upf.exe` стартует, но уйдёт в `DEGRADED`, потому что не сможет установить PFCP/N4 session c `127.0.0.1:8805`.

## Внешний N6 downlink tool

```bash
cmake --build --preset default --target n6_traffic_tool
./build/n6_traffic_tool --delay-ms 200 --count 5 --interval-ms 120
```

По умолчанию tool ищет `config/upf-config.yaml` как из корня репозитория, так и из каталога `build`, шлёт пакет в `n6_bind` и использует session-значения той же PDU-сессии, что и `upf`. При необходимости можно переопределить `--endpoint`, `--imsi`, `--pdu`, `--protocol`, `--src`, `--dst`, `--bytes`, `--count` и `--interval-ms`.
