# PR-2.1 Review Checklist

## Scope

- N6 downlink buffering вынесен в отдельный `N6PacketBuffer`
- `NetworkN6Adapter` и `ConsoleN6Adapter` используют один и тот же buffer abstraction
- runtime-конфиг экспортирует `n6_buffer_capacity` и `n6_buffer_overflow_policy`
- live `UpfNode::status()` и CLI экспортируют N6 buffer metrics

## Functional Checks

- bounded buffering выполняется per-session, а не глобально
- при `drop_oldest` новый пакет принимается, старый вытесняется
- при `drop_newest` существующий buffered packet сохраняется, новый отклоняется
- buffered state очищается при удалении N6-session
- downlink packets для неизвестной сессии не создают queue state

## Metrics Checks

- `enqueued_packets` увеличивается только на реально buffered packets
- `dequeued_packets` отражает только успешную выдачу из буфера
- `dropped_packets` включает overflow, session removal и unknown-session drops
- `dropped_overflow_oldest`, `dropped_overflow_newest`, `dropped_session_removed`, `dropped_unknown_session` согласованы с общим `dropped_packets`
- `rejected_by_policy` растёт только для policy-reject path (`drop_newest`)

## CLI Checks

- `show running` отражает `n6_buffer_capacity` и `n6_buffer_policy`
- `show status` показывает live state и forwarding counters
- `show n6-buffer` показывает capacity, overflow policy, occupancy и drop counters
- `show n6-buffer session <imsi> <pdu>` показывает per-session `enqueued`, `dequeued`, `dropped`, breakdown `dropped_oldest`/`dropped_newest`/`dropped_session_removed`, `rejected_by_policy`, `buffered` и session metadata
- `show n6-buffer session <imsi> <pdu> json` возвращает тот же per-session snapshot в structured JSON виде
- `show status json` и `show n6-buffer json` возвращают global live snapshots в structured JSON виде
- `show running json` / `show candidate json` используют общий serializer path, а не локальный CLI formatter
- JSON schema markers разделены по payload family: runtime config, live status, global N6 buffer, per-session N6, SBI event и SBI envelope
- SBI request body и PFCP response/detail formatting больше не собираются inline в `network_adapters.cpp`
- PFCP session request wire encoding вынесен в protocol-level `pfcp_wire` serializer/helper path
- `unknown_session` проверяется только на глобальном уровне, без искусственной привязки к per-session view

## SBI Event Exposure Checks

- `notify_sbi("nupf-event-exposure", ...)` добавляет live status и N6 buffer metrics к публикуемому payload
- payload структурирован как JSON object с `message`, `status` и `n6_buffer`
- `status` содержит как минимум `state`, `active_sessions`, `n4_messages`, `n6_forwards`
- `n6_buffer` содержит как минимум `capacity`, `overflow_policy`, `buffered`, `dropped` и policy-specific counters

## Validation

- targeted tests для `N6PacketBuffer` покрывают оба overflow policy
- transport tests покрывают unknown-session drop и `drop_newest`
- full CTest остаётся зелёным после интеграции
