# vUPF (C++): 5G User Plane Function

Репозиторий реализует прототип UPF в том же стиле построения, что и проект SMF: разделение на ядро, адаптеры, runtime-конфиг, CLI и тесты.

## Что реализовано

- `UpfNode` как оркестратор состояния и жизненного цикла пользовательских сессий
- Модуль `SessionTable` для хранения контекстов PDU-сессий
- Интерфейсы и адаптеры N3/N4/N6/N9 + SBI
- Обработка PFCP establish/modify/delete через N4
- Uplink/downlink forwarding accounting (N3<->N6)
- Heartbeat-логика и переход `RUNNING -> DEGRADED -> RUNNING`
- Runtime config loader (`.json` и `.yaml`)
- CLI с candidate/running моделью (`set`, `commit`, `show`)
- Набор тестов для ядра, конфигурации, CLI и трафик-флоу

## Структура

- `include/upf` — публичные интерфейсы и заголовки
- `src` — реализация ядра, адаптеров, CLI и config
- `tests` — unit/integration-like тесты
- `config` — примеры runtime-конфигов

## Сборка

```bash
cmake --preset default
cmake --build --preset default
ctest --preset default
```

## Быстрый запуск

```bash
cmake --build --preset default --target upf
./build/default/upf
```
