@echo off
REM Запуск всех основных компонентов vUPF в отдельных окнах

start "UPF" build\upf.exe --config config\runtime_config.json
start "N4 Mock Peer" build\n4_mock_peer.exe
start "N6 Traffic Tool" build\n6_traffic_tool.exe --delay-ms 200 --count 5 --interval-ms 120
REM Следующая строка — CLI, если нужен отдельный REPL:
start "UPF CLI" build\upf.exe --cli
