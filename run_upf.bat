@echo off
REM Сборка и запуск vUPF

REM Переход в директорию проекта
cd /d %~dp0

REM Сборка проекта через CMake
cmake --preset default
cmake --build --preset default --target upf

REM Запуск программы с конфигом (если есть)
IF EXIST config\runtime_config.json (
    .\build\upf.exe --config config\runtime_config.json
) ELSE (
    .\build\upf.exe
)

pause