@echo off
chcp 65001 >nul

:menu
echo Выберите режим запуска UPF:
echo 1. Интерактивный REPL (--cli)
echo 2. Запуск с конфигом (--config config\runtime_config.json)
echo 3. Обычный режим (по умолчанию)
echo 4. Выход
set /p mode=Введите номер (1-4): 

if "%mode%"=="1" goto cli
if "%mode%"=="2" goto config
if "%mode%"=="3" goto default
if "%mode%"=="4" exit

echo Неверный выбор!
goto menu

:cli
build\upf.exe --cli
pause
goto menu

:config
build\upf.exe --config config\runtime_config.json
pause
goto menu

:default
build\upf.exe
pause
goto menu
