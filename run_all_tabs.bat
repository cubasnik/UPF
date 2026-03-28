@echo off
REM Запуск всех .bat-файлов в отдельных вкладках Windows Terminal
wt -w 0 ^
  new-tab -d "C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF" cmd /k run_all.bat ; ^
  new-tab -d "C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF" cmd /k run_upf.bat ; ^
  new-tab -d "C:\Users\Alexey\Desktop\min\vNE\vUPF\UPF" cmd /k run_upf_menu.bat
