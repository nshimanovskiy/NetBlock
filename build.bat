@echo off
cd /d "%~dp0"
python -m pip install --upgrade -r requirements-dev.txt || goto :err
python -m PyInstaller --onefile --noconsole --uac-admin --name NetBlock netblock.py || goto :err
if exist Portable rmdir /s /q Portable
mkdir Portable
copy /y dist\NetBlock.exe Portable\NetBlock.exe >nul
copy /y PORTABLE.txt Portable\README.txt >nul
echo.
echo Done. Portable version: %~dp0Portable
pause
exit /b 0
:err
echo Build failed.
pause
