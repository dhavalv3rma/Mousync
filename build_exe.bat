@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt pyinstaller --quiet
pyinstaller --noconfirm --onefile --noconsole --name MouseBridge --icon assets\icon.ico --add-data "assets;assets" --hidden-import pystray._win32 mousebridge.py
echo.
echo Done: dist\MouseBridge.exe  (copy it to both PCs - no Python needed there)
pause
