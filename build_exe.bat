@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt pyinstaller --quiet
pyinstaller --noconfirm --onefile --noconsole --name MouseBridge mousebridge.py
echo.
echo Done: dist\MouseBridge.exe  (copy it to both PCs - no Python needed there)
pause
