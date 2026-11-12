@echo off
title Women's Safety Heatmap
cd /d "%~dp0"

rem ---- find Python (python or py) ----
set PY=python
where python >nul 2>nul || set PY=py
where %PY% >nul 2>nul || (
  echo Python is not installed. Download it from https://www.python.org/downloads/
  echo During install, tick "Add Python to PATH". Then run this file again.
  pause & exit /b 1
)

echo [1/3] Installing packages (first time only)...
%PY% -m pip install -r requirements.txt
if errorlevel 1 ( echo Package install failed. Check your internet connection. & pause & exit /b 1 )

echo [2/3] Preparing database...
if not exist safety.db %PY% seed_data.py

echo [3/3] Starting app... browser will open at http://127.0.0.1:5000
echo Close this window (or press Ctrl+C) to stop the app.
start "" http://127.0.0.1:5000
%PY% app.py
pause
