@echo off
cd /d "%~dp0"
if not exist "..\.venv\Scripts\python.exe" (
  echo Create the project .venv and install requirements.txt first.
  pause
  exit /b 1
)
"..\.venv\Scripts\python.exe" main.py
pause
