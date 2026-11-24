@echo off
echo Starting CNN-LSTM Realtime NIDS Backend on http://127.0.0.1:8000 ...
cd /d "%~dp0.."
".venv\Scripts\python.exe" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
