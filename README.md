# CryptoAPI-Safe

Post-Quantum Cryptographic API Misuse Detection — a small demo that statically analyzes Python code (AST) to find incorrect PQC API usage (example: passing a public key to a signing API).

## Contents
- backend/: Flask API and AST scanner
  - backend/app.py — API server (POST /api/scan)
  - backend/analyzer/scanner.py — demo AST rules
  - backend/requirements.txt — Python dependencies (liboqs-python, flask, flask-cors)
  - backend/crypto/mlkem_demo.py — example using liboqs
- backend/frontend/: Vite + React frontend (UI to paste code and view findings)

## Requirements
- Windows (PowerShell instructions)
- Python 3.11+ (venv provided)
- Node.js + npm

## Setup
1. Open PowerShell in project root:
   cd C:\Users\nithy\OneDrive\Desktop\CryptoSafe

2. Backend (Terminal 1):
   venv\Scripts\Activate.ps1
   python -m pip install -r backend\requirements.txt
   # liboqs-python will fetch/build liboqs (may take several minutes)

3. Frontend (Terminal 2):
   cd backend/frontend
   npm install

## Run
- Backend (keep terminal open):
  $env:PYTHONUTF8='1'   # optional — ensures UTF-8 console output for emojis
  python .\backend\app.py
  (Server: http://127.0.0.1:5000)

- Frontend:
  cd backend\frontend
  npm run dev
  (Open: http://localhost:5173 or the port Vite prints)

## Quick test (PowerShell)
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/scan -ContentType 'application/json' -Body (ConvertTo-Json @{ code = "print('hi')" })

## Notes & Troubleshooting
- First-time liboqs build is slow; be patient.
- If you see `ModuleNotFoundError: No module named 'oqs'`, re-run pip install in the active venv.
- If PowerShell cannot print emojis, set `PYTHONUTF8=1` or use `chcp 65001`.
- To stop servers: Ctrl+C in their terminals.

## Where to edit rules
- backend/analyzer/scanner.py — add/adjust AST rules and returned finding format.

## License
MIT
