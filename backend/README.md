# ECHO Intake API

This backend milestone extracts structured facts from `.eml` messages. It does not perform threat analysis and does not return the frontend `AnalysisResult` yet.

## Run

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API exposes `GET /api/health` and `POST /api/analyze`. The analyze endpoint expects a multipart field named `file` containing an `.eml` file.

Successful parsing returns `200 OK` with typed `EmailData`: metadata, selected headers, observed `Received` hops, raw authentication evidence, decoded plain text/HTML bodies, extracted HTTP(S) URLs, attachment hashes, and factual parser statistics.

The parser uses Python's standard-library `email` package and keeps attachment bytes in memory only. It does not fetch URLs, resolve domains, execute attachments, score risk, or classify messages.