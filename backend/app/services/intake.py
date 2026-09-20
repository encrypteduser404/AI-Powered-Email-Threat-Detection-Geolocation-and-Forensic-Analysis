import re
from datetime import datetime, timezone

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings
from app.schemas.email import EmailData
from app.schemas.analysis import AnalysisResult
from app.services.email_parser import parse_email
from app.services.threat_engine import analyze_email
from app.services.forensic_footprint import build_forensic_footprint
from app.services.report_generator import generate_forensic_report
from app.services.report_store import store_report

HEADER_PATTERN = re.compile(r"(?m)^[A-Za-z][A-Za-z0-9-]*:\s*.+$")


async def validate_eml_upload(file: UploadFile) -> AnalysisResult:
    received_at = datetime.now(timezone.utc).isoformat()
    filename = file.filename or ""
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="An .eml file is required")
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported file type. Please upload an .eml file")

    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Upload exceeds the 10 MB limit")
    if not content.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The .eml file is empty")

    decoded_content = content.decode("utf-8", errors="replace")
    if not HEADER_PATTERN.search(decoded_content):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="The file does not contain recognizable email-style headers")
    analysis_started_at = datetime.now(timezone.utc).isoformat()
    parsed_email: EmailData = parse_email(content)
    result = analyze_email(parsed_email)
    analysis_completed_at = datetime.now(timezone.utc).isoformat()
    footprint = build_forensic_footprint(content, filename, file.content_type or "message/rfc822", parsed_email, result, received_at, analysis_started_at, analysis_completed_at)
    result.forensic_footprint = footprint.model_dump()
    store_report(generate_forensic_report(result, footprint))
    return result