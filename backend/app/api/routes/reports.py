from fastapi import APIRouter, HTTPException, status

from app.schemas.forensics import ForensicReport
from app.services.report_store import get_report

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports/{incident_id}", response_model=ForensicReport)
def report(incident_id: str) -> ForensicReport:
    result = get_report(incident_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found")
    return result