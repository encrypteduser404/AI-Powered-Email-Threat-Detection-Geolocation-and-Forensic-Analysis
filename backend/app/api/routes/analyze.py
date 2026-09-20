from fastapi import APIRouter, File, UploadFile

from app.schemas.analysis import AnalysisResult
from app.services.intake import validate_eml_upload

router = APIRouter(prefix="/api", tags=["analysis"])


@router.post(
    "/analyze",
    response_model=AnalysisResult,
)
async def analyze(file: UploadFile = File(...)) -> AnalysisResult:
    return await validate_eml_upload(file)