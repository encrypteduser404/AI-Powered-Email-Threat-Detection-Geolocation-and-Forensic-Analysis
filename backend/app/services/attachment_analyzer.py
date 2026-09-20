import re
from pathlib import PurePosixPath

from app.schemas.analysis import AnalyzedAttachment, Finding
from app.schemas.email import EmailData

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}


def analyze_attachments(email: EmailData) -> tuple[list[AnalyzedAttachment], list[Finding]]:
    analyzed: list[AnalyzedAttachment] = []
    findings: list[Finding] = []
    for index, attachment in enumerate(email.attachments):
        name = attachment.filename.lower()
        suffixes = PurePosixPath(name).suffixes
        indicators: list[str] = []
        if any(suffix in EXECUTABLE_EXTENSIONS for suffix in suffixes):
            indicators.append("Executable or script extension")
        if any(suffix in MACRO_EXTENSIONS for suffix in suffixes):
            indicators.append("Macro-capable office extension")
        if any(suffix in ARCHIVE_EXTENSIONS for suffix in suffixes):
            indicators.append("Archive extension")
        if len(suffixes) >= 2 and re.search(r"\.[a-z0-9]{1,8}\.[a-z0-9]{1,8}$", name):
            indicators.append("Double extension")
        risk = min(35, (20 if any(suffix in EXECUTABLE_EXTENSIONS for suffix in suffixes) else 0) + (20 if any(suffix in MACRO_EXTENSIONS for suffix in suffixes) else 0) + (15 if "Double extension" in indicators else 0))
        status = "SUSPICIOUS" if indicators else "OBSERVED"
        analyzed.append(AnalyzedAttachment(filename=attachment.filename, content_type=attachment.content_type, size_bytes=attachment.size_bytes, sha256=attachment.sha256, content_disposition=attachment.content_disposition, indicators=indicators, status=status, risk_contribution=risk))
        if indicators:
            findings.append(Finding(id=f"attachment_structure_{index}", category="attachment", title="Suspicious attachment type", severity="HIGH" if risk >= 20 else "MEDIUM", description="Attachment metadata contains a structural indicator that warrants analyst review; the file was not executed or scanned.", evidence=f"{attachment.filename}: {', '.join(indicators)}", risk_contribution=risk, source="attachment metadata"))
    return analyzed, findings