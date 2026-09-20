from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.analysis import AnalysisResult
from app.schemas.forensics import FootprintMessage, ForensicFootprint, ForensicReport, HeaderEvidence


def generate_forensic_report(analysis_result: AnalysisResult, forensic_footprint: ForensicFootprint, analyst_notes: str = "") -> ForensicReport:
    report_id = f"ECH-RPT-{uuid4().hex[:8].upper()}"
    return ForensicReport(
        report_id=report_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        incident={"incident_id": analysis_result.incident_id, "risk_score": analysis_result.risk_score, "severity": analysis_result.severity, "threat_type": analysis_result.threat_type},
        executive_summary=f"{analysis_result.threat_type} assessment with a Risk Score of {analysis_result.risk_score} / 100. Findings are based on observable message evidence and deterministic analysis.",
        evidence_provenance=forensic_footprint,
        email_metadata=forensic_footprint.message,
        authentication={"results": analysis_result.authentication.model_dump(), "raw_evidence": forensic_footprint.header_evidence.authentication_headers, "note": "Observed header evidence; no cryptographic or live DNS verification was performed."},
        routing=forensic_footprint.header_evidence,
        url_evidence=analysis_result.urls,
        attachment_evidence=analysis_result.attachments,
        ioc_manifest=analysis_result.indicators,
        findings=analysis_result.findings,
        infrastructure=None,
        forensic_timeline=analysis_result.timeline,
        recommendations=analysis_result.recommendations,
        analyst_notes=analyst_notes,
        integrity=forensic_footprint.integrity,
    )