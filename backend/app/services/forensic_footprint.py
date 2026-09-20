import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from app.core.config import settings
from app.schemas.analysis import AnalysisResult
from app.schemas.email import EmailData
from app.schemas.forensics import (
    AnalyticalEvidence,
    ArtifactEvidence,
    EvidenceSource,
    FootprintMessage,
    ForensicFootprint,
    HeaderEvidence,
    IntegrityMetadata,
    NetworkEvidence,
    ProcessingMetadata,
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_forensic_footprint(raw_bytes: bytes, filename: str, media_type: str, email: EmailData, analysis: AnalysisResult, received_at: str, started_at: str, completed_at: str) -> ForensicFootprint:
    source_hash = hashlib.sha256(raw_bytes).hexdigest()
    evidence_id = f"EVD-{uuid4().hex[:12].upper()}"
    observed_domains = sorted({url.domain for url in email.urls})
    observed_ips = sorted({ip for hop in email.headers.received for ip in hop.observed_ip_candidates})
    authentication_headers = [*email.headers.authentication.authentication_results, *email.headers.authentication.arc_authentication_results, *email.headers.authentication.received_spf, *email.headers.authentication.dkim_signature]
    footprint_without_integrity = {
        "incident_id": analysis.incident_id,
        "evidence_id": evidence_id,
        "source_sha256": source_hash,
        "attachment_hashes": sorted(attachment.sha256 for attachment in email.attachments),
        "observed_urls": sorted(url.url for url in email.urls),
        "observed_ips": observed_ips,
        "message_id": email.metadata.message_id,
    }
    manifest_bytes = json.dumps(footprint_without_integrity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    return ForensicFootprint(
        evidence_id=evidence_id,
        incident_id=analysis.incident_id,
        source=EvidenceSource(filename=filename, media_type=media_type or "message/rfc822", size_bytes=len(raw_bytes), sha256=source_hash),
        processing=ProcessingMetadata(received_at=received_at, analysis_started_at=started_at, analysis_completed_at=completed_at, parser_version=settings.parser_version, analysis_engine_version=settings.analysis_engine_version),
        message=FootprintMessage(sender=email.metadata.from_address, recipients=[*email.metadata.to, *email.metadata.cc, *email.metadata.bcc], subject=email.metadata.subject, message_id=email.metadata.message_id, date=email.metadata.date, reply_to=email.metadata.reply_to, return_path=email.metadata.return_path),
        header_evidence=HeaderEvidence(received_hops=[hop.raw for hop in email.headers.received], authentication_headers=authentication_headers),
        network_evidence=NetworkEvidence(observed_ips=observed_ips, observed_domains=observed_domains, observed_urls=[url.url for url in email.urls]),
        artifact_evidence=ArtifactEvidence(attachments=[attachment.filename for attachment in email.attachments], attachment_hashes=[attachment.sha256 for attachment in email.attachments]),
        analytical_evidence=AnalyticalEvidence(findings=analysis.findings, indicators=analysis.indicators, risk_score=analysis.risk_score, severity=analysis.severity, threat_type=analysis.threat_type),
        timeline=analysis.timeline,
        recommendations=analysis.recommendations,
        integrity=IntegrityMetadata(original_email_sha256=source_hash, evidence_manifest_sha256=manifest_hash),
    )