from pydantic import BaseModel, Field

from app.schemas.analysis import AnalysisIndicator, AnalysisTimelineEvent, Finding


class EvidenceSource(BaseModel):
    filename: str
    media_type: str
    size_bytes: int
    sha256: str


class ProcessingMetadata(BaseModel):
    received_at: str
    analysis_started_at: str
    analysis_completed_at: str
    parser_version: str
    analysis_engine_version: str


class FootprintMessage(BaseModel):
    sender: str | None = None
    recipients: list[str] = Field(default_factory=list)
    subject: str | None = None
    message_id: str | None = None
    date: str | None = None
    reply_to: list[str] = Field(default_factory=list)
    return_path: str | None = None


class HeaderEvidence(BaseModel):
    received_hops: list[str] = Field(default_factory=list)
    authentication_headers: list[str] = Field(default_factory=list)


class NetworkEvidence(BaseModel):
    observed_ips: list[str] = Field(default_factory=list)
    observed_domains: list[str] = Field(default_factory=list)
    observed_urls: list[str] = Field(default_factory=list)


class ArtifactEvidence(BaseModel):
    attachments: list[str] = Field(default_factory=list)
    attachment_hashes: list[str] = Field(default_factory=list)


class AnalyticalEvidence(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    indicators: list[AnalysisIndicator] = Field(default_factory=list)
    risk_score: int
    severity: str
    threat_type: str


class IntegrityMetadata(BaseModel):
    original_email_sha256: str
    evidence_manifest_sha256: str


class ForensicFootprint(BaseModel):
    evidence_id: str
    incident_id: str
    source: EvidenceSource
    processing: ProcessingMetadata
    message: FootprintMessage
    header_evidence: HeaderEvidence
    network_evidence: NetworkEvidence
    artifact_evidence: ArtifactEvidence
    analytical_evidence: AnalyticalEvidence
    timeline: list[AnalysisTimelineEvent] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    integrity: IntegrityMetadata


class ForensicReport(BaseModel):
    report_id: str
    generated_at: str
    incident: dict[str, str | int]
    executive_summary: str
    evidence_provenance: ForensicFootprint
    email_metadata: FootprintMessage
    authentication: dict[str, object]
    routing: HeaderEvidence
    url_evidence: list[object] = Field(default_factory=list)
    attachment_evidence: list[object] = Field(default_factory=list)
    ioc_manifest: list[AnalysisIndicator] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    infrastructure: None = None
    forensic_timeline: list[AnalysisTimelineEvent] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
    integrity: IntegrityMetadata
