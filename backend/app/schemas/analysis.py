from pydantic import BaseModel
from typing import Literal

from app.schemas.email import EmailAttachment, EmailMetadata, EmailUrl


class HealthResponse(BaseModel):
    status: str
    service: str


class UploadAnalysisResponse(BaseModel):
    status: str
    filename: str
    content_type: str
    size_bytes: int


AnalysisSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
FindingCategory = Literal["authentication", "header", "url", "attachment", "content"]
AuthenticationState = Literal["PASS", "FAIL", "NEUTRAL", "UNKNOWN"]
UrlStatus = Literal["BENIGN", "SUSPICIOUS", "UNKNOWN"]
IndicatorType = Literal["EMAIL", "DOMAIN", "URL", "IP", "HASH"]
IndicatorStatus = Literal["OBSERVED", "SUSPICIOUS", "UNKNOWN"]


class Finding(BaseModel):
    id: str
    category: FindingCategory
    title: str
    severity: AnalysisSeverity
    description: str
    evidence: str
    risk_contribution: int
    source: str


class AuthenticationAnalysis(BaseModel):
    spf: AuthenticationState
    dkim: AuthenticationState
    dmarc: AuthenticationState
    dkim_signature_observed: bool = False


class AnalyzedUrl(BaseModel):
    url: str
    domain: str
    scheme: Literal["http", "https"]
    indicators: list[str]
    status: UrlStatus
    risk_contribution: int


class AnalyzedAttachment(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    content_disposition: str | None = None
    indicators: list[str]
    status: Literal["OBSERVED", "SUSPICIOUS"]
    risk_contribution: int


class AnalysisIndicator(BaseModel):
    type: IndicatorType
    value: str
    source: str
    status: IndicatorStatus


class AnalysisTimelineEvent(BaseModel):
    label: str
    timestamp: str
    detail: str


class AnalysisResult(BaseModel):
    incident_id: str
    risk_score: int
    severity: AnalysisSeverity
    threat_type: str
    metadata: EmailMetadata
    authentication: AuthenticationAnalysis
    urls: list[AnalyzedUrl]
    attachments: list[AnalyzedAttachment]
    findings: list[Finding]
    indicators: list[AnalysisIndicator]
    timeline: list[AnalysisTimelineEvent]
    geolocation: None = None
    recommendations: list[str]
    analyzed_at: str
    forensic_footprint: dict[str, object] | None = None