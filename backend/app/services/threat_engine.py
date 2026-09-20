import hashlib
from datetime import datetime, timezone
from email.utils import getaddresses

from app.schemas.analysis import (
    AnalysisIndicator,
    AnalysisResult,
    AnalysisTimelineEvent,
    AnalyzedAttachment,
    AnalyzedUrl,
    Finding,
)
from app.schemas.email import EmailData
from app.services.attachment_analyzer import analyze_attachments
from app.services.authentication_analyzer import analyze_authentication
from app.services.content_analyzer import analyze_content
from app.services.header_analyzer import analyze_headers
from app.services.url_analyzer import analyze_urls


def _severity(score: int) -> str:
    if score <= 10:
        return "LOW"
    if score <= 35:
        return "MEDIUM"
    if score <= 65:
        return "HIGH"
    return "CRITICAL"


def _classify(email: EmailData, findings: list[Finding], analyzed_urls: list[AnalyzedUrl], analyzed_attachments: list[AnalyzedAttachment], score: int) -> str:
    categories = {finding.category for finding in findings if finding.risk_contribution > 0}
    has_credential = any(finding.id == "content_credential_language" for finding in findings)
    has_financial = any(finding.id == "content_financial_language" for finding in findings)
    has_suspicious_url = any(getattr(url, "status", "") == "SUSPICIOUS" for url in analyzed_urls)
    has_suspicious_attachment = any(getattr(attachment, "status", "") == "SUSPICIOUS" for attachment in analyzed_attachments)
    if has_credential and has_suspicious_url:
        return "Credential Phishing"
    if has_financial and email.metadata.subject and "invoice" in email.metadata.subject.lower():
        return "Invoice / Financial Fraud"
    if has_suspicious_attachment:
        return "Malicious Attachment"
    if "header" in categories or ("authentication" in categories and not has_credential):
        return "Spoofing / Impersonation"
    if score > 10:
        return "Suspicious Email"
    return "Benign / Low Risk"


def _recommendations(findings: list[Finding]) -> list[str]:
    categories = {finding.category for finding in findings if finding.risk_contribution > 0}
    recommendations: list[str] = []
    if "authentication" in categories:
        recommendations.append("Review sender authentication and consider quarantining the message.")
    if "url" in categories:
        recommendations.append("Inspect or block the suspicious URL through established security controls.")
    if "attachment" in categories:
        recommendations.append("Quarantine the attachment and preserve it for further analysis.")
    if "content" in categories:
        recommendations.append("Verify the request through an independent trusted channel.")
    if "header" in categories:
        recommendations.append("Confirm sender identity and routing details through a trusted channel.")
    if not recommendations:
        recommendations.append("No immediate action is indicated; retain the parsed evidence for audit history.")
    return recommendations


def _indicators(email: EmailData, analyzed_urls: list[AnalyzedUrl], analyzed_attachments: list[AnalyzedAttachment]) -> list[AnalysisIndicator]:
    indicators: list[AnalysisIndicator] = []
    seen: set[tuple[str, str]] = set()

    def add(indicator_type: str, value: str, source: str, status: str) -> None:
        key = (indicator_type, value)
        if value and key not in seen:
            seen.add(key)
            indicators.append(AnalysisIndicator(type=indicator_type, value=value, source=source, status=status))

    for address in [email.metadata.from_address, *email.metadata.to, *email.metadata.cc, *email.metadata.reply_to]:
        for _, parsed_address in getaddresses([address] if address else []):
            if parsed_address:
                add("EMAIL", parsed_address, "parsed email metadata", "OBSERVED")
                if "@" in parsed_address:
                    add("DOMAIN", parsed_address.rsplit("@", 1)[1].lower(), "parsed email metadata", "OBSERVED")
    for url in analyzed_urls:
        add("URL", url.url, "URL analyzer", "SUSPICIOUS" if url.status == "SUSPICIOUS" else "OBSERVED")
        add("DOMAIN", url.domain, "URL analyzer", "SUSPICIOUS" if url.status == "SUSPICIOUS" else "OBSERVED")
    for attachment in analyzed_attachments:
        add("HASH", attachment.sha256, "attachment metadata", "SUSPICIOUS" if attachment.status == "SUSPICIOUS" else "OBSERVED")
    for hop in email.headers.received:
        for ip in hop.observed_ip_candidates:
            add("IP", ip, "observed Received header", "OBSERVED")
    return indicators


def analyze_email(email: EmailData) -> AnalysisResult:
    header_findings = analyze_headers(email)
    authentication, authentication_findings = analyze_authentication(email)
    analyzed_urls, url_findings = analyze_urls(email)
    analyzed_attachments, attachment_findings = analyze_attachments(email)
    content_findings = analyze_content(email)
    findings = [*header_findings, *authentication_findings, *url_findings, *attachment_findings, *content_findings]
    score = min(sum(finding.risk_contribution for finding in findings), 100)
    timestamp = datetime.now(timezone.utc).isoformat()
    timeline_labels = [
        ("Message parsed", "EmailData created from the uploaded message."),
        ("Headers analyzed", "Observable sender and routing relationships evaluated."),
        ("Authentication evidence evaluated", "Explicit authentication header results interpreted without live verification."),
        ("URLs analyzed", "Extracted URLs evaluated for structural indicators only."),
        ("Attachments analyzed", "Attachment metadata evaluated without execution or scanning."),
        ("Content signals evaluated", "Deterministic language groups evaluated in decoded bodies."),
        ("Risk calculated", "Transparent analyzer contributions capped at 100."),
        ("Threat classified", "Evidence-driven category selected from observed findings."),
    ]
    return AnalysisResult(
        incident_id="INC-" + hashlib.sha256((email.metadata.message_id or email.body.plain_text or "empty-email").encode()).hexdigest()[:10].upper(),
        risk_score=score,
        severity=_severity(score),
        threat_type=_classify(email, findings, analyzed_urls, analyzed_attachments, score),
        metadata=email.metadata,
        authentication=authentication,
        urls=analyzed_urls,
        attachments=analyzed_attachments,
        findings=findings,
        indicators=_indicators(email, analyzed_urls, analyzed_attachments),
        timeline=[AnalysisTimelineEvent(label=label, timestamp=timestamp, detail=detail) for label, detail in timeline_labels],
        geolocation=None,
        recommendations=_recommendations(findings),
        analyzed_at=timestamp,
    )