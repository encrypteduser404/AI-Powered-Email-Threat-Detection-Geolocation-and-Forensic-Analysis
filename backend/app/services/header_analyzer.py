from email.utils import getaddresses

from app.schemas.analysis import Finding
from app.schemas.email import EmailData


def _domain(address: str | None) -> str | None:
    if not address:
        return None
    parsed = getaddresses([address])
    value = parsed[0][1] if parsed else address
    return value.rsplit("@", 1)[1].lower() if "@" in value else None


def _finding(title: str, description: str, evidence: str, risk: int, source: str, finding_id: str, severity: str = "MEDIUM") -> Finding:
    return Finding(id=finding_id, category="header", title=title, severity=severity, description=description, evidence=evidence, risk_contribution=risk, source=source)


def analyze_headers(email: EmailData) -> list[Finding]:
    findings: list[Finding] = []
    sender_domain = _domain(email.metadata.from_address)
    reply_domains = {_domain(address) for address in email.metadata.reply_to}
    reply_domains.discard(None)
    if sender_domain and reply_domains and reply_domains != {sender_domain}:
        findings.append(_finding("Reply-To domain mismatch", "The reply destination differs from the sender domain.", f"From domain: {sender_domain}; Reply-To domain(s): {', '.join(sorted(reply_domains))}", 15, "header metadata", "reply_to_domain_mismatch"))

    return_path_domain = _domain(email.metadata.return_path)
    if sender_domain and return_path_domain and return_path_domain != sender_domain:
        findings.append(_finding("Return-Path domain mismatch", "The envelope return path differs from the sender domain.", f"From domain: {sender_domain}; Return-Path domain: {return_path_domain}", 10, "header metadata", "return_path_domain_mismatch"))

    if not email.metadata.message_id:
        findings.append(_finding("Message-ID header missing", "The message does not contain a Message-ID header.", "Message-ID was not present in the parsed metadata.", 0, "header metadata", "missing_message_id", "LOW"))
    if not email.metadata.date:
        findings.append(_finding("Date header missing", "The message does not contain a Date header.", "Date was not present in the parsed metadata.", 0, "header metadata", "missing_date", "LOW"))
    return findings