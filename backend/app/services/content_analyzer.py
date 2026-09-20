import re

from app.schemas.analysis import Finding
from app.schemas.email import EmailData

GROUPS = {
    "credential": ("Credential-related language observed", 15, ("verify your account", "login", "sign in", "password", "credentials", "confirm identity")),
    "urgency": ("Urgency language observed", 10, ("urgent", "immediately", "action required", "suspended", "expires today", "final warning")),
    "financial": ("Financial request language observed", 10, ("invoice", "payment", "wire transfer", "bank account", "transaction")),
    "security": ("Security alert language observed", 10, ("security alert", "unusual activity", "account locked", "verify identity")),
}


def analyze_content(email: EmailData) -> list[Finding]:
    content = "\n".join(value for value in (email.body.plain_text, email.body.html) if value).lower()
    findings: list[Finding] = []
    for group, (title, risk, phrases) in GROUPS.items():
        matches = [phrase for phrase in phrases if re.search(re.escape(phrase), content, re.IGNORECASE)]
        if matches:
            findings.append(Finding(id=f"content_{group}_language", category="content", title=title, severity="MEDIUM", description="Suspicious language was observed in the decoded message content; keyword presence alone does not prove phishing.", evidence="Matched phrases: " + ", ".join(matches), risk_contribution=risk, source="decoded message body"))
    return findings