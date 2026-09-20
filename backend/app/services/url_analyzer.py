import ipaddress
from urllib.parse import urlsplit

from app.schemas.analysis import AnalyzedUrl, Finding
from app.schemas.email import EmailData


def analyze_urls(email: EmailData) -> tuple[list[AnalyzedUrl], list[Finding]]:
    analyzed: list[AnalyzedUrl] = []
    findings: list[Finding] = []
    for index, url in enumerate(email.urls):
        parsed = urlsplit(url.url)
        indicators: list[str] = []
        is_ip_hostname = False
        if url.scheme == "http":
            indicators.append("HTTP transport")
        try:
            ipaddress.ip_address(url.domain)
            is_ip_hostname = True
            indicators.append("Raw IP hostname")
        except ValueError:
            pass
        if not is_ip_hostname and len(url.domain.split(".")) >= 4:
            indicators.append("Excessive subdomain depth")
        if "%" in url.url:
            indicators.append("Encoded URL characters")
        if any(keyword in parsed.path.lower() for keyword in ("login", "signin", "sign-in", "verify", "password", "credential")):
            indicators.append("Credential-related path")
        if len(url.url) > 200:
            indicators.append("Unusually long URL")
        if "xn--" in url.domain.lower():
            indicators.append("Punycode hostname")
        risk = min(25, len(indicators) * 10)
        status = "SUSPICIOUS" if indicators else "BENIGN"
        analyzed.append(AnalyzedUrl(url=url.url, domain=url.domain, scheme=url.scheme, indicators=indicators, status=status, risk_contribution=risk))
        if indicators:
            findings.append(Finding(id=f"url_structural_{index}", category="url", title="Suspicious URL structure observed", severity="MEDIUM", description="The URL contains structural indicators that warrant analyst review; no reputation lookup was performed.", evidence=f"{url.url}: {', '.join(indicators)}", risk_contribution=risk, source="URL structure"))
    return analyzed, findings