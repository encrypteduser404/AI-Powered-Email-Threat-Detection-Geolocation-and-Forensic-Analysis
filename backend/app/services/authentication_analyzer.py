import re

from app.schemas.analysis import AuthenticationAnalysis, Finding
from app.schemas.email import EmailData

RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
FAILURE_RESULTS = {"fail", "softfail", "permerror"}


def _state(results: list[str], protocol: str) -> str:
    values = [match.group(2).lower() for value in results for match in RESULT_PATTERN.finditer(value) if match.group(1).lower() == protocol]
    if any(value in FAILURE_RESULTS for value in values):
        return "FAIL"
    if "pass" in values:
        return "PASS"
    if any(value in {"neutral", "none", "temperror"} for value in values):
        return "NEUTRAL"
    return "UNKNOWN"


def analyze_authentication(email: EmailData) -> tuple[AuthenticationAnalysis, list[Finding]]:
    evidence = email.headers.authentication
    all_results = evidence.authentication_results + evidence.arc_authentication_results + evidence.received_spf
    authentication = AuthenticationAnalysis(
        spf=_state(all_results, "spf"),
        dkim=_state(all_results, "dkim"),
        dmarc=_state(all_results, "dmarc"),
        dkim_signature_observed=bool(evidence.dkim_signature),
    )
    findings: list[Finding] = []
    if authentication.spf == "FAIL":
        findings.append(Finding(id="spf_explicit_failure", category="authentication", title="SPF reported fail", severity="MEDIUM", description="Authentication evidence explicitly reported an SPF failure.", evidence="SPF result observed in authentication headers.", risk_contribution=15, source="authentication evidence"))
    if authentication.dmarc == "FAIL":
        findings.append(Finding(id="dmarc_explicit_failure", category="authentication", title="DMARC reported fail", severity="HIGH", description="Authentication evidence explicitly reported a DMARC failure.", evidence="DMARC result observed in authentication headers.", risk_contribution=20, source="authentication evidence"))
    if authentication.dkim == "FAIL":
        findings.append(Finding(id="dkim_explicit_failure", category="authentication", title="DKIM reported fail", severity="MEDIUM", description="Authentication evidence explicitly reported a DKIM failure.", evidence="DKIM result observed in authentication headers.", risk_contribution=15, source="authentication evidence"))
    return authentication, findings