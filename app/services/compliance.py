from app.models import NormalizedFinding


OWASP_TO_COMPLIANCE = {
    "SQL Injection": ["PCI-DSS 6.5", "GDPR Art. 32"],
    "Cross-Site Scripting": ["PCI-DSS 6.5", "GDPR Art. 25"],
    "Security Misconfiguration": ["PCI-DSS 2.2", "GDPR Art. 32"],
}


def apply_compliance_tags(finding: NormalizedFinding) -> NormalizedFinding:
    tags = OWASP_TO_COMPLIANCE.get(finding.title, ["Review Required"])
    finding.compliance_tags = tags
    return finding
