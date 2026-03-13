from app.models import NormalizedFinding


#maps finding types to specific gdpr articles and pci-dss requirements
OWASP_TO_COMPLIANCE = {
    "sql injection": ["PCI-DSS 6.5", "GDPR Art. 32"],
    "cross-site scripting": ["PCI-DSS 6.5", "GDPR Art. 25"],
    "security misconfiguration": ["PCI-DSS 2.2", "GDPR Art. 32"],
    "authentication": ["PCI-DSS 8", "GDPR Art. 32"],
    "cookie": ["PCI-DSS 6.5", "GDPR Art. 25"],
    "transport layer": ["PCI-DSS 4", "GDPR Art. 32"],
    "information disclosure": ["GDPR Art. 5", "GDPR Art. 32"],
}


#checks the finding title against keywords and tags it with compliance refs
def apply_compliance_tags(finding: NormalizedFinding) -> NormalizedFinding:
    title = finding.title.strip().lower()
    #default tag if nothing matches
    tags = ["Review Required"]
    for keyword, mapped_tags in OWASP_TO_COMPLIANCE.items():
        if keyword in title:
            tags = mapped_tags
            break
    finding.compliance_tags = tags
    return finding
