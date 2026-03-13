#severity gets a base score, confidence adjusts it up or down
SEVERITY_POINTS = {
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 8,
    "CRITICAL": 10,
}

CONFIDENCE_MULTIPLIER = {
    "LOW": 0.8,
    "MEDIUM": 1.0,
    "HIGH": 1.2,
}


#multiply severity by confidence to get a single risk score
def calculate_score(severity: str, confidence: str) -> float:
    base = SEVERITY_POINTS.get(severity, 1)
    multiplier = CONFIDENCE_MULTIPLIER.get(confidence, 1.0)
    return round(base * multiplier, 2)


#buckets the score into a label that non-technical users can understand
def classify_risk_band(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"
