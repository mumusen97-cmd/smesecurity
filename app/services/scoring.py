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


def calculate_score(severity: str, confidence: str) -> float:
    base = SEVERITY_POINTS.get(severity, 1)
    multiplier = CONFIDENCE_MULTIPLIER.get(confidence, 1.0)
    return round(base * multiplier, 2)
