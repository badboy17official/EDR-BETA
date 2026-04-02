from datetime import datetime, timezone

from core.config import settings


def classify_risk(risk_score: float, frequency: int) -> str:
    # Dynamic threshold tuning: frequent sightings lower the malicious cutoff slightly.
    dynamic_malicious = max(50.0, settings.MALICIOUS_THRESHOLD - min(10.0, frequency * 0.2))
    if risk_score >= dynamic_malicious:
        return "malicious"
    if risk_score >= settings.SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "benign"


def compute_confidence(previous_confidence: float, risk_score: float, frequency: int, last_seen: datetime | None) -> float:
    now = datetime.now(timezone.utc)
    recency_bonus = 0.0
    if last_seen is not None:
        delta_hours = (now - last_seen.replace(tzinfo=timezone.utc)).total_seconds() / 3600.0
        recency_bonus = max(0.0, 10.0 - min(10.0, delta_hours / 12.0))

    frequency_bonus = min(15.0, frequency * 0.5)
    blended = (risk_score * 0.65) + (previous_confidence * 0.2) + frequency_bonus + recency_bonus
    return round(max(0.0, min(100.0, blended)), 2)
