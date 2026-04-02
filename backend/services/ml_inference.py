import os
import joblib
import structlog
import pandas as pd
from typing import Dict

from core.config import settings
from services.reputation import classify_risk

logger = structlog.get_logger()

# Pathing to saved model
MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../models/saved_models/rf_malware_model.pkl"))

# Global model instance for worker memory caching
_model = None

def get_model():
    """Lazily load the model into memory."""
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            logger.error("model_not_found", path=MODEL_PATH)
            raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}")
        logger.info("loading_ml_model", path=MODEL_PATH)
        _model = joblib.load(MODEL_PATH)
    return _model

def evaluate_risk(features: Dict) -> dict:
    """
    Evaluates static analysis features against the RandomForest model.
    Returns normalized inference output for reputation updates.
    """
    model = get_model()
    
    # Extract matching features required by model layout in models/train.py
    # Fallback to zero if extraction failed
    x_input = pd.DataFrame([{
        'entropy': features.get('entropy', 0.0),
        'imports_count': features.get('imports_count', 0),
        'strings_count': features.get('strings_count', 0)
    }])
    
    # Predict probabilities: [Prob_Benign, Prob_Malicious]
    probabilities = model.predict_proba(x_input)[0]
    prob_malicious = probabilities[1]
    
    # Convert to 0-100 risk score
    risk_score = round(float(prob_malicious * 100), 2)
    classification = classify_risk(risk_score, frequency=1)
    is_malicious = classification == "malicious"
    
    logger.info(
        "ml_inference_complete",
        risk_score=risk_score,
        classification=classification,
        is_malicious=is_malicious,
        entropy=x_input["entropy"].iloc[0],
        suspicious_threshold=settings.SUSPICIOUS_THRESHOLD,
        malicious_threshold=settings.MALICIOUS_THRESHOLD,
    )

    return {
        "risk_score": risk_score,
        "classification": classification,
        "is_malicious": is_malicious,
    }
