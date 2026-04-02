import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import structlog

# Setup logger
structlog.configure(processors=[structlog.stdlib.add_log_level, structlog.processors.JSONRenderer()])
logger = structlog.get_logger()

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "saved_models")
MODEL_PATH = os.path.join(MODEL_DIR, "rf_malware_model.pkl")

def generate_synthetic_dataset(num_samples=2000):
    """
    Simulates a dataset of benign and malicious PE/ELF flies based on static features.
    Malware generally has: Higher entropy (packed), fewer normal strings, abnormal import counts.
    """
    logger.info("generating_synthetic_dataset", samples=num_samples)
    np.random.seed(42)
    
    # Half benign, half malicious
    labels = np.array([0] * (num_samples // 2) + [1] * (num_samples // 2))
    
    # Benign features (label 0)
    b_entropy = np.random.normal(loc=4.5, scale=1.0, size=(num_samples // 2))
    b_imports = np.random.normal(loc=80, scale=30, size=(num_samples // 2))
    b_strings = np.random.normal(loc=500, scale=150, size=(num_samples // 2))
    
    # Malicious features (label 1 - often packed meaning high entropy, low visible strings)
    m_entropy = np.random.normal(loc=7.5, scale=0.5, size=(num_samples // 2))
    m_imports = np.random.normal(loc=15, scale=10, size=(num_samples // 2))
    m_strings = np.random.normal(loc=50, scale=30, size=(num_samples // 2))
    
    # Combine and clip to realistic boundaries
    entropy = np.clip(np.concatenate([b_entropy, m_entropy]), 0.0, 8.0)
    imports = np.clip(np.concatenate([b_imports, m_imports]), 0, 500).astype(int)
    strings = np.clip(np.concatenate([b_strings, m_strings]), 0, 5000).astype(int)
    
    df = pd.DataFrame({
        'entropy': entropy,
        'imports_count': imports,
        'strings_count': strings,
        'is_malicious': labels
    })
    
    # Shuffle dataset
    return df.sample(frac=1).reset_index(drop=True)

def train_model():
    df = generate_synthetic_dataset()
    
    X = df[['entropy', 'imports_count', 'strings_count']]
    y = df['is_malicious']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    logger.info("training_model", algorithm="RandomForestClassifier")
    # Using RandomForest instead of XGBoost here for portability and ease of setup, performance on tabular data remains top-tier
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    logger.info("model_evaluation", accuracy=float(accuracy), report=classification_report(y_test, y_pred, output_dict=True))
    
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    logger.info("model_saved", path=MODEL_PATH)

if __name__ == "__main__":
    train_model()
