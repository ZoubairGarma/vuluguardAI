"""
Tests for the trained VulnGuard ML Risk Model (joblib).
Verifies model loading, pipeline inference, and probability calibration.
"""

from pathlib import Path
import joblib
import pandas as pd
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "data" / "models" / "risk_model.joblib"
METADATA_PATH = PROJECT_ROOT / "data" / "models" / "model_metadata.json"
X_PATH = PROJECT_ROOT / "data" / "processed" / "ml" / "X_features.csv"
Y_PATH = PROJECT_ROOT / "data" / "processed" / "ml" / "y_kev.csv"


def test_model_and_metadata_files_exist():
    """Ensure the serialized model artifact and its metadata are present."""
    assert MODEL_PATH.exists(), f"Model file missing at {MODEL_PATH}"
    assert METADATA_PATH.exists(), f"Metadata file missing at {METADATA_PATH}"


def test_model_loads_and_has_expected_classes():
    """Verify that the model pipeline loads cleanly and outputs binary classes [0, 1]."""
    model = joblib.load(MODEL_PATH)
    assert hasattr(model, "predict"), "Loaded object has no predict method"
    assert hasattr(model, "predict_proba"), "Loaded object has no predict_proba method"
    assert list(model.classes_) == [0, 1], f"Unexpected classes: {model.classes_}"


def test_model_inference_on_sample_data():
    """Test model prediction and probability estimation on real feature rows."""
    if not X_PATH.exists() or not Y_PATH.exists():
        pytest.skip("ML feature datasets not present on disk.")

    model = joblib.load(MODEL_PATH)
    X = pd.read_csv(X_PATH)
    y = pd.read_csv(Y_PATH)["is_kev"]

    sample_X = X.iloc[:5]
    preds = model.predict(sample_X)
    probs = model.predict_proba(sample_X)

    assert len(preds) == 5
    assert probs.shape == (5, 2)
    # Probabilities must sum to 1.0 for each row
    for row in probs:
        assert round(float(sum(row)), 4) == 1.0

    # Ensure high risk probability is assigned to known KEV CVEs
    pos_indices = y[y == 1].index
    if len(pos_indices) > 0:
        kev_sample = X.iloc[[pos_indices[0]]]
        kev_prob = model.predict_proba(kev_sample)[0, 1]
        assert kev_prob > 0.5, f"Expected KEV probability > 0.5, got {kev_prob}"

