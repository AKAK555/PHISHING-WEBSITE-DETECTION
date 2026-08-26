import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional
from src.config_loader import load_config
from src.website_feature_extraction import FeatureExtractor

# =========================================================
# PATHS + LOAD ARTIFACTS (config-driven)
# =========================================================

CONFIG = load_config()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = PROJECT_ROOT / CONFIG["artifacts"]["directory"]
SCALER_PATH = ARTIFACTS_DIR / CONFIG["artifacts"]["scaler_filename"]
XGB_MODEL_PATH = ARTIFACTS_DIR / CONFIG["artifacts"]["xgb_model_filename"]
ANN_MODEL_PATH = ARTIFACTS_DIR / CONFIG["artifacts"]["ann_model_filename"]

def _safe_load(path: Path):
    if not path.exists():
        raise FileNotFoundError(
            f"Artifact not found: {path}\n"
            f"Fix: Run training pipeline first so artifacts get created."
        )
    return joblib.load(path)

SCALER = _safe_load(SCALER_PATH)
XGB_MODEL = _safe_load(XGB_MODEL_PATH)
ANN_MODEL = _safe_load(ANN_MODEL_PATH)

# =========================================================
# HELPERS
# =========================================================

def decode_label(pred: int) -> str:
    return "Legit Website" if int(pred) == 1 else "Phishing Website"

def _get_expected_columns_from_scaler() -> Optional[list]:
    """
    Try best to recover expected feature columns.
    Best case: scaler was fit on a DataFrame and retains feature names.
    Otherwise returns None.
    """
    if hasattr(SCALER, "feature_names_in_"):
        return list(SCALER.feature_names_in_)
    return None

EXPECTED_COLUMNS = _get_expected_columns_from_scaler()

def validate_and_build_df(input_dict: Dict[str, Any]) -> pd.DataFrame:
    """
    Convert dict -> DataFrame and ensure it matches training feature columns.

    - If scaler has feature_names_in_: reorder & validate strictly
    - Else: just create DataFrame from dict (assumes correct order/keys provided)
    """
    if not isinstance(input_dict, dict):
        raise TypeError("input_dict must be a Python dict of feature_name -> value.")

    df = pd.DataFrame([input_dict])

    if EXPECTED_COLUMNS is not None:
        missing = [c for c in EXPECTED_COLUMNS if c not in df.columns]
        extra = [c for c in df.columns if c not in EXPECTED_COLUMNS]

        if missing:
            raise ValueError(
                f"Missing required features: {missing}\n"
                f"Expected columns (total {len(EXPECTED_COLUMNS)}): {EXPECTED_COLUMNS}"
            )

        # We allow extra columns but drop them to be safe
        if extra:
            df = df.drop(columns=extra)

        # Reorder exactly as training
        df = df[EXPECTED_COLUMNS]

    return df

def preprocess_input(input_dict: Dict[str, Any]) -> np.ndarray:
    """
    input_dict -> DataFrame -> scaled numpy array
    """
    df = validate_and_build_df(input_dict)
    X_scaled = SCALER.transform(df)
    return X_scaled


from src.genai_detector import GeminiPhishingDetector

GEMINI_DETECTOR = GeminiPhishingDetector()


def predict(
    input_dict: Dict[str, Any],
    model_type: str = "xgboost",
    url: Optional[str] = None,
    page_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Predict phishing vs legit using XGBoost, ANN, Gemini GenAI, or Hybrid Ensemble.

    model_type: "xgboost" | "ann" | "gemini" | "ensemble"
    returns: dict with prediction + label + risk probability + GenAI explainability
    """
    model_key = model_type.lower()

    # 1. GenAI Direct Scan
    if model_key in ["gemini", "genai", "llm"]:
        target_url = url or "http://unknown-target-domain.com"
        return GEMINI_DETECTOR.analyze(url=target_url, features=input_dict, page_context=page_context)

    # 2. Tabular ML Prediction (XGBoost / ANN)
    X_scaled = preprocess_input(input_dict)

    if model_key == "xgboost":
        model = XGB_MODEL
        active_name = "xgboost"
    elif model_key in ["ann", "mlp", "mlpclassifier"]:
        model = ANN_MODEL
        active_name = "ann"
    elif model_key == "ensemble":
        # Hybrid Tri-Engine: XGBoost + ANN + Gemini
        xgb_proba = float(XGB_MODEL.predict_proba(X_scaled)[0][0])
        ann_proba = float(ANN_MODEL.predict_proba(X_scaled)[0][0])

        target_url = url or "http://unknown-target-domain.com"
        gemini_result = GEMINI_DETECTOR.analyze(url=target_url, features=input_dict, page_context=page_context)
        
        gemini_prob = gemini_result.get("phishing_probability")
        if gemini_prob is not None:
            # Weighted Ensemble: 40% XGBoost, 20% ANN, 40% Gemini Reasoner
            ensemble_phishing_prob = (0.40 * xgb_proba) + (0.20 * ann_proba) + (0.40 * gemini_prob)
        else:
            # Fallback if Gemini key is missing
            ensemble_phishing_prob = (0.65 * xgb_proba) + (0.35 * ann_proba)

        ensemble_pred = 0 if ensemble_phishing_prob >= 0.5 else 1

        return {
            "model": "ensemble (XGBoost + ANN + Gemini)",
            "prediction": ensemble_pred,
            "result_text": decode_label(ensemble_pred),
            "phishing_probability": ensemble_phishing_prob,
            "legit_probability": 1.0 - ensemble_phishing_prob,
            "brand_impersonated": gemini_result.get("brand_impersonated", "None"),
            "threat_category": gemini_result.get("threat_category", "Multi-Model Consensus"),
            "summary": gemini_result.get("summary", f"Tri-Engine Consensus: XGBoost={xgb_proba:.1%}, ANN={ann_proba:.1%}, GenAI={gemini_prob or 0.0:.1%}"),
            "red_flags": gemini_result.get("red_flags", []),
            "security_tips": gemini_result.get("security_tips", []),
            "sub_model_scores": {
                "xgboost": round(xgb_proba, 3),
                "ann": round(ann_proba, 3),
                "gemini": round(gemini_prob, 3) if gemini_prob is not None else "N/A"
            }
        }
    else:
        raise ValueError("model_type must be 'xgboost', 'ann', 'gemini', or 'ensemble'.")

    pred = int(model.predict(X_scaled)[0])

    phishing_prob = None
    legit_prob = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_scaled)[0]
        phishing_prob = float(proba[0])
        legit_prob = float(proba[1])

    return {
        "model": active_name,
        "prediction": pred,
        "result_text": decode_label(pred),
        "phishing_probability": phishing_prob,
        "legit_probability": legit_prob,
        "threat_category": "Tabular Heuristic Classification",
        "summary": f"Classified by {active_name.upper()} based on 30 engineered URL/host vectors."
    }

# =========================================================
# CLI DEMO
# =========================================================

if __name__ == "__main__":
    # NOTE:
    # Use same feature names as training CSV (excluding target column).
    # Values should be numeric (mostly -1/0/1 for this dataset).

    # sample_input = {
    #     "having_IP_Address": 0,
    #     "URL_Length": 1,
    #     "Shortining_Service": 0,
    #     "having_At_Symbol": 0,
    #     "double_slash_redirecting": 1,
    #     "Prefix_Suffix": 0,
    #     "having_Sub_Domain": 1,
    #     "SSLfinal_State": 1,
    #     "Domain_registeration_length": 1,
    #     "Favicon": 1,
    #     "port": 0,
    #     "HTTPS_token": 0,
    #     "Request_URL": 1,
    #     "URL_of_Anchor": 1,
    #     "Links_in_tags": 1,
    #     "SFH": 1,
    #     "Submitting_to_email": 0,
    #     "Abnormal_URL": 0,
    #     "Redirect": 1,
    #     "on_mouseover": 0,
    #     "RightClick": 1,
    #     "popUpWidnow": 0,
    #     "Iframe": 0,
    #     "age_of_domain": 1,
    #     "DNSRecord": 1,
    #     "web_traffic": 1,
    #     "Page_Rank": 1,
    #     "Google_Index": 1,
    #     "Links_pointing_to_page": 1,
    #     "Statistical_report": 0
    # }
    

    extractor = FeatureExtractor()
    #url = "https://secure-paypal-login-verification.xyz/login"
    #url = "http://google.com.secure-login.verify-account.example.com/"
    url = "http://google.com/"
    features = extractor.extract(url)
    # print("\nExtracted Features:")
    # for k, v in features.items():
    #     print(f"  {k}: {v}")

    print("\n--- XGBoost Prediction ---")
    print(predict(features, model_type="xgboost"))

    print("\n--- ANN (MLPClassifier) Prediction ---")
    print(predict(features, model_type="ann"))