from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from typing import Optional, Dict, Any

from inference.predictor import predict
from src.website_feature_extraction import FeatureExtractor

app = FastAPI(title="PhishGuard AI", version="2.0")

BASE_DIR = Path(__file__).resolve().parents[1]
templates = Jinja2Templates(directory=str(BASE_DIR / "api" / "templates"))

extractor = FeatureExtractor()

FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

UI_TO_MODEL_MAP = {
    "yes": 1,
    "no": 0,
    "unknown": -1,
    "1": 1,
    "0": 0,
    "-1": -1,
    1: 1,
    0: 0,
    -1: -1
}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    default_values = {f: "unknown" for f in FEATURES}
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "features": FEATURES,
            "values": default_values,
            "result": None,
            "url": "",
            "model_type": "xgboost",
        },
    )


@app.post("/extract_features", response_class=JSONResponse)
async def extract_features_api(payload: dict):
    url = payload.get("url", "").strip()
    if not url:
        return JSONResponse({"error": "URL is required"}, status_code=400)
    try:
        features = extractor.extract(url)
        ui_features = {}
        for k, v in features.items():
            if v == 1:
                ui_features[k] = "yes"
            elif v == 0:
                ui_features[k] = "no"
            else:
                ui_features[k] = "unknown"
        return JSONResponse({"features": ui_features, "raw": features})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/predict", response_class=HTMLResponse)
async def predict_ui(
    request: Request,
    url: Optional[str] = Form(""),
    model_type: str = Form("xgboost"),
):
    form = await request.form()
    url = (url or "").strip()

    # Build feature dict
    input_data = {}
    
    if url:
        try:
            input_data = extractor.extract(url)
        except Exception:
            input_data = {f: -1 for f in FEATURES}
    else:
        input_data = {f: -1 for f in FEATURES}

    # Override/fill from manual form inputs if provided (Mode 1 - Tabular ML)
    values_dict = {}
    for feature in FEATURES:
        raw_val = form.get(feature)
        if raw_val is not None:
            raw_str = str(raw_val).lower().strip()
            values_dict[feature] = raw_str
            if raw_str in UI_TO_MODEL_MAP:
                input_data[feature] = UI_TO_MODEL_MAP[raw_str]
        else:
            curr_val = input_data.get(feature, -1)
            values_dict[feature] = "yes" if curr_val == 1 else ("no" if curr_val == 0 else "unknown")

    try:
        result = predict(
            input_dict=input_data,
            model_type=model_type,
            url=url if url else "http://custom-tabular-features.input"
        )

        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "features": FEATURES,
                "values": values_dict,
                "result": result,
                "url": url,
                "model_type": model_type,
            },
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "features": FEATURES,
                "values": values_dict,
                "result": {
                    "model": model_type,
                    "prediction": 0,
                    "result_text": f"Error: {str(e)}",
                    "phishing_probability": None,
                },
                "url": url,
                "model_type": model_type,
            },
        )
