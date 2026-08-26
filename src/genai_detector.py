"""
Google Gemini GenAI Phishing Detection Module
Provides semantic lexical reasoning, threat categorization, brand spoofing detection,
and structured explainability.
"""

import os
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

try:
    from google import genai
    from google.genai import types
    from google.genai.errors import APIError
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


class GeminiPhishingAnalysis(BaseModel):
    verdict: str = Field(description="'Legitimate' or 'Phishing'")
    prediction: int = Field(description="1 for Legitimate, 0 for Phishing")
    phishing_probability: float = Field(description="Estimated risk probability from 0.0 (safe) to 1.0 (dangerous)")
    brand_impersonated: Optional[str] = Field(default=None, description="Brand being spoofed/impersonated, or 'None'")
    threat_category: str = Field(description="Category e.g. Credential Harvesting, Brand Spoofing, Typosquatting, Benign Website")
    summary: str = Field(description="1-2 sentence concise executive explanation of the analysis")
    red_flags: List[str] = Field(default_factory=list, description="Key suspicious indicators or safety findings")
    security_tips: List[str] = Field(default_factory=list, description="Actionable safety guidance for the user")


class GeminiPhishingDetector:
    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
        self.api_key = os.getenv("GEMINI_API_KEY")

    def _get_client(self) -> Optional[Any]:
        if not self.api_key:
            self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            return None
        return genai.Client(api_key=self.api_key)

    def analyze(
        self,
        url: str,
        features: Optional[Dict[str, Any]] = None,
        page_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a target URL using Google Gemini GenAI with automatic model fallback.
        """
        client = self._get_client()

        if not client:
            return {
                "model": "gemini (API key required)",
                "prediction": 0,
                "result_text": "Gemini API Key Missing",
                "phishing_probability": None,
                "brand_impersonated": "Unknown",
                "threat_category": "Configuration Required",
                "summary": "Please set your GEMINI_API_KEY in a .env file or environment variable to enable GenAI Deep Reasoning.",
                "red_flags": [
                    "GEMINI_API_KEY environment variable is not configured.",
                    "Obtain a free API key at https://aistudio.google.com/"
                ],
                "security_tips": [
                    "Add GEMINI_API_KEY=your_key_here to .env in your project root."
                ]
            }

        features_str = ""
        if features:
            active_signals = {k: v for k, v in features.items() if v in [1, 0]}
            features_str = json.dumps(active_signals, indent=2)

        context_str = ""
        if page_context:
            context_str = json.dumps(page_context, indent=2)

        prompt = f"""You are an elite Cybersecurity Intelligence and Phishing Threat Analyst.
Evaluate the following target website URL and extracted technical indicators to determine if it is a PHISHING or LEGITIMATE website.

TARGET URL:
{url}

EXTRACTED HEURISTIC SIGNALS:
{features_str or 'No pre-computed tabular signals available.'}

PAGE CONTEXT:
{context_str or 'No raw DOM context available.'}

Perform a rigorous evaluation:
1. Examine lexical anomalies (lookalike domains, typosquatting, deceptive subdomains, @ signs, IP address hostnames, suspicious TLDs).
2. Check for brand impersonation (e.g. attempting to mimic PayPal, Google, Microsoft, Apple, Netflix, banks).
3. Evaluate SSL/TLS, domain age, and form submission flags.
4. Output your analysis adhering strictly to the JSON schema.
"""

        candidate_models = [self.model_name, "gemini-3.6-flash", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
        # Remove duplicates while preserving order
        candidate_models = list(dict.fromkeys(candidate_models))

        last_error = None
        for model in candidate_models:
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=GeminiPhishingAnalysis,
                        temperature=0.1,
                    ),
                )

                data = json.loads(response.text)
                
                is_legit = data.get("prediction") == 1 or data.get("verdict", "").lower() == "legitimate"
                pred_code = 1 if is_legit else 0
                
                return {
                    "model": model,
                    "prediction": pred_code,
                    "result_text": "Legitimate Website" if pred_code == 1 else "Phishing Website Detected",
                    "phishing_probability": float(data.get("phishing_probability", 0.0 if pred_code == 1 else 0.95)),
                    "brand_impersonated": data.get("brand_impersonated") or "None",
                    "threat_category": data.get("threat_category", "Standard Analysis"),
                    "summary": data.get("summary", ""),
                    "red_flags": data.get("red_flags", []),
                    "security_tips": data.get("security_tips", [])
                }

            except Exception as e:
                last_error = str(e)
                # If model not found or deprecated, try next candidate
                if "NOT_FOUND" in last_error or "404" in last_error or "not available" in last_error:
                    continue
                else:
                    break

        return {
            "model": self.model_name,
            "prediction": 0,
            "result_text": f"GenAI Analysis Error: {last_error}",
            "phishing_probability": None,
            "brand_impersonated": "Unknown",
            "threat_category": "API Request Error",
            "summary": f"Failed to complete GenAI analysis: {last_error}",
            "red_flags": [str(last_error)],
            "security_tips": ["Verify your GEMINI_API_KEY quota and model access at https://aistudio.google.com/"]
        }
