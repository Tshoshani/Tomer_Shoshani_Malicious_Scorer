"""
Centralized configuration — all values are loaded from environment variables
or a .env file. Uses pydantic-settings so every field is validated on startup.
All API keys default to None, meaning the corresponding analyzer will
gracefully skip if the key is not provided.
"""

from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional


class Settings(BaseSettings):
    # Tells pydantic-settings to read from a .env file in the working directory
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # External API keys — all optional; analyzers skip gracefully if missing
    vt_api_key: Optional[str] = None       # VirusTotal (domain + hash checks)
    whois_api_key: Optional[str] = None    # WhoisXMLAPI (fallback domain age)
    gemini_api_key: Optional[str] = None   # Google Gemini (AI content analysis)

    # How much each analyzer influences the final score (higher = more impact).
    # These act as weights in a weighted average, not raw points.
    weight_authentication: int = 100
    weight_domain_reputation: int = 100
    weight_intent: int = 75
    weight_url: int = 45
    weight_ai_content: int = 80
    weight_attachment: int = 90

    # Final score thresholds for converting the 0–100 score to a verdict
    verdict_malicious_threshold: int = 75   # score >= 75 → "Malicious"
    verdict_suspicious_threshold: int = 35  # score >= 35 → "Suspicious"

    # Timeout for all outgoing HTTP requests (VirusTotal, WHOIS, etc.)
    http_timeout: float = 15.0


# Singleton — imported by other modules as `from app.config import settings`
settings = Settings()
