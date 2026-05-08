from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # API Keys
    vt_api_key: Optional[str] = None
    whois_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None

    # Scoring weights (per analyzer max contribution)
    weight_authentication: int = 100
    weight_domain_reputation: int = 100
    weight_intent: int = 75
    weight_url: int = 45
    weight_ai_content: int = 80
    weight_attachment: int = 90

    # Thresholds
    verdict_malicious_threshold: int = 75
    verdict_suspicious_threshold: int = 35

    # HTTP settings
    http_timeout: float = 15.0

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
