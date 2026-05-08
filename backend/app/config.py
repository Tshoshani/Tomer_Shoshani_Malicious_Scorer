from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8")

    # API Keys
    vt_api_key: Optional[str] = None
    whois_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None

    # Backend authentication (shared secret with Gmail Add-on)
    api_secret_key: Optional[str] = None

    # Rate limiting
    rate_limit_requests: int = 10
    rate_limit_window_seconds: int = 60

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


settings = Settings()
