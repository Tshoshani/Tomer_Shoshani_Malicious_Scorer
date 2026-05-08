import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import APIKeyHeader

from app.analyzers.ai_content import AiContentAnalyzer
from app.analyzers.attachment import AttachmentAnalyzer
from app.analyzers.authentication import AuthenticationAnalyzer
from app.analyzers.domain_reputation import DomainReputationAnalyzer
from app.analyzers.intent import IntentAnalyzer
from app.analyzers.url_analysis import UrlAnalyzer
from app.config import settings
from app.schemas import AnalysisResponse, EmailAnalysisRequest
from app.scoring.scorer import Scorer
from app.services.http_client import close_http_client


# --- Lifespan: cleanup resources on shutdown ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_http_client()


app = FastAPI(title="Malicious Email Scorer", lifespan=lifespan)


# --- API Key Authentication ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str | None = Depends(api_key_header)):
    """Require X-API-Key header if API_SECRET_KEY is configured."""
    if not settings.api_secret_key:
        return  # No secret configured → open access (dev mode)
    if api_key != settings.api_secret_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# --- In-memory rate limiting ---
_request_log: dict[str, list[float]] = defaultdict(list)


async def rate_limit(request: Request):
    """Simple sliding-window rate limiter per client IP."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = settings.rate_limit_window_seconds

    # Remove expired entries
    _request_log[client_ip] = [
        t for t in _request_log[client_ip] if now - t < window
    ]

    if len(_request_log[client_ip]) >= settings.rate_limit_requests:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {settings.rate_limit_requests} requests per {window}s.",
        )

    _request_log[client_ip].append(now)


# --- Scorer setup ---
scorer = Scorer(analyzers=[
    AuthenticationAnalyzer(),
    DomainReputationAnalyzer(),
    IntentAnalyzer(),
    UrlAnalyzer(),
    AiContentAnalyzer(),
    AttachmentAnalyzer(),
])


# --- Endpoint ---
@app.post(
    "/analyze",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_api_key), Depends(rate_limit)],
)
async def analyze_email(request: EmailAnalysisRequest):
    return await scorer.score(request)
