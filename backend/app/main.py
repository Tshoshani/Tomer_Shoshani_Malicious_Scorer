"""
Entry point — exposes POST /analyze for the Gmail Add-on.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.analyzers.ai_content import AiContentAnalyzer
from app.analyzers.attachment import AttachmentAnalyzer
from app.analyzers.authentication import AuthenticationAnalyzer
from app.analyzers.domain_reputation import DomainReputationAnalyzer
from app.analyzers.intent import IntentAnalyzer
from app.analyzers.url_analysis import UrlAnalyzer
from app.schemas import AnalysisResponse, EmailAnalysisRequest
from app.scoring.scorer import Scorer
from app.services.http_client import close_http_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Close the shared HTTP connection pool when the server shuts down."""
    yield
    await close_http_client()


# Create the FastAPI application instance
# lifespan= tells FastAPI to use our startup/shutdown handler above
app = FastAPI(title="Malicious Email Scorer", lifespan=lifespan)

# Six analyzers — each checks a different attack vector, all run in parallel
scorer = Scorer(analyzers=[
    AuthenticationAnalyzer(),   # SPF / DKIM / DMARC headers
    DomainReputationAnalyzer(), # VirusTotal flags + domain age
    IntentAnalyzer(),           # Phishing keyword detection
    UrlAnalyzer(),              # Brand impersonation in links
    AiContentAnalyzer(),        # Gemini LLM semantic analysis
    AttachmentAnalyzer(),       # File extension risk + VT hash lookup
])


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Receive email metadata from the Gmail Add-on, run all analyzers,
    and return a scored verdict (Safe / Suspicious / Malicious).
    """
    return await scorer.score(request)
