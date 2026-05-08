# FastAPI turns our Python code into a web server that can receive HTTP requests
from fastapi import FastAPI

# Import all 6 analyzers — each one checks a different aspect of the email
from app.analyzers.ai_content import AiContentAnalyzer
from app.analyzers.attachment import AttachmentAnalyzer
from app.analyzers.authentication import AuthenticationAnalyzer
from app.analyzers.domain_reputation import DomainReputationAnalyzer
from app.analyzers.intent import IntentAnalyzer
from app.analyzers.url_analysis import UrlAnalyzer

# Schemas define the expected shape of input (request) and output (response)
from app.schemas import AnalysisResponse, EmailAnalysisRequest

# The Scorer orchestrates all analyzers and combines their results
from app.scoring.scorer import Scorer

# Create the web server
app = FastAPI(title="Malicious Email Scorer")

# Create the scorer with all analyzers registered
scorer = Scorer(analyzers=[
    AuthenticationAnalyzer(),
    DomainReputationAnalyzer(),
    IntentAnalyzer(),
    UrlAnalyzer(),
    AiContentAnalyzer(),
    AttachmentAnalyzer(),
])


# POST /analyze — the single endpoint that the Gmail Add-on calls
# FastAPI automatically validates the incoming JSON against EmailAnalysisRequest
@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    return await scorer.score(request)
