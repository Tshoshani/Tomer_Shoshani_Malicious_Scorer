"""
Pydantic models that define what the API accepts (request) and returns (response).
FastAPI uses these for automatic validation and documentation.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional


class AttachmentInfo(BaseModel):
    """One attachment, identified by its SHA-256 hash (no raw bytes are sent)."""
    filename: str
    mime_type: str
    sha256: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$")  # Must be a valid 64-char hex hash
    size_bytes: int


class EmailAnalysisRequest(BaseModel):
    """The payload the Gmail Add-on sends for each email to analyze."""
    subject: str = Field(..., max_length=1000)         # Capped to prevent abuse
    sender_email: EmailStr                              # Validated email format
    body: str = Field(..., max_length=100_000)          # ~100 KB max
    headers: Optional[dict] = None                      # e.g. Authentication-Results
    attachments: Optional[List[AttachmentInfo]] = None   # SHA-256 hashes only


class AnalyzerDetail(BaseModel):
    """Per-analyzer breakdown included in the response."""
    analyzer: str          # e.g. "authentication", "intent"
    score: int             # Raw score this analyzer assigned
    max_score: int         # Maximum possible score for this analyzer
    findings: List[str]    # Human-readable explanations of what was detected
    skipped: bool = False  # True if analyzer couldn't run (missing API key, etc.)


class AnalysisResponse(BaseModel):
    """The full response returned to the Gmail Add-on."""
    score: int                    # Final weighted score (0–100)
    verdict: str                  # "Safe", "Suspicious", or "Malicious"
    summary: str                  # One-line human-readable summary
    details: List[AnalyzerDetail] # Breakdown per analyzer (transparency)
