from pydantic import BaseModel, Field
from typing import List, Optional


class AttachmentInfo(BaseModel):
    filename: str
    mime_type: str
    sha256: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int


class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., max_length=1000)
    sender_email: str
    body: str = Field(..., max_length=100_000)
    headers: Optional[dict] = None
    attachments: Optional[List[AttachmentInfo]] = None


class AnalyzerDetail(BaseModel):
    analyzer: str
    score: int
    max_score: int
    findings: List[str]
    skipped: bool = False


class AnalysisResponse(BaseModel):
    score: int
    verdict: str
    summary: str
    details: List[AnalyzerDetail]
