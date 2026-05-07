from pydantic import BaseModel, EmailStr
from typing import List, Optional

class EmailAnalysisRequest(BaseModel):
    subject: str
    sender_email: str  # Validates basic email formatting
    body: str
    # We will pass raw headers later for SPF/DKIM checks
    headers: Optional[dict] = None 

class AnalysisResponse(BaseModel):
    score: int         # 0-100
    verdict: str       # "Safe", "Suspicious", "Malicious"
    reasoning: List[str] # Explainable logic for the user