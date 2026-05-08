import json
import logging

from google.genai import Client
from google.genai.errors import ClientError
from app.analyzers.base import AnalysisResult, BaseAnalyzer
from app.config import settings
from app.schemas import EmailAnalysisRequest

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an email security analyst. Analyze the email below for phishing/malicious indicators.

Evaluate these dimensions:
1. Social engineering tactics (urgency, fear, authority impersonation)
2. Linguistic anomalies (grammar inconsistencies, tone shifts, generic greetings)
3. Logical coherence (does the request make sense for the claimed sender?)
4. Credential/data harvesting intent
5. Known phishing patterns and pretexting techniques

Respond ONLY with valid JSON in this exact format:
{
  "risk_score": <0-100 integer>,
  "flags": ["<short flag 1>", "<short flag 2>"],
  "explanation": "<one-sentence summary of your assessment>"
}

Rules:
- risk_score 0-20: clearly legitimate
- risk_score 21-50: mildly suspicious but likely okay
- risk_score 51-75: suspicious, multiple red flags
- risk_score 76-100: highly likely phishing/malicious
- Be conservative: normal marketing emails should score below 30
- flags array should have 0-5 items, each under 10 words
"""


class AiContentAnalyzer(BaseAnalyzer):
    """Uses Google Gemini to analyze email content for sophisticated phishing signals."""

    name = "ai_content"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=80)

        if not settings.gemini_api_key:
            result.skipped = True
            result.findings.append("AI analysis skipped: No Gemini API key configured.")
            return result

        try:
            # Initialize Gemini client (async)
            client = Client(api_key=settings.gemini_api_key)

            # Truncate body to avoid excessive token usage
            body_truncated = email.body[:3000] if len(email.body) > 3000 else email.body

            user_message = (
                f"Subject: {email.subject}\n"
                f"From: {email.sender_email}\n"
                f"Body:\n{body_truncated}"
            )

            prompt = f"{SYSTEM_PROMPT}\n\nEmail to analyze:\n{user_message}"

            # Call Gemini API asynchronously to avoid blocking the event loop
            response = await client.aio.models.generate_content(
                model="models/gemini-2.0-flash",
                contents=prompt
            )

            content = response.text.strip() if hasattr(response, 'text') else str(response).strip()
            parsed = self._parse_response(content)

            if parsed:
                result.score = min(parsed["risk_score"], result.max_score)
                if parsed.get("flags"):
                    for flag in parsed["flags"]:
                        result.findings.append(f"AI Flag: {flag}")
                if parsed.get("explanation"):
                    result.findings.append(f"AI Assessment: {parsed['explanation']}")
            else:
                result.findings.append("AI analysis: Could not parse LLM response.")

        except ClientError as e:
            # Handle ClientError exceptions (includes 429 rate limit)
            if hasattr(e, 'code') and e.code == 429:
                logger.warning(f"Gemini API rate limit hit (free trial quota exhausted)")
                result.findings.append("AI analysis skipped: Free trial quota exceeded. Please try again later.")
                result.skipped = True
            else:
                logger.warning(f"AI content analysis failed: ClientError: {str(e)[:100]}")
                result.findings.append(f"AI analysis skipped: {e.code if hasattr(e, 'code') else 'Unknown'}")
                result.skipped = True

        except Exception as e:
            logger.warning(f"AI content analysis failed: {type(e).__name__}: {str(e)[:100]}")
            result.findings.append(f"AI analysis skipped: {type(e).__name__}")
            result.skipped = True

        return result

    @staticmethod
    def _parse_response(content: str) -> dict | None:
        """Safely parse and validate LLM JSON response."""
        try:
            # Strip markdown code fences if present
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                content = content.rsplit("```", 1)[0]
            data = json.loads(content)

            # Validate risk_score is an integer in range
            risk_score = data.get("risk_score")
            if not isinstance(risk_score, int):
                return None
            data["risk_score"] = max(0, min(100, risk_score))

            # Validate flags is a list of strings (or absent)
            flags = data.get("flags")
            if flags is not None and not isinstance(flags, list):
                data["flags"] = []

            return data
        except (json.JSONDecodeError, IndexError):
            return None
