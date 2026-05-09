"""
Uses Google Gemini (LLM) to analyze email content for sophisticated
phishing signals that keyword matching can't catch — e.g. novel phrasing,
contextual manipulation, or social engineering tactics.

The LLM is asked to return structured JSON with a risk score and flags.
Its response is validated (must be int 0-100) to prevent hallucinated
scores from corrupting the final verdict.

This analyzer runs alongside deterministic checks, not instead of them.
If the Gemini API is unavailable, the system still works with the other 5.
"""

import json

from google.genai import Client
from google.genai.errors import ClientError
from app.analyzers.base_analyzer_definitions import AnalysisResult, BaseAnalyzer
from app.config import settings
from app.schemas import EmailAnalysisRequest

# System prompt instructs the LLM to act as a security analyst and respond
# with structured JSON only — no tool calls, no code execution.
# This separation of system/user prompts helps mitigate prompt injection.
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

        # Skip if no API key — mark as skipped so it doesn't dilute the score
        if not settings.gemini_api_key:
            result.skipped = True
            result.findings.append("AI analysis skipped: No Gemini API key configured.")
            return result

        try:
            client = Client(api_key=settings.gemini_api_key)

            # Truncate body to avoid excessive token usage / cost
            body_truncated = email.body[:3000] if len(email.body) > 3000 else email.body

            user_message = (
                f"Subject: {email.subject}\n"
                f"From: {email.sender_email}\n"
                f"Body:\n{body_truncated}"
            )

            prompt = f"{SYSTEM_PROMPT}\n\nEmail to analyze:\n{user_message}"

            # Async call to avoid blocking the event loop while waiting for LLM
            response = await client.aio.models.generate_content(
                model="models/gemini-2.0-flash",
                contents=prompt
            )

            content = response.text.strip() if hasattr(response, 'text') else str(response).strip()
            parsed = self._parse_response(content)

            if parsed:
                # Clamp LLM score to our max to prevent it from dominating
                result.score = min(parsed["risk_score"], result.max_score)
                if parsed.get("flags"):
                    for flag in parsed["flags"]:
                        result.findings.append(f"AI Flag: {flag}")
                if parsed.get("explanation"):
                    result.findings.append(f"AI Assessment: {parsed['explanation']}")
            else:
                result.findings.append("AI analysis: Could not parse LLM response.")

        except ClientError as e:
            if hasattr(e, 'code') and e.code == 429:
                result.findings.append("AI analysis skipped: Free trial quota exceeded.")
            else:
                result.findings.append(f"AI analysis skipped: {type(e).__name__}")
            result.skipped = True

        except Exception as e:
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
