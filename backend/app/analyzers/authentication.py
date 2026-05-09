"""
Checks email authentication headers (SPF, DKIM, DMARC).
These protocols verify whether the sender is who they claim to be.
A failed DMARC is the strongest phishing signal here because it means
the domain owner explicitly said this sender is unauthorized.
"""

from app.analyzers.base_analyzer_definitions import AnalysisResult, BaseAnalyzer
from app.schemas import EmailAnalysisRequest


class AuthenticationAnalyzer(BaseAnalyzer):
    """Analyzes SPF, DKIM, and DMARC results from email headers."""

    name = "authentication"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=100)
        headers = email.headers or {}

        # The Authentication-Results header is added by the receiving mail server
        auth_results = headers.get("Authentication-Results", "").lower()

        # If no authentication headers exist at all, the email's identity is unverifiable
        if not auth_results:
            result.score = 20
            result.findings.append(
                "No authentication headers found. Identity could not be verified."
            )
            return result

        # DMARC (Domain-based Message Authentication, Reporting & Conformance))— most critical check (combines SPF + DKIM policy)
        # A DMARC fail (+50) means the domain owner says this sender is not authorized
        if "dmarc=pass" in auth_results:
            pass  # Good — no penalty
        elif "dmarc=fail" in auth_results:
            result.score += 50
            result.findings.append("Critical: DMARC authentication failed.")
        else:
            result.score += 10
            result.findings.append(
                "Warning: DMARC record is missing, neutral, or could not be verified."
            )

        # SPF (Sender Policy Framework)— checks if the sending server's IP is authorized by the domain
        if "spf=fail" in auth_results:
            result.score += 30
            result.findings.append(
                "SPF failed: The sending server is not authorized by the domain."
            )
        elif "spf=softfail" in auth_results:
            result.score += 15
            result.findings.append(
                "SPF soft-fail: The sending server is suspicious."
            )

        # DKIM (DomainKeys Identified Mail)— checks if the email content was tampered with in transit
        if "dkim=fail" in auth_results:
            result.score += 20
            result.findings.append(
                "DKIM failed: The email signature is invalid or was tampered with."
            )

        result.score = min(result.score, result.max_score)
        return result
