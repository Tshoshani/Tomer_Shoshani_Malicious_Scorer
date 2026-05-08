from app.analyzers.base import AnalysisResult, BaseAnalyzer
from app.schemas import EmailAnalysisRequest


class AuthenticationAnalyzer(BaseAnalyzer):
    """Analyzes SPF, DKIM, and DMARC results from email headers."""

    name = "authentication"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=100)
        headers = email.headers or {}

        auth_results = headers.get("Authentication-Results", "").lower()

        if not auth_results:
            result.score = 20
            result.findings.append(
                "No authentication headers found. Identity could not be verified."
            )
            return result

        # DMARC (most critical)
        if "dmarc=pass" in auth_results:
            pass
        elif "dmarc=fail" in auth_results:
            result.score += 50
            result.findings.append("Critical: DMARC authentication failed.")
        else:
            result.score += 10
            result.findings.append(
                "Warning: DMARC record is missing, neutral, or could not be verified."
            )

        # SPF
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

        # DKIM
        if "dkim=fail" in auth_results:
            result.score += 20
            result.findings.append(
                "DKIM failed: The email signature is invalid or was tampered with."
            )

        # Ensure we never exceed max_score
        result.score = min(result.score, result.max_score)
        return result
