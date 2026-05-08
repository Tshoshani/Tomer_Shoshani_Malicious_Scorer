from app.analyzers.base import AnalysisResult, BaseAnalyzer
from app.schemas import EmailAnalysisRequest


PHISHING_CATEGORIES = {
    "Urgency/Pressure": [
        "urgent", "immediate action required", "act now", "expires today",
        "limited time", "final notice", "last warning", "account will be closed",
        "response needed immediately", "within 24 hours",
    ],
    "Security/Fear": [
        "security alert", "unauthorized login", "suspicious activity",
        "account compromised", "verify your identity", "confirm your account",
        "reset your password", "fraud detected", "we detected unusual activity",
    ],
    "Financial": [
        "payment failed", "invoice attached", "you have been charged",
        "refund available", "claim your refund", "billing issue",
        "update your payment", "tax refund", "unpaid balance",
    ],
    "Rewards/Bait": [
        "you won", "congratulations", "free gift", "claim your prize",
        "exclusive offer", "selected winner", "lottery", "reward waiting",
    ],
    "Authority": [
        "bank notice", "official notice", "government alert", "admin request",
        "it department", "support team", "customer service", "your account manager",
    ],
    "Action Triggers": [
        "click here", "login now", "verify now", "update now",
        "open attachment", "download now", "access your account", "secure your account",
    ],
    "High-Risk Combos": [
        "urgent action required", "account suspended immediately",
        "verify your account now", "unauthorized login attempt",
        "click here to secure your account",
    ],
}

CATEGORY_WEIGHTS = {
    "High-Risk Combos": 30,
    "Urgency/Pressure": 30,
}
DEFAULT_CATEGORY_WEIGHT = 15


class IntentAnalyzer(BaseAnalyzer):
    """Detects phishing intent through keyword/phrase pattern matching."""

    name = "intent"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=75)
        content = (email.subject + " " + email.body).lower()

        for category, phrases in PHISHING_CATEGORIES.items():
            found = [p for p in phrases if p in content]
            if found:
                weight = CATEGORY_WEIGHTS.get(category, DEFAULT_CATEGORY_WEIGHT)
                result.score += weight
                result.findings.append(f"Content flags: Detected {category}")

        result.score = min(result.score, result.max_score)
        return result
