"""
The Scorer orchestrates all analyzers and combines their results.
It runs every analyzer in parallel (asyncio.gather), normalizes each
score to 0-100, then computes a weighted average. The weights are
configurable in .env so the user can tune which signals matter most
without changing code.
"""

import asyncio
from typing import List

from app.analyzers.base_analyzer_definitions import AnalysisResult, BaseAnalyzer
from app.config import settings
from app.schemas import AnalysisResponse, AnalyzerDetail, EmailAnalysisRequest


class Scorer:
    """Runs all analyzers in parallel and combines their results into a single score."""

    def __init__(self, analyzers: List[BaseAnalyzer]):
        self.analyzers = analyzers

    async def score(self, email: EmailAnalysisRequest) -> AnalysisResponse:
        # Run all analyzers at the same time (not one after another)
        tasks = [analyzer.analyze(email) for analyzer in self.analyzers]
        results: List[AnalysisResult] = await asyncio.gather(*tasks)

        total_weighted = 0.0  # Accumulates (normalized_score * weight)
        total_weight = 0.0    # Accumulates weights (for dividing later)
        details: List[AnalyzerDetail] = []

        for r in results:
            # Skipped analyzers (missing API key, etc.) are excluded from the average
            # so they don't dilute the score
            if r.skipped:
                details.append(AnalyzerDetail(
                    analyzer=r.analyzer_name, score=0, max_score=r.max_score,
                    findings=r.findings, skipped=True,
                ))
                continue

            # Clamp score to max, then normalize to 0–100 scale
            # e.g. score 45 out of max 90 → 50/100
            clamped = min(r.score, r.max_score)
            normalized = (clamped / r.max_score * 100) if r.max_score > 0 else 0
            weight = self._get_weight(r.analyzer_name)  # From config (.env)

            total_weighted += normalized * weight
            total_weight += weight

            details.append(AnalyzerDetail(
                analyzer=r.analyzer_name, score=clamped, max_score=r.max_score,
                findings=r.findings, skipped=False,
            ))

        # Weighted average: ensures final score reflects relative importance
        # and always stays in 0–100 range (unlike a raw sum)
        final_score = int(total_weighted / total_weight) if total_weight > 0 else 0

        # Convert numeric score to a human-readable verdict
        if final_score >= settings.verdict_malicious_threshold:
            verdict = "Malicious"
        elif final_score >= settings.verdict_suspicious_threshold:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        summary = self._build_summary(verdict, final_score, results)

        return AnalysisResponse(
            score=final_score, verdict=verdict, summary=summary, details=details,
        )

    @staticmethod
    def _get_weight(analyzer_name: str) -> float:
        """Map analyzer name to its configured weight from .env settings."""
        weight_map = {
            "authentication": settings.weight_authentication,
            "domain_reputation": settings.weight_domain_reputation,
            "intent": settings.weight_intent,
            "url_analysis": settings.weight_url,
            "ai_content": settings.weight_ai_content,
            "attachment": settings.weight_attachment,
        }
        return weight_map.get(analyzer_name, 50)

    @staticmethod
    def _build_summary(verdict: str, score: int, results: List[AnalysisResult]) -> str:
        """Generate a one-line summary highlighting the top concerns."""
        if verdict == "Safe":
            return f"Email appears safe (score: {score}/100). No significant threats detected."

        critical = [r.findings[0] for r in results if r.score > 0 and r.findings]
        if critical:
            top = "; ".join(critical[:3])
            return f"{verdict} (score: {score}/100). Key concerns: {top}"

        return f"{verdict} (score: {score}/100)."
