import asyncio
from typing import List

from app.analyzers.base import AnalysisResult, BaseAnalyzer
from app.config import settings
from app.schemas import AnalysisResponse, AnalyzerDetail, EmailAnalysisRequest


class Scorer:
    """
    The Scorer is the "manager" — it runs all analyzers and combines their results
    into a single score + verdict.
    """

    def __init__(self, analyzers: List[BaseAnalyzer]):
        # Store the list of analyzers we'll run on each email
        self.analyzers = analyzers

    async def score(self, email: EmailAnalysisRequest) -> AnalysisResponse:
        # Step 1: Run ALL analyzers at the same time (in parallel, not one-by-one)
        # asyncio.gather runs them concurrently — much faster than sequential
        results: List[AnalysisResult] = await asyncio.gather(
            *(analyzer.analyze(email) for analyzer in self.analyzers)
        )

        # Step 2: Compute the weighted average of all analyzer scores
        total_weighted = 0.0  # Sum of (normalized_score * weight)
        total_weight = 0.0    # Sum of weights (for dividing later)

        details: List[AnalyzerDetail] = []  # Per-analyzer breakdown for the response

        for r in results:
            # Skip analyzers that were intentionally skipped (e.g., rate limit, missing API key)
            if r.skipped:
                details.append(
                    AnalyzerDetail(
                        analyzer=r.analyzer_name,
                        score=0,
                        max_score=r.max_score,
                        findings=r.findings,
                        skipped=True,
                    )
                )
                continue  # Don't include in the weighted average

            # Ensure no analyzer exceeds its own max_score
            clamped_score = min(r.score, r.max_score)

            # Normalize to 0-100 scale (e.g., score 45 out of max 90 → 50/100)
            normalized = (clamped_score / r.max_score * 100) if r.max_score > 0 else 0

            # Get this analyzer's importance weight from config
            weight = self._get_weight(r.analyzer_name)

            # Accumulate for weighted average calculation
            total_weighted += normalized * weight
            total_weight += weight

            details.append(
                AnalyzerDetail(
                    analyzer=r.analyzer_name,
                    score=clamped_score,
                    max_score=r.max_score,
                    findings=r.findings,
                    skipped=False,
                )
            )

        # Step 3: Calculate final score (weighted average, 0-100)
        final_score = int(total_weighted / total_weight) if total_weight > 0 else 0

        # Step 4: Convert score to a human-readable verdict
        if final_score >= settings.verdict_malicious_threshold:    # default: 75
            verdict = "Malicious"
        elif final_score >= settings.verdict_suspicious_threshold:  # default: 35
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        # Step 5: Build a one-line summary with the top concerns
        summary = self._build_summary(verdict, final_score, results)

        # Return the complete response to be sent back to the Gmail Add-on
        return AnalysisResponse(
            score=final_score,
            verdict=verdict,
            summary=summary,
            details=details,
        )

    @staticmethod
    def _get_weight(analyzer_name: str) -> float:
        """
        Each analyzer has a different importance weight (configured in .env).
        Authentication matters more than URL pattern matching, for example.
        """
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
        if verdict == "Safe":
            return f"Email appears safe (score: {score}/100). No significant threats detected."

        # Collect most important findings
        critical_findings = []
        for r in results:
            if r.score > 0:
                critical_findings.extend(r.findings[:1])

        if critical_findings:
            top = "; ".join(critical_findings[:3])
            return f"{verdict} (score: {score}/100). Key concerns: {top}"

        return f"{verdict} (score: {score}/100)."
