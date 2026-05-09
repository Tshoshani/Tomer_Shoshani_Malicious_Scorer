"""Unit tests for the Scorer orchestrator."""

import pytest
from app.analyzers.base_analyzer_definitions import AnalysisResult, BaseAnalyzer
from app.schemas import EmailAnalysisRequest
from app.scoring.scorer import Scorer


class FakeAnalyzer(BaseAnalyzer):
    def __init__(self, name, score, max_score, skipped=False):
        self.name = name
        self._score = score
        self._max = max_score
        self._skipped = skipped

    async def analyze(self, email):
        return AnalysisResult(
            analyzer_name=self.name, score=self._score,
            max_score=self._max, skipped=self._skipped,
        )


def _email():
    return EmailAnalysisRequest(subject="T", sender_email="a@b.com", body="x")


class TestScorer:
    @pytest.mark.asyncio
    async def test_safe_verdict(self):
        scorer = Scorer(analyzers=[FakeAnalyzer("authentication", 0, 100)])
        r = await scorer.score(_email())
        assert r.verdict == "Safe" and r.score == 0

    @pytest.mark.asyncio
    async def test_malicious_verdict(self):
        scorer = Scorer(analyzers=[FakeAnalyzer("authentication", 100, 100)])
        r = await scorer.score(_email())
        assert r.verdict == "Malicious" and r.score == 100

    @pytest.mark.asyncio
    async def test_skipped_analyzers_not_counted(self):
        scorer = Scorer(analyzers=[
            FakeAnalyzer("authentication", 100, 100),
            FakeAnalyzer("ai_content", 0, 80, skipped=True),
        ])
        r = await scorer.score(_email())
        assert r.score == 100  # skipped analyzer doesn't dilute

    @pytest.mark.asyncio
    async def test_weighted_average(self):
        # auth weight=100, intent weight=75
        scorer = Scorer(analyzers=[
            FakeAnalyzer("authentication", 100, 100),
            FakeAnalyzer("intent", 0, 75),
        ])
        r = await scorer.score(_email())
        # (100*100 + 0*75) / 175 ≈ 57
        assert r.score == 57
