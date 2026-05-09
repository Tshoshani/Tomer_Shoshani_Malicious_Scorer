"""
Base class and result container for all analyzers.
Every analyzer implements BaseAnalyzer and returns an AnalysisResult.
This plugin architecture means adding a new analyzer requires only:
  1. Create the new file implementing BaseAnalyzer
  2. Register it in main.py's analyzer list
"""

from abc import ABC, abstractmethod
from app.schemas import EmailAnalysisRequest


class AnalysisResult:
    """What every analyzer returns after examining an email."""
    def __init__(self, analyzer_name, score=0, max_score=100, findings=None, skipped=False):
        self.analyzer_name = analyzer_name   # Identifies which analyzer produced this result
        self.score = score                   # How suspicious the email looks (0 = clean)
        self.max_score = max_score           # Upper bound — used to normalize across analyzers
        self.findings = findings if findings is not None else []  # Human-readable explanations
        self.skipped = skipped               # True if analyzer couldn't run (e.g. missing API key)


class BaseAnalyzer(ABC):
    """Abstract base class — every analyzer must implement analyze()."""

    name: str = "base"

    @abstractmethod
    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        ...
