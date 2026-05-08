from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List

from app.schemas import EmailAnalysisRequest


@dataclass
class AnalysisResult:
    analyzer_name: str
    score: int = 0
    max_score: int = 100
    findings: List[str] = field(default_factory=list)
    skipped: bool = False


class BaseAnalyzer(ABC):
    """Base class for all email analyzers."""

    name: str = "base"

    @abstractmethod
    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        ...
