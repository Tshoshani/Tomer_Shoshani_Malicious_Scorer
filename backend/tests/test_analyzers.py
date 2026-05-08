"""Unit tests for individual analyzers."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from app.analyzers.authentication import AuthenticationAnalyzer
from app.analyzers.intent import IntentAnalyzer
from app.analyzers.url_analysis import UrlAnalyzer
from app.analyzers.attachment import AttachmentAnalyzer
from app.analyzers.ai_content import AiContentAnalyzer
from app.analyzers.domain_reputation import DomainReputationAnalyzer
from app.schemas import EmailAnalysisRequest
from datetime import datetime, timezone, timedelta


def _email(subject="Test", sender="user@example.com", body="Hello", headers=None, attachments=None):
    return EmailAnalysisRequest(
        subject=subject, sender_email=sender, body=body,
        headers=headers, attachments=attachments,
    )


# --- Authentication ---

class TestAuthentication:
    @pytest.mark.asyncio
    async def test_all_pass_scores_zero(self):
        result = await AuthenticationAnalyzer().analyze(
            _email(headers={"Authentication-Results": "spf=pass dkim=pass dmarc=pass"})
        )
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_all_fail_scores_max(self):
        result = await AuthenticationAnalyzer().analyze(
            _email(headers={"Authentication-Results": "spf=fail dkim=fail dmarc=fail"})
        )
        assert result.score == 100


# --- Intent ---

class TestIntent:
    @pytest.mark.asyncio
    async def test_clean_email_scores_zero(self):
        result = await IntentAnalyzer().analyze(_email(body="See you at the meeting."))
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_phishing_phrases_detected(self):
        result = await IntentAnalyzer().analyze(
            _email(subject="URGENT", body="Immediate action required. Verify your identity now.")
        )
        assert result.score > 0
        assert len(result.findings) >= 2


# --- URL Analysis ---

class TestUrlAnalysis:
    @pytest.mark.asyncio
    async def test_legit_url_not_flagged(self):
        result = await UrlAnalyzer().analyze(_email(body="Visit https://google.com/search"))
        assert result.score == 0

    @pytest.mark.asyncio
    async def test_spoofed_brand_flagged(self):
        result = await UrlAnalyzer().analyze(
            _email(body="Login: https://google-security.evil.xyz/verify")
        )
        assert result.score == 45  # max_score


# --- Attachment ---

class TestAttachment:
    @pytest.mark.asyncio
    async def test_exe_scores_high(self):
        with patch("app.analyzers.attachment.settings") as s:
            s.vt_api_key = None
            result = await AttachmentAnalyzer().analyze(_email(attachments=[
                {"filename": "invoice.exe", "mime_type": "application/x-msdownload",
                 "sha256": "a" * 64, "size_bytes": 1000},
            ]))
        assert result.score >= 50

    @pytest.mark.asyncio
    async def test_safe_extension_scores_zero(self):
        with patch("app.analyzers.attachment.settings") as s:
            s.vt_api_key = None
            result = await AttachmentAnalyzer().analyze(_email(attachments=[
                {"filename": "photo.jpg", "mime_type": "image/jpeg",
                 "sha256": "b" * 64, "size_bytes": 5000},
            ]))
        assert result.score == 0


# --- AI Content ---

class TestAiContent:
    @pytest.mark.asyncio
    async def test_skips_without_api_key(self):
        with patch("app.analyzers.ai_content.settings") as s:
            s.gemini_api_key = None
            result = await AiContentAnalyzer().analyze(_email())
        assert result.skipped is True

    @pytest.mark.asyncio
    async def test_parses_gemini_response(self):
        mock_response = MagicMock()
        mock_response.text = '{"risk_score": 70, "flags": ["urgency"], "explanation": "Phishing"}'

        mock_aio_models = MagicMock()
        mock_aio_models.generate_content = AsyncMock(return_value=mock_response)
        mock_client = MagicMock()
        mock_client.aio = MagicMock(models=mock_aio_models)

        with patch("app.analyzers.ai_content.settings") as s, \
             patch("app.analyzers.ai_content.Client", return_value=mock_client):
            s.gemini_api_key = "key"
            result = await AiContentAnalyzer().analyze(_email())
        assert result.score == 70


# --- Domain Reputation ---

class TestDomainReputation:
    @pytest.mark.asyncio
    async def test_skips_without_api_key(self):
        with patch("app.analyzers.domain_reputation.settings") as s:
            s.vt_api_key = None
            result = await DomainReputationAnalyzer().analyze(_email())
        assert result.skipped is True

    @pytest.mark.asyncio
    async def test_new_domain_scores_high(self):
        creation_ts = int((datetime.now(timezone.utc) - timedelta(days=5)).timestamp())
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "harmless": 60},
            "creation_date": creation_ts,
        }}}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("app.analyzers.domain_reputation.get_http_client", return_value=mock_client), \
             patch("app.analyzers.domain_reputation.settings") as s:
            s.vt_api_key = "key"
            s.whois_api_key = None
            result = await DomainReputationAnalyzer().analyze(_email())
        assert result.score >= 40
