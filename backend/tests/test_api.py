"""Integration tests for the /analyze API endpoint."""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch
from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestAPI:
    @pytest.mark.asyncio
    async def test_valid_request_returns_200(self, client):
        with patch("app.analyzers.domain_reputation.settings") as dr, \
             patch("app.analyzers.ai_content.settings") as ai, \
             patch("app.analyzers.attachment.settings") as att:
            dr.vt_api_key = None
            ai.gemini_api_key = None
            att.vt_api_key = None

            r = await client.post("/analyze", json={
                "subject": "Hi",
                "sender_email": "friend@example.com",
                "body": "See you tomorrow",
                "headers": {"Authentication-Results": "spf=pass dkim=pass dmarc=pass"},
            })
        assert r.status_code == 200
        assert r.json()["verdict"] == "Safe"

    @pytest.mark.asyncio
    async def test_missing_field_returns_422(self, client):
        r = await client.post("/analyze", json={"subject": "Hi", "sender_email": "a@b.com"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_email_format_returns_422(self, client):
        r = await client.post("/analyze", json={
            "subject": "Hi", "sender_email": "not-an-email", "body": "x",
        })
        assert r.status_code == 422
