"""
Shared async HTTP client.
All analyzers that make external API calls (VirusTotal, WHOIS, URL resolution)
use this same client, which maintains a connection pool for efficiency.
The client is closed on server shutdown via FastAPI's lifespan handler.
"""

import httpx
from app.config import settings

_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    """Return the shared client, creating it on first use."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=settings.http_timeout)
    return _client


async def close_http_client() -> None:
    """Gracefully close the connection pool. Called on server shutdown."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
        _client = None
