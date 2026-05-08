import httpx
from app.config import settings

_client: httpx.AsyncClient | None = None


async def get_http_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=settings.http_timeout)
    return _client
