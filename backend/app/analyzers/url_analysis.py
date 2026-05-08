import re
from urllib.parse import urlparse

from app.analyzers.base import AnalysisResult, BaseAnalyzer
from app.schemas import EmailAnalysisRequest
from app.services.http_client import get_http_client


# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.io", "rebrand.ly", "cutt.ly", "rb.gy",
}

PROTECTED_BRANDS = [
    "google", "gmail", "microsoft", "outlook", "office 365", "apple", "icloud",
    "yahoo", "amazon", "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "x", "paypal", "visa", "mastercard", "american express", "chase",
    "bank of america", "wells fargo", "citibank", "hsbc", "barclays",
    "capital one", "revolut", "wise", "stripe", "ups", "fedex", "dhl", "usps",
    "royal mail", "canada post", "australia post", "ebay", "aliexpress",
    "shopify", "etsy", "walmart", "target", "best buy", "netflix", "spotify",
    "disney+", "hulu", "youtube", "irs", "tax authority", "social security",
    "government", "ministry of finance", "customs", "adobe", "dropbox",
    "onedrive", "google drive", "icloud drive", "booking.com", "airbnb",
    "expedia", "uber", "israel post", "bank hapoalim", "bank leumi",
    "discount bank", "mizrahi tefahot", "bit", "paybox", "isracard", "clal", "harel",
]


class UrlAnalyzer(BaseAnalyzer):
    """Detects brand impersonation in URLs (look-alike domains)."""

    name = "url_analysis"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=45)

        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email.body)
        if not urls:
            return result

        # Resolve shortened URLs to their final destination
        resolved_urls = []
        for url in urls:
            resolved = await self._resolve_shortened_url(url)
            resolved_urls.append(resolved)

        flagged_brands: set[str] = set()

        for url in resolved_urls:
            try:
                parsed = urlparse(url)
                netloc = (parsed.netloc or parsed.path).lower()

                for brand in PROTECTED_BRANDS:
                    if brand in netloc and brand not in flagged_brands:
                        legit_domains = [
                            f"{brand}.com", f"{brand}.co.il",
                            f"{brand}.org", f"{brand}.net",
                        ]
                        is_legit = any(legit in netloc for legit in legit_domains)

                        if not is_legit:
                            # Short brand names need stricter matching
                            if len(brand) <= 3 and f".{brand}." not in f".{netloc}.":
                                continue

                            result.score = result.max_score
                            result.findings.append(
                                f"Suspicious Link: URL mimics official '{brand}' domain"
                            )
                            flagged_brands.add(brand)
            except (ValueError, AttributeError):
                continue

        return result

    @staticmethod
    async def _resolve_shortened_url(url: str) -> str:
        """Resolve URL shorteners (bit.ly, tinyurl, etc.) to final destination."""
        try:
            parsed = urlparse(url)
            domain = (parsed.netloc or parsed.path.split("/")[0]).lower()

            if domain not in SHORTENER_DOMAINS:
                return url

            client = await get_http_client()
            response = await client.head(url, follow_redirects=True)
            return str(response.url)
        except Exception:
            return url  # On failure, analyze the original URL
