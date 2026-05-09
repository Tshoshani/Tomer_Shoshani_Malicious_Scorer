"""
Detects brand impersonation in URLs embedded in the email body.
Phishing emails often use domains that look like real brands
(e.g. "g00gle-login.xyz" instead of "google.com").

Also resolves shortened URLs (bit.ly, tinyurl, etc.) before checking,
since attackers use shorteners to hide the real destination.
"""

import re
from urllib.parse import urlparse

from app.analyzers.base_analyzer_definitions import AnalysisResult, BaseAnalyzer
from app.schemas import EmailAnalysisRequest
from app.services.http_client import get_http_client


# Domains that redirect to a final URL — we resolve these first
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "short.io", "rebrand.ly", "cutt.ly", "rb.gy",
}

# Brands that attackers commonly impersonate in phishing URLs
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

        # Extract all URLs from the email body using regex
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email.body)
        if not urls:
            return result

        # Resolve any shortened URLs (e.g. bit.ly → actual destination)
        resolved_urls = []
        for url in urls:
            resolved = await self._resolve_shortened_url(url)
            resolved_urls.append(resolved)

        flagged_brands: set[str] = set()  # Avoid duplicate findings for same brand

        for url in resolved_urls:
            try:
                parsed = urlparse(url)
                # netloc = the domain part of the URL (e.g. "g00gle-alerts.xyz")
                # Falls back to parsed.path for URLs without a scheme (e.g. "www.fake.com/login")
                netloc = (parsed.netloc or parsed.path).lower()

                # Check if any protected brand name appears in the domain
                for brand in PROTECTED_BRANDS:
                    if brand in netloc and brand not in flagged_brands:
                        # Build list of legitimate domains for this brand
                        legit_domains = [
                            f"{brand}.com", f"{brand}.co.il",
                            f"{brand}.org", f"{brand}.net",
                        ]
                        is_legit = any(legit in netloc for legit in legit_domains)

                        if not is_legit:
                            # Short brand names (e.g. "x", "dhl") need stricter matching
                            # to avoid false positives on words like "extra" or "dhlab"
                            if len(brand) <= 3 and f".{brand}." not in f".{netloc}.":
                                continue

                            # Brand name in URL but not on a legit domain = impersonation
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
        """Follow redirects on shortened URLs to reveal the final destination."""
        try:
            parsed = urlparse(url)
            domain = (parsed.netloc or parsed.path.split("/")[0]).lower()

            # Only resolve if it's a known shortener; skip for regular URLs
            if domain not in SHORTENER_DOMAINS:
                return url

            # HEAD request follows redirects without downloading the page body
            client = await get_http_client()
            response = await client.head(url, follow_redirects=True)
            return str(response.url)
        except Exception:
            return url  # On failure, analyze the original URL
