import re
from datetime import datetime, timezone

from app.analyzers.base import AnalysisResult, BaseAnalyzer
from app.config import settings
from app.schemas import EmailAnalysisRequest
from app.services.http_client import get_http_client


class DomainReputationAnalyzer(BaseAnalyzer):
    """Checks sender domain reputation via VirusTotal."""

    name = "domain_reputation"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=100)

        if not settings.vt_api_key:
            result.skipped = True
            result.findings.append("VirusTotal check skipped: No API key configured.")
            return result

        domain = self._extract_domain(email.sender_email)
        if not domain:
            result.findings.append("Could not extract domain from sender email.")
            return result

        client = await get_http_client()
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": settings.vt_api_key}

        try:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                # Engine flags
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)

                if malicious_count > 0:
                    result.score += min(60, malicious_count * 20)
                    result.findings.append(
                        f"VirusTotal: {malicious_count} security engine(s) flagged this domain."
                    )
                else:
                    result.findings.append(
                        f"No malicious flags found for {domain} on VirusTotal."
                    )

                # Domain age (from VirusTotal)
                creation_date_ts = attributes.get("creation_date")
                if creation_date_ts:
                    self._score_domain_age(result, creation_date_ts)
                else:
                    # Fallback: try WHOIS only if VT doesn't have creation date
                    await self._whois_fallback(result, domain)

            elif response.status_code == 404:
                result.findings.append(f"Domain {domain} not found in VirusTotal database.")
                # VT doesn't know this domain at all — try WHOIS for age
                await self._whois_fallback(result, domain)
            else:
                result.findings.append(
                    f"VirusTotal API returned status {response.status_code}."
                )

        except Exception as e:
            result.findings.append(f"Reputation check error: {type(e).__name__}")

        # Ensure we never exceed max_score
        result.score = min(result.score, result.max_score)
        return result

    @staticmethod
    def _score_domain_age(result: AnalysisResult, creation_date_ts: int):
        """Score based on domain age in days."""
        creation_date = datetime.fromtimestamp(creation_date_ts, tz=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days

        if age_days < 30:
            result.score += 40
            result.findings.append(f"High Risk: Domain is very new ({age_days} days old).")
        elif age_days < 180:
            result.score += 15
            result.findings.append(f"Caution: Domain is relatively new ({age_days} days old).")
        else:
            result.findings.append(f"Domain is established ({age_days} days old).")

    async def _whois_fallback(self, result: AnalysisResult, domain: str):
        """Only called when VirusTotal doesn't have the domain's creation date."""
        if not settings.whois_api_key:
            return

        client = await get_http_client()
        url = (
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
            f"?apiKey={settings.whois_api_key}&domainName={domain}&outputFormat=JSON"
        )

        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                created_date_str = data.get("WhoisRecord", {}).get("createdDate")
                if created_date_str:
                    created_date = datetime.fromisoformat(
                        created_date_str.replace("Z", "+00:00")
                    )
                    age_days = (datetime.now(timezone.utc) - created_date).days

                    if age_days < 30:
                        result.score += 40
                        result.findings.append(
                            f"WHOIS: Domain is very new ({age_days} days old)."
                        )
                    elif age_days < 180:
                        result.score += 15
                        result.findings.append(
                            f"WHOIS: Domain is relatively new ({age_days} days old)."
                        )
                    else:
                        result.findings.append(
                            f"WHOIS: Domain is established ({age_days} days old)."
                        )
        except Exception:
            pass  # WHOIS is best-effort fallback, don't fail the whole analysis

    @staticmethod
    def _extract_domain(sender_email: str) -> str | None:
        match = re.search(r"@([\w.-]+)", sender_email.lower())
        return match.group(1) if match else None
