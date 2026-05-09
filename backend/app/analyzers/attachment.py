"""
Analyzes email attachments using two signals:
  1. File extension risk tier — executables (.exe, .bat) score highest,
     macro-enabled Office docs and archives score medium.
  2. VirusTotal hash reputation — the SHA-256 hash (computed by the Gmail
     Add-on) is looked up. The backend never receives raw file bytes,
     reducing attack surface.
"""

from app.analyzers.base_analyzer_definitions import AnalysisResult, BaseAnalyzer
from app.config import settings
from app.schemas import EmailAnalysisRequest
from app.services.http_client import get_http_client

# Extension risk tiers — files that can directly execute code score highest
HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".wsh", ".pif", ".hta", ".cpl", ".reg",
    ".iso", ".img", ".vhd", ".vhdx",
}

MEDIUM_RISK_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm",  # Macro-enabled Office (can run VBA code)
    ".zip", ".rar", ".7z", ".tar", ".gz",  # Archives (can hide payloads)
    ".pdf", ".rtf",  # Known exploit vectors
    ".lnk", ".url",  # Shortcut files (can point to malicious targets)
}


class AttachmentAnalyzer(BaseAnalyzer):
    """Analyzes attachments by file extension risk and hash reputation (VirusTotal)."""

    name = "attachment"

    async def analyze(self, email: EmailAnalysisRequest) -> AnalysisResult:
        result = AnalysisResult(analyzer_name=self.name, max_score=90)

        if not email.attachments:
            return result

        extension_score = 0
        hash_score = 0

        for attachment in email.attachments:
            # Signal 1: Extension-based risk scoring
            ext = self._get_extension(attachment.filename)
            if ext in HIGH_RISK_EXTENSIONS:
                extension_score = max(extension_score, 50)
                result.findings.append(
                    f"High-risk file type: '{attachment.filename}' ({ext})"
                )
            elif ext in MEDIUM_RISK_EXTENSIONS:
                extension_score = max(extension_score, 25)
                result.findings.append(
                    f"Medium-risk file type: '{attachment.filename}' ({ext})"
                )

            # Signal 2: Check file hash against VirusTotal's database
            if settings.vt_api_key and attachment.sha256:
                vt_score = await self._check_hash_reputation(attachment.sha256)
                if vt_score > 0:
                    hash_score = max(hash_score, vt_score)
                    result.findings.append(
                        f"VirusTotal flagged '{attachment.filename}' as malicious."
                    )
                elif vt_score == 0:
                    # Hash not in VT database — unknown file, warrants caution
                    result.findings.append(
                        f"'{attachment.filename}' hash not found in VirusTotal — "
                        f"exercise caution with unknown files."
                    )
                # vt_score == -1 means clean

        # Combine both signals, capped at max_score
        result.score = min(extension_score + hash_score, result.max_score)
        return result

    async def _check_hash_reputation(self, sha256: str) -> int:
        """
        Look up a file hash on VirusTotal.
        Returns: positive score if malicious, 0 if unknown, -1 if clean.
        """
        client = await get_http_client()
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": settings.vt_api_key}

        try:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0 or suspicious > 0:
                    return min(60, (malicious + suspicious) * 15)
                return -1  # Known and clean

            elif response.status_code == 404:
                return 0  # Hash not in database

        except Exception:
            pass  # Network error — treat as unknown

        return 0

    @staticmethod
    def _get_extension(filename: str) -> str:
        """Extract lowercase file extension."""
        dot_idx = filename.rfind(".")
        if dot_idx == -1:
            return ""
        return filename[dot_idx:].lower()
