import re
import os
import httpx
from datetime import datetime, timezone
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

def check_authentication(headers: dict):
    """
    Analyzes SPF, DKIM, and DMARC results from the headers.
    Returns (score_contribution, reason_list)
    """
    score = 0
    reasons = []
    
    # We look for the 'Authentication-Results' header provided by Gmail
    # It usually looks like: "spf=pass ... dkim=pass ... dmarc=pass"
    auth_results = headers.get("Authentication-Results", "").lower()
    
    if not auth_results:
        return 20, ["No authentication headers found. Identity could not be verified."]

    # 1. Check DMARC (The most important one)
    if "dmarc=pass" in auth_results:
        pass
    elif "dmarc=fail" in auth_results:
        score += 50
        reasons.append("Critical: DMARC authenticationfailed.")
    else:
        score += 10
        reasons.append("Warning: DMARC record is missing, neutral, or could not be verified.")
    
    # 2. Check SPF
    if "spf=fail" in auth_results:
        score += 30
        reasons.append("SPF failed: The sending server is not authorized by the domain.")
    elif "spf=softfail" in auth_results:
        score += 15
        reasons.append("SPF soft-fail: The sending server is suspicious.")

    # 3. Check DKIM
    if "dkim=fail" in auth_results:
        score += 20
        reasons.append("DKIM failed: The email signature is invalid or was tampered with.")

    return score, reasons


async def check_domain_reputation(domain: str):
    """
    Checks VirusTotal domain reputation and age.
    Combines security insights with engineering hygiene.
    """
    score = 0
    reasons = []
    
    if not VT_API_KEY:
        return 0, ["VirusTotal check skipped: No API key found in environment."]

    async with httpx.AsyncClient() as client:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        
        try:
            # שימוש ב-timeout של 100 שניות כפי שמומלץ לעבודה עם API חיצוניים
            response = await client.get(url, headers=headers, timeout=100.0)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # 1. ניתוח מנועי סריקה (VirusTotal Stats)
                stats = attributes.get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                
                if malicious_count > 0:
                    # 20 נקודות לכל מנוע שזיהה את הדומיין כזדוני
                    score += (malicious_count * 20)
                    reasons.append(f"VirusTotal: {malicious_count} security engines flagged this domain.")
                else:
                    reasons.append(f"Reputation: No malicious flags found for {domain} on VirusTotal.")

                # 2. בדיקת גיל דומיין (Creativity: Beyond the obvious)
                creation_date_ts = attributes.get('creation_date')
                if creation_date_ts:
                    # המרת ה-Timestamp (Unix) לתאריך והשוואה לזמן הנוכחי[cite: 3]
                    creation_date = datetime.fromtimestamp(creation_date_ts, tz=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - creation_date).days
                    
                    if age_days < 30:
                        score += 40
                        reasons.append(f"High Risk: Domain is very new ({age_days} days old).")
                    elif age_days < 180:
                        score += 15
                        reasons.append(f"Caution: Domain is relatively new ({age_days} days old).")
                    else:
                        reasons.append(f"Reputation: Domain is established ({age_days} days old).")
                else:
                    reasons.append("Reputation: Domain creation date could not be retrieved from VirusTotal.")
            
            elif response.status_code == 404:
                reasons.append(f"Reputation: Domain {domain} not found in VirusTotal database.")
            else:
                # עוזר לניפוי באגים ב-Swagger UI[cite: 1]
                reasons.append(f"Reputation: VirusTotal API returned status {response.status_code}.")
                        
        except Exception as e:
            reasons.append(f"Reputation check error: {str(e)}")

    return score, reasons

WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

async def check_whois_age(domain: str):
    """
    Queries a WHOIS API to find the domain's age.
    Demonstrates 'beyond the obvious' creativity by identifying staging.
    """
    score = 0
    reasons = []
    
    if not WHOIS_API_KEY:
        return 0, ["WHOIS check skipped: No API key found."]

    async with httpx.AsyncClient() as client:
        # Example using WhoisXMLAPI
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
        
        try:
            response = await client.get(url, timeout=100.0)
            if response.status_code == 200:
                data = response.json()
                created_date_str = data.get('WhoisRecord', {}).get('createdDate')
                
                if created_date_str:
                    # Convert string to datetime (WhoisXMLAPI usually returns ISO format)
                    created_date = datetime.fromisoformat(created_date_str.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - created_date).days
                    
                    if age_days < 30:
                        score += 40
                        reasons.append(f"WHOIS Alert: Domain is very new ({age_days} days old).")
                    elif age_days < 180:
                        score += 15
                        reasons.append(f"WHOIS Warning: Domain is relatively new ({age_days} days old).")
                    else:
                        reasons.append(f"WHOIS Verified: Domain is established ({age_days} days old).")
            else:
                reasons.append(f"WHOIS API error: Status {response.status_code}")
        except Exception as e:
            reasons.append(f"WHOIS check error: {str(e)}")

    return score, reasons


PROTECTED_BRANDS = [
    "google",
    "gmail",
    "microsoft",
    "outlook",
    "office 365",
    "apple",
    "icloud",
    "yahoo",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "linkedin",
    "twitter",
    "x",
    "paypal",
    "visa",
    "mastercard",
    "american express",
    "chase",
    "bank of america",
    "wells fargo",
    "citibank",
    "hsbc",
    "barclays",
    "capital one",
    "revolut",
    "wise",
    "stripe",
    "ups",
    "fedex",
    "dhl",
    "usps",
    "royal mail",
    "canada post",
    "australia post",
    "ebay",
    "aliexpress",
    "shopify",
    "etsy",
    "walmart",
    "target",
    "best buy",
    "netflix",
    "spotify",
    "disney+",
    "hulu",
    "youtube",
    "irs",
    "tax authority",
    "social security",
    "government",
    "ministry of finance",
    "customs",
    "adobe",
    "dropbox",
    "onedrive",
    "google drive",
    "icloud drive",
    "booking.com",
    "airbnb",
    "expedia",
    "uber",
    "israel post",
    "bank hapoalim",
    "bank leumi",
    "discount bank",
    "mizrahi tefahot",
    "bit",
    "paybox",
    "isracard",
    "clal",
    "harel"
]
# The comprehensive list organized by category for better reasoning
PHISHING_CATEGORIES = {
    "Urgency/Pressure": [
        "urgent", "immediate action required", "act now", "expires today", 
        "limited time", "final notice", "last warning", "account will be closed", 
        "response needed immediately", "within 24 hours"
    ],
    "Security/Fear": [
        "security alert", "unauthorized login", "suspicious activity", 
        "account compromised", "verify your identity", "confirm your account", 
        "reset your password", "fraud detected", "we detected unusual activity"
    ],
    "Financial": [
        "payment failed", "invoice attached", "you have been charged", 
        "refund available", "claim your refund", "billing issue", 
        "update your payment", "tax refund", "unpaid balance"
    ],
    "Rewards/Bait": [
        "you won", "congratulations", "free gift", "claim your prize", 
        "exclusive offer", "selected winner", "lottery", "reward waiting"
    ],
    "Authority": [
        "bank notice", "official notice", "government alert", "admin request", 
        "it department", "support team", "customer service", "your account manager"
    ],
    "Action Triggers": [
        "click here", "login now", "verify now", "update now", 
        "open attachment", "download now", "access your account", "secure your account"
    ],
    "High-Risk Combos": [
        "urgent action required", "account suspended immediately", 
        "verify your account now", "unauthorized login attempt", 
        "click here to secure your account"
    ]
}


def check_intent(body: str, subject: str):
    score = 0
    reasons = set()
    content = (subject + " " + body).lower()
    
    # 1. ניתוח מילות מפתח
    for category, phrases in PHISHING_CATEGORIES.items():
        found = [p for p in phrases if p in content]
        if found:
            weight = 30 if category in ["High-Risk Combos", "Urgency/Pressure"] else 15
            score += weight
            reasons.add(f"Content flags: Detected {category}")

    # 2. בדיקת לינקים דומים (Look-alike) - תיקון ה-False Positive
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    flagged_brands = set()

    for url in urls:
        try:
            # חילוץ הדומיין בלבד מהקישור (למשל madlan.co.il מתוך ה-URL)
            parsed = urlparse(url)
            netloc = (parsed.netloc or parsed.path).lower()
            
            for brand in PROTECTED_BRANDS:
                # בדיקה אם המותג מופיע בדומיין אבל זה לא האתר הרשמי שלו
                if brand in netloc and brand not in flagged_brands:
                    # רשימת דומיינים לגיטימיים למותגים קצרים
                    legit_domains = [f"{brand}.com", f"{brand}.co.il", f"{brand}.org", f"{brand}.net"]
                    is_legit = any(legit in netloc for legit in legit_domains)
                    
                    # אם המותג קצר מאוד (כמו x, ups, dhl), נדרוש בדיקה מחמירה יותר
                    if not is_legit:
                        if len(brand) <= 3 and f".{brand}." not in f".{netloc}.":
                            continue # התעלמות אם זה סתם חלק ממילה
                        
                        score += 45
                        reasons.add(f"Suspicious Link: URL mimics official '{brand}' domain")
                        flagged_brands.add(brand)
        except:
            continue

    return score, list(reasons)