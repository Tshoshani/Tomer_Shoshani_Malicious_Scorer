import re # ייבוא נדרש לניקוי דומיינים
from fastapi import FastAPI
from schemas import EmailAnalysisRequest, AnalysisResponse
from engine import check_authentication, check_domain_reputation, check_intent, check_whois_age

app = FastAPI(title="Upwind Malicious Email Scorer")

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    # 1. Identity Pillar
    auth_score, auth_reasons = check_authentication(request.headers or {})
    
    # --- התיקון כאן: חילוץ דומיין נקי באמצעות Regex ---
    # זה מונע שגיאות 400 מול VirusTotal ומנקה תווים מיותרים כמו < >
    sender = request.sender_email.lower()
    domain_match = re.search(r"@([\w.-]+)", sender)
    domain = domain_match.group(1) if domain_match else "unknown"
    # --------------------------------------------------
    
    # 2. Reputation Pillar
    rep_score, rep_reasons = await check_domain_reputation(domain)

    # 3. WHOIS Pillar 
    whois_score, whois_reasons = await check_whois_age(domain)
    
    # 4. Intent Pillar 
    intent_score, intent_reasons = check_intent(request.body, request.subject)
    
    # איסוף כל הניקוד (מקסימום 100) וכל הנימוקים
    total_score = min(100, auth_score + rep_score + whois_score + intent_score)
    all_reasons = auth_reasons + rep_reasons + whois_reasons + intent_reasons
    
    verdict = "Safe"
    if total_score >= 75:
        verdict = "Malicious"
    elif total_score >= 35:
        verdict = "Suspicious"
        
        
    return {
        "score": total_score,
        "verdict": verdict,
        "reasoning": all_reasons if all_reasons else ["No significant threats found."]
    }