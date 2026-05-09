# Malicious Email Scorer

A Gmail Add-on backed by a Python analysis engine that scores emails for phishing and malicious intent, providing users with a transparent verdict and detailed reasoning.

## What It Does

When a user opens an email in Gmail, the add-on extracts its metadata (sender, headers, body, attachments) and sends it to a backend service. The backend runs **six independent analyzers in parallel**, each examining a different attack vector. Their scores are combined into a single 0–100 maliciousness score with a clear verdict: **Safe**, **Suspicious**, or **Malicious**.

The user sees the score, the verdict, and a breakdown of *why* — which analyzers flagged what.

---

## Architecture

```
Gmail Add-on (Google Apps Script)
        │
        │  HTTP POST /analyze
        ▼
┌─────────────────────────────────────────┐
│           FastAPI Backend                │
│                                         │
│   Scorer (orchestrator)                 │
│     ├── AuthenticationAnalyzer          │
│     ├── DomainReputationAnalyzer        │
│     ├── IntentAnalyzer                  │
│     ├── UrlAnalyzer                     │
│     ├── AiContentAnalyzer              │
│     └── AttachmentAnalyzer             │
│                                         │
│   External APIs:                        │
│     • VirusTotal (domain + file hash)   │
│     • WhoisXMLAPI (fallback for age)    │
│     • Google Gemini (content analysis)  │
└─────────────────────────────────────────┘
```

### Why this split?

- **Gmail Add-on** handles only UI rendering and data extraction. It contains no analysis logic — that belongs on the backend where it can be tested, iterated, and secured independently.
- **Backend** owns all decision-making. This means the add-on never touches API keys, never runs analysis that could be bypassed client-side, and can be deployed/updated without republishing the add-on.

---

## Analyzers

| Analyzer | What it checks | Key signals |
|----------|---------------|-------------|
| **Authentication** | SPF, DKIM, DMARC headers | Failed authentication = strong phishing indicator |
| **Domain Reputation** | VirusTotal flags + domain age | Flagged domains or domains <30 days old score high |
| **Intent** | Phishing phrase patterns in subject/body | Urgency, fear, financial bait, authority impersonation |
| **URL Analysis** | Brand impersonation in embedded links | Links mimicking Google, PayPal, banks, etc. |
| **AI Content** | LLM-based semantic analysis (Gemini 2.0 Flash) | Catches sophisticated social engineering that keywords miss |
| **Attachment** | File extension risk + VirusTotal hash lookup | Executables, macro-enabled docs, unknown file hashes |

### Scoring Logic

Each analyzer returns a score relative to its own maximum. The **Scorer** normalizes these and computes a weighted average — authentication and domain reputation carry more weight than URL pattern matching alone. Thresholds:

- **0–34**: Safe
- **35–74**: Suspicious
- **75–100**: Malicious

Weights are configurable via environment variables without code changes.

---

## Design Decisions and Trade-offs

### Plugin architecture for analyzers
Every analyzer implements `BaseAnalyzer.analyze()` and returns an `AnalysisResult`. Adding a new analyzer requires: (1) create the file, (2) add it to the list in `main.py`. No other code changes. This was chosen over a monolithic scoring function for testability and clarity.

### AI as complement, not replacement
The AI analyzer runs alongside deterministic checks, not instead of them. If the Gemini API is down or the key isn't configured, the system still functions with 5 other analyzers. The LLM catches what regex cannot (novel phrasing, contextual manipulation), while keyword detection catches what the LLM might hallucinate past.

### WHOIS as fallback only
Domain age is available from VirusTotal's response for free. WHOIS is only queried when VirusTotal doesn't have the creation date — saving API quota and reducing latency.

### Weighted average over raw sum
The original implementation summed all scores, which could exceed 100 unpredictably. A weighted average ensures the final score always reflects relative importance and stays in a predictable range.

### Attachment analysis without sandboxing
Sandboxing (detonating attachments) is out of scope for this project. Instead, we combine two practical signals: file extension risk tiers and VirusTotal hash reputation. The SHA-256 is computed by the Google Apps Script before sending — the backend never receives raw file bytes, reducing attack surface.

---

## Security Considerations

- **Input validation**: Pydantic enforces field types, max lengths (subject: 1000 chars, body: 100KB), email format validation (`EmailStr`), and required fields. Malformed requests are rejected before reaching any analyzer.
- **No secrets in client code**: All API keys live in the backend's `.env` file. The Gmail Add-on has no access to them.
- **Untrusted input handling**: Email bodies are treated as untrusted. No `eval()`, no template rendering, no shell execution on user-supplied content.
- **LLM prompt injection mitigation**: The AI analyzer sends email content as a user message, separated from the system prompt. The system prompt requests only structured JSON output — no tool calls or code execution. Response is validated (must be int 0-100) before use.
- **External API errors don't crash the system**: Each analyzer catches exceptions independently. A VirusTotal timeout doesn't prevent the authentication check from completing.
- **No raw file transfer**: Attachments are identified by SHA-256 hash only. The backend never handles file bytes.
- **Graceful HTTP client lifecycle**: Connection pool is properly closed on server shutdown via FastAPI lifespan.

---

## Running the Project

### Prerequisites

- Python 3.11+
- API keys (all optional — analyzers gracefully skip if their key is missing):
  - [VirusTotal](https://www.virustotal.com/gui/join-us) (free tier: 4 requests/min)
  - [Google AI Studio](https://aistudio.google.com/apikey) (for Gemini AI content analysis)
  - [WhoisXMLAPI](https://whois.whoisxmlapi.com/) (optional fallback)

### Setup

```bash
cd backend
pip install -r requirements.txt

# Create .env file with your keys
cp .env.example .env
# Edit .env and add your API keys
```

### Run locally

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

The API is available at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### Expose to Gmail Add-on (for development)

```bash
ngrok http 8000
```

Copy the ngrok HTTPS URL and set it as `BACKEND_URL` in the Google Apps Script.

### Example request

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "URGENT: Verify your account now",
    "sender_email": "security@g00gle-alerts.xyz",
    "body": "Click here to verify: https://g00gle-alerts.xyz/login",
    "headers": {
      "Authentication-Results": "spf=fail dkim=fail dmarc=fail"
    }
  }'
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | No | VirusTotal API key |
| `GEMINI_API_KEY` | No | Google Gemini API key for AI content analysis |
| `WHOIS_API_KEY` | No | WhoisXMLAPI key (fallback for domain age) |

---

## Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app + /analyze endpoint
│   ├── config.py            # Environment settings (reads .env)
│   ├── schemas.py           # Request/response data models
│   ├── analyzers/
│   │   ├── base_analyzer_definitions.py  # BaseAnalyzer interface + AnalysisResult
│   │   ├── authentication.py
│   │   ├── domain_reputation.py
│   │   ├── intent.py
│   │   ├── url_analysis.py  # Includes URL unshortening
│   │   ├── ai_content.py
│   │   └── attachment.py
│   ├── scoring/
│   │   └── scorer.py        # Runs analyzers in parallel, computes weighted score
│   └── services/
│       └── http_client.py   # Shared async HTTP client with connection pooling
├── tests/                   # Unit + integration tests (pytest)
├── .env.example             # Template for environment variables
└── requirements.txt         # Pinned dependencies
```
