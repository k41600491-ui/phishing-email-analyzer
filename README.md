# Phishing Email Analyzer

A Python tool that automatically analyzes `.eml` email files for phishing indicators — email authentication failures, sender spoofing, suspicious URLs, and urgency-based social engineering — and produces a weighted risk score with a final verdict.

Built as a hands-on project to learn practical security automation: email header analysis, threat intelligence API integration, and secure secret management.

## Features

- **Header parsing** — extracts and analyzes From, Reply-To, Subject, and Date fields from raw email files using Python's built-in `email` library
- **Sender spoofing detection** — flags mismatches between the From domain and Reply-To domain, a common phishing tell
- **Email authentication checks** — parses `Authentication-Results` headers to detect SPF, DKIM, and DMARC failures
- **URL extraction** — uses regex to pull links out of HTML email bodies
- **Threat intelligence lookup** — checks extracted URLs against [urlscan.io](https://urlscan.io) for prior scan history, using a securely-stored API key
- **Urgency/social engineering detection** — flags common manipulation language ("urgent," "verify immediately," "account suspended," etc.)
- **Weighted risk scoring** — combines all signals into a single score and a `MALICIOUS` / `SUSPICIOUS` / `LIKELY SAFE` verdict

## How it works

Each email is scored based on weighted signals:

| Signal | Points |
|---|---|
| Reply-To domain differs from From domain | +20 |
| SPF authentication failure | +15 |
| DKIM authentication failure | +15 |
| DMARC authentication failure | +15 |
| Suspicious URL found in body | +20 |
| URL has prior malicious scan history (urlscan.io) | +20 |
| Each urgency/social-engineering keyword found | +5 |

**Verdict thresholds:** 50+ = `MALICIOUS`, 20-49 = `SUSPICIOUS`, under 20 = `LIKELY SAFE`

These weights and thresholds are a starting hypothesis based on common phishing patterns, not a validated statistical model — see Known Limitations below.

## Setup

```bash
git clone https://github.com/k41600491-ui/phishing-email-analyzer.git
cd phishing-email-analyzer
python -m venv venv
venv\Scripts\Activate.ps1      # Windows PowerShell
pip install -r requirements.txt
```

Create a `.env` file in the project root with a free [urlscan.io](https://urlscan.io) API key:
URLSCAN_API_KEY=your_key_here