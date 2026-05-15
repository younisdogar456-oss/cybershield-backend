from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from urllib.parse import urlparse

app = FastAPI()

# =========================
# CORS FIX
# =========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # بعد میں specific domain لگا سکتے ہیں
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# INPUT MODEL
# =========================
class URLRequest(BaseModel):
    url: str


# =========================
# DOMAIN EXTRACT
# =========================
def get_domain(url: str):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


# =========================
# API KEYS
# =========================

# PASTE IN RENDER ENVIRONMENT
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

# PASTE IN RENDER ENVIRONMENT
VT_API_KEY = os.getenv("VT_API_KEY")

# PASTE IN RENDER ENVIRONMENT
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


# =========================
# WHOIS CHECK
# =========================
def check_whois(domain: str):

    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"

    try:
        res = requests.get(url, timeout=10)
        data = res.json()
        return data.get("WhoisRecord", {}).get("estimatedDomainAge")
    except:
        return None


# =========================
# VIRUSTOTAL CHECK
# =========================
def check_virustotal(url_value: str):

    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": VT_API_KEY},
            data={"url": url_value}
        )

        analysis_id = submit.json()["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": VT_API_KEY}
        )

        stats = result.json()["data"]["attributes"]["stats"]
        return stats

    except:
        return None


# =========================
# MAIN SCAN API
# =========================
@app.post("/scan")
def scan(data: URLRequest):

    url = data.url
    domain = get_domain(url)

    score = 100
    issues = []

    keywords = ["hack", "free", "login", "verify", "win", "bitcoin"]

    for k in keywords:
        if k in url.lower():
            score -= 10
            issues.append(f"Suspicious keyword: {k}")

    if not url.startswith("https://"):
        score -= 15
        issues.append("No HTTPS security")

    age = check_whois(domain)

    if age is not None:
        if age < 365:
            score -= 30
            issues.append("Very new domain (high risk)")
        elif age < 1825:
            score -= 15
            issues.append("Medium age domain")
    else:
        issues.append("WHOIS data not available")

    vt = check_virustotal(url)

    if vt:
        if vt.get("malicious", 0) > 0:
            score -= 50
            issues.append("Malicious detected")

        if vt.get("suspicious", 0) > 0:
            score -= 20
            issues.append("Suspicious activity detected")

    if score < 0:
        score = 0

    if score >= 70:
        status = "SAFE"
    elif score >= 40:
        status = "SUSPICIOUS"
    else:
        status = "DANGEROUS"

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "status": status,
        "issues": issues
    }
