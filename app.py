from fastapi import FastAPI
from pydantic import BaseModel
import requests
from urllib.parse import urlparse

app = FastAPI()


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
# WHOIS CHECK
# =========================
def check_whois(domain: str):
    API_KEY = "at_eXQ3BNRKyD1L0j5dyKPSFWQ1ihikK"

    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={API_KEY}&domainName={domain}&outputFormat=JSON"

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
    API_KEY = "2dc1f8344737680c7963bf4a059121484fae39b5c2e8afe4541dee6756af67d3"

    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": API_KEY},
            data={"url": url_value}
        )

        analysis_id = submit.json()["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": API_KEY}
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

    # -------------------------
    # RULE CHECK
    # -------------------------
    keywords = ["hack", "free", "login", "verify", "win", "bitcoin"]

    for k in keywords:
        if k in url.lower():
            score -= 10
            issues.append(f"Suspicious keyword: {k}")

    if not url.startswith("https://"):
        score -= 15
        issues.append("No HTTPS security")

    # -------------------------
    # WHOIS
    # -------------------------
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

    # -------------------------
    # VIRUSTOTAL
    # -------------------------
    vt = check_virustotal(url)

    if vt:
        if vt.get("malicious", 0) > 0:
            score -= 50
            issues.append("Malicious detected")
        if vt.get("suspicious", 0) > 0:
            score -= 20
            issues.append("Suspicious activity detected")

    # -------------------------
    # FINAL SCORE
    # -------------------------
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
