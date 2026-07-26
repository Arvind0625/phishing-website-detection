from flask import Flask, render_template, request
import pickle
import math
import re
import shap
import requests
import whois
from bs4 import BeautifulSoup
from collections import Counter
from datetime import datetime
import socket
from urllib.parse import urlparse
import ssl

app = Flask(__name__)

# Load model
with open("models/phishing_model.pkl","rb") as f:
    model = pickle.load(f)
explainer = shap.TreeExplainer(model)

trusted_domains = [
    "google.com",
    "amazon.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "linkedin.com",
    "wikipedia.org",
    "stackoverflow.com"
]

# ---------- FEATURE FUNCTIONS ----------- #

def url_entropy(url):
    counts = Counter(url)
    probs = [c/len(url) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def keyword_score(url):
    suspicious_words = ["login", "verify", "bank", "secure", "update", "free"]
    return sum(word in url.lower() for word in suspicious_words)

def is_ip(url):
    return 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

def count_digits(url):
    return sum(c.isdigit() for c in url)

def subdomain_count(url):
    return url.count(".") - 1

def has_at_symbol(url):
    return 1 if "@" in url else 0

def has_https(url):
    return 1 if url.startswith("https") else 0

def suspicious_tld(url):
    bad_tlds = [".tk",".ml",".ga",".cf",".gq"]
    return int(any(url.endswith(tld) for tld in bad_tlds))

def slash_count(url):
    return url.count("/")

def query_length(url):
    if "?" in url:
        return len(url.split("?")[1])
    return 0

def special_char_count(url):
    return len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url))


def extract_features(url):

    return [[
        len(url),
        url.count("."),
        url.count("-"),
        count_digits(url),
        is_ip(url),
        keyword_score(url),
        url_entropy(url),
        subdomain_count(url),
        has_at_symbol(url),
        has_https(url),
        suspicious_tld(url),
        slash_count(url),
        query_length(url),
        special_char_count(url)
    ]]


def get_site_purpose(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=3,
            allow_redirects=True
        )

        soup = BeautifulSoup(response.text, "html.parser")

        # Title
        title = soup.title.string.strip() if soup.title else "Unknown Website"

        # Standard meta description
        meta = soup.find("meta", attrs={"name": "description"})

        if meta and meta.get("content"):
            description = meta["content"]

        else:
            # Try OpenGraph description
            og = soup.find("meta", attrs={"property": "og:description"})
            description = og["content"] if og else "No description available"

        return title, description

    except Exception as e:
        print("Metadata fetch failed:", e)
        return "Unknown Website", "Unable to analyze site content"
    
# ---------- IP ADDRESS FUNCTION ----------

def get_ip(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None


# ---------- IP LOCATION FUNCTION ----------

def get_ip_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org")
        }
    except:
        return None
    
def get_domain_age(url):
    try:
        # Ensure URL has scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")

        # Handle subdomains
        parts = domain.split(".")
        if len(parts) > 2:
            if parts[-2] in ["co", "com", "org", "net"]:
                domain = ".".join(parts[-3:])
            else:
                domain = ".".join(parts[-2:])

        # WHOIS lookup
        w = whois.whois(domain)

        creation_date = (
            w.creation_date
            or w.get("created")
            or w.get("registration_date")
        )

        # Sometimes WHOIS returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return "Not Available"

        # Remove timezone if present
        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo:
            creation_date = creation_date.replace(tzinfo=None)

        now = datetime.now()
        age_days = (now - creation_date).days
        age_years = age_days / 365.25

        # Classification
        if age_years < 1:
            return f"Very New Domain ({age_days} days old)"
        elif age_years < 3:
            return "Moderately New Domain"
        else:
            return f"{round(age_years, 2)} years"

    except Exception as e:
        print("WHOIS lookup failed:", e)
        return "Not Available"
    
def check_ssl(url):
    try:
        hostname = urlparse(url).netloc

        ctx = ssl.create_default_context()

        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        return "Valid SSL Certificate"

    except:
        return "No Valid SSL Certificate"
# ---------- ROUTES ----------- #

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]
    title, description = get_site_purpose(url)
    # --------- GET IP & LOCATION ---------

    ip = get_ip(url)
    location_data = None
    domain_age = get_domain_age(url)
    ssl_status = check_ssl(url)

    if ip:
        location_data = get_ip_location(ip)
    features = extract_features(url)

    prob = model.predict_proba(features)[0][0]
    risk_percent = round(prob * 100, 2)

    domain = urlparse(url).netloc.replace("www.", "")

    if ssl_status == "No Valid SSL Certificate":
        risk_percent += 15

    if "Very New Domain" in domain_age:
        risk_percent += 20
    elif "Moderately New Domain" in domain_age:
        risk_percent += 10
    
    for trusted in trusted_domains:
        if trusted in domain:
            risk_percent = min(risk_percent, 5)
    risk_percent = min(risk_percent, 100)
    
    # Risk level classification
    if risk_percent < 40:
        level = "Low Risk"
    elif risk_percent < 75:
        level = "Medium Risk"
    else:
        level = "High Risk"
    if risk_percent < 20:
        trust_status = "Trusted Website"
    elif risk_percent < 80:
        trust_status = "Use Caution"
    else:
        trust_status = "Potential Phishing Website"

    shap_values = explainer.shap_values(features)

    feature_names = [
    "URL Length",
    "Dot Count",
    "Hyphen Count",
    "Digit Count",
    "IP Present",
    "Suspicious Keywords",
    "URL Entropy",
    "Subdomain Count",
    "Has @ Symbol",
    "HTTPS",
    "Suspicious TLD",
    "Slash Count",
    "Query Length",
    "Special Character Count"
    ]

    # Safe handling
    if isinstance(shap_values, list):
        shap_array = shap_values[1][0]
    else:
        shap_array = shap_values[0]

    importance = dict(zip(feature_names, shap_array))

    top_features = sorted(
        importance.items(),
        key=lambda x: abs(x[1]),
        reverse=True
    )[:3]

    return render_template(
    "index.html",
    risk=risk_percent,
    level=level,
    trust_status=trust_status,
    explanation=top_features,
    url=url,
    ip=ip,
    location=location_data,
    title=title,
    description=description,
    domain=domain,
    domain_age = domain_age,
    ssl_status = ssl_status
)

if __name__ == "__main__":
    app.run(debug=True)