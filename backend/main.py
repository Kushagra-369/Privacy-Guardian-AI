from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
import requests
import os
import re
from dotenv import load_dotenv
from ai.feature_extractor import extract_advanced_features
from ai.nlp_detector import detect_phishing_text
load_dotenv()
app = FastAPI()

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== LOAD MODELS =====
risk_model = None
phishing_model = None

try:
    if os.path.exists("ai/phishing_model.pkl"):
        phishing_model = joblib.load("ai/phishing_model.pkl")
        print("✅ Phishing model loaded")
    else:
        print("⚠️ Phishing model not found")
except Exception as e:
    print("❌ Phishing Model Load Error:", e)

try:
    if os.path.exists("ai/model.pkl"):
        risk_model = joblib.load("ai/model.pkl")
        print("✅ Risk model loaded")
    else:
        print("⚠️ Risk model not found, using fallback")
except Exception as e:
    print("❌ Risk Model Load Error:", e)

# ===== REQUEST MODEL =====
class Data(BaseModel):
    trackers: list
    location: str
    camera: str
    microphone: str
    sensitive: bool
    phishing: bool
    blacklisted: bool
    url_phishing: bool = False
    url_length: int = 0
    has_https: bool = False
    dots: int = 0
    url: str = ""
    page_text: str = ""
    iframe_count: int = 0
    external_scripts: int = 0
    hidden_elements: int = 0

@app.get("/")
def home():
    return {"message": "AI Backend running 🚀"}

# ===== ADVANCED URL PHISHING DETECTION =====
def detect_url_phishing_advanced(url: str) -> tuple[bool, int]:
    """Advanced URL phishing detection with risk score"""
    risk_score = 0
    reasons = []
    
    url_lower = url.lower()
    
    # 1. Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.work', '.date', '.download']
    for tld in suspicious_tlds:
        if tld in url_lower:
            risk_score += 15
            reasons.append(f"suspicious TLD {tld}")
            break
    
    # 2. Check for excessive subdomains
    subdomain_count = url_lower.count('.')
    if subdomain_count > 3:
        risk_score += 10
        reasons.append("excessive subdomains")
    
    # 3. Check for URL length
    if len(url) > 100:
        risk_score += 10
        reasons.append("very long URL")
    if len(url) > 200:
        risk_score += 10
    
    # 4. Check for @ symbol (phishing)
    if '@' in url:
        risk_score += 30
        reasons.append("@ symbol in URL")
    
    # 5. Check for hyphens (brand spoofing)
    if url_lower.count('-') > 2:
        risk_score += 10
        reasons.append("multiple hyphens")
    
    # 6. Check for IP address in URL
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, url):
        risk_score += 35
        reasons.append("IP address in URL")
    
    # 7. Check for suspicious keywords
    suspicious_keywords = [
        'secure', 'account', 'login', 'signin', 'verify', 'update',
        'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'apple',
        'microsoft', 'support', 'customer', 'service', 'billing'
    ]
    
    for keyword in suspicious_keywords:
        if keyword in url_lower:
            risk_score += 5
            if keyword not in reasons:
                reasons.append(f"suspicious keyword '{keyword}'")
    
    # 8. Check for brand typosquatting
    brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple', 'netflix']
    for brand in brands:
        if brand in url_lower and not url_lower.startswith(brand) and not url_lower.startswith(f"www.{brand}"):
            # Check for typos
            if url_lower.count(brand) == 1:
                risk_score += 20
                reasons.append(f"possible {brand} typosquatting")
    
    # 9. Check for non-standard ports
    if ':8080' in url or ':3000' in url or ':5000' in url:
        risk_score += 10
        reasons.append("non-standard port")
    
    # 10. Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.link']
    for shortener in shorteners:
        if shortener in url_lower:
            risk_score += 20
            reasons.append("URL shortener detected")
    
    is_phishing = risk_score >= 30
    return is_phishing, min(risk_score, 100)

# ===== BRAND SPOOFING DETECTION =====
def detect_brand_spoofing(url: str) -> tuple[bool, str]:
    """Detect brand spoofing in URL"""
    url_lower = url.lower()
    
    brand_patterns = {
        'google': ['g00gle', 'go0gle', 'gooogle', 'googlee', 'goggle', 'googel'],
        'facebook': ['faceb00k', 'faceboook', 'facebok', 'facbook', 'face-book'],
        'amazon': ['amaz0n', 'amazom', 'amzon', 'amazzon', 'amazonn'],
        'paypal': ['paypa1', 'paypaI', 'pay-pal', 'paypal1', 'paypall'],
        'microsoft': ['micr0soft', 'micros0ft', 'microsoftt', 'micro-soft'],
        'apple': ['app1e', 'appple', 'aple', 'appleid'],
        'netflix': ['netfl1x', 'netflx', 'net-flix', 'netflixx']
    }
    
    for brand, spoofs in brand_patterns.items():
        for spoof in spoofs:
            if spoof in url_lower:
                return True, f"Brand spoofing detected: '{spoof}' looks like '{brand}'"
    
    return False, ""

# ===== GOOGLE SAFE BROWSING =====
def check_google_safe(url: str) -> bool:
    """Google Safe Browsing API check"""
    API_KEY = os.getenv("GOOGLE_API_KEY")
    
    if not API_KEY or API_KEY == "your_api_key_here":
        return False
    
    if "localhost" in url or "127.0.0.1" in url:
        return False
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    
    body = {
        "client": {"clientId": "privacy-guardian", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        res = requests.post(endpoint, json=body, timeout=5)
        if res.status_code == 200:
            result = res.json()
            return "matches" in result
    except Exception as e:
        print("⚠️ Safe Browsing check failed:", e)
    
    return False

# ===== SAFE DOMAINS =====
SAFE_DOMAINS = [
    "google.com", "youtube.com", "leetcode.com", "github.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com",
    "netflix.com", "spotify.com", "twitter.com", "facebook.com",
    "instagram.com", "whatsapp.com", "telegram.org", "stackoverflow.com",
    "reddit.com", "wikipedia.org", "github.io"
]

# ===== AI MESSAGE GENERATION =====
def generate_ai_message(risk: int, data: Data, phishing_detected: bool, url_phishing_score: int = 0):
    reasons = []
    
    # Tracker detection
    if len(data.trackers) > 5:
        reasons.append(f"multiple tracking scripts ({len(data.trackers)}) detected")
    elif len(data.trackers) > 0:
        reasons.append(f"{len(data.trackers)} tracking scripts detected")
    
    # Permission risks
    if "Allowed" in data.location:
        reasons.append("location access is enabled")
    if "Allowed" in data.camera:
        reasons.append("camera access is enabled")
    if "Allowed" in data.microphone:
        reasons.append("microphone access is enabled")
    
    # Content risks
    if data.sensitive:
        reasons.append("sensitive input fields detected")
    if data.phishing:
        reasons.append("suspicious phishing content detected")
    if data.blacklisted:
        reasons.append("domain is blacklisted")
    if data.url_phishing:
        reasons.append("suspicious URL pattern detected")
    
    # Security issues
    if not data.has_https:
        reasons.append("no HTTPS encryption")
    
    # Risk level
    if risk > 75:
        level = "⚠️ HIGH RISK"
        recommendation = "We strongly recommend leaving this site immediately."
    elif risk > 40:
        level = "⚠️ MODERATE RISK"
        recommendation = "Be cautious and avoid entering sensitive information."
    else:
        level = "✅ LOW RISK"
        recommendation = "No immediate threats detected."
    
    if phishing_detected:
        recommendation = "🚨 PHISHING SITE DETECTED! Leave immediately!"
    
    message = f"Risk Score: {risk}% - {level}\n\n"
    if reasons:
        message += f"⚠️ Issues found: {', '.join(reasons)}.\n\n"
    else:
        message += f"No major issues detected.\n\n"
    message += recommendation
    
    return message

# ===== MAIN ANALYSIS =====
@app.post("/analyze")
def analyze(data: Data):
    print("📥 Analyzing:", data.url)
    # ===== ADVANCED FEATURES (NEW 🔥) =====
    try:
        page_text = data.page_text.lower()
        iframe_count = data.iframe_count
        external_scripts = data.external_scripts
        hidden_elements = data.hidden_elements
        nlp_score, nlp_reasons = detect_phishing_text(data.url)
        advanced_features = extract_advanced_features(data.url)

        domain_age = advanced_features.get("domain_age", -1)
        dns_valid = advanced_features.get("dns_valid", 0)
        ssl_valid = advanced_features.get("ssl_valid", 0)     
        
        # ===== CALCULATE BASE RISK =====
        num_trackers = len(data.trackers)
        base_risk = min(num_trackers * 10, 40)
        
        # ===== EXTRA RISK CALCULATION =====
        extra_risk = 0
        
        # Cookie risk
        if "cookies-enabled" in data.trackers:
            extra_risk += 10
        
        # Permission risks
        if "Allowed" in data.location:
            extra_risk += 25
        elif "Requested" in data.location:
            extra_risk += 10
            
        if "Allowed" in data.camera:
            extra_risk += 25
        elif "Requested" in data.camera:
            extra_risk += 10
            
        if "Allowed" in data.microphone:
            extra_risk += 20
        elif "Requested" in data.microphone:
            extra_risk += 10
        
        # Content risks
        if data.sensitive:
            extra_risk += 20
        if data.phishing:
            extra_risk += 20
        if data.blacklisted:
            extra_risk += 40   # reduced from 60
        if data.url_phishing:
            extra_risk += 20
            

        
          # ===== SAFE DOMAIN CHECK (FIXED 🔥) =====
        url_phishing_advanced, url_risk_score = detect_url_phishing_advanced(data.url)
        brand_spoof, brand_message = detect_brand_spoofing(data.url)
        
        domain_only = data.url.split("/")[2] if "://" in data.url else data.url
        is_safe_domain = any(domain_only.endswith(d) for d in SAFE_DOMAINS)
        # ===== ADVANCED FEATURE RISK (NEW 🔥) =====
        if domain_age != -1 and domain_age < 30:
            extra_risk += 15   # new domain = risky

        if dns_valid == 0:
            extra_risk += 10   # invalid DNS

        if ssl_valid == 0 and not is_safe_domain:
            extra_risk += 15   # SSL issue
        
        if nlp_score > 0:
            extra_risk += min(20, nlp_score)
        # ===== PAGE BEHAVIOR ANALYSIS (NEW 🔥) =====

        if iframe_count > 3:
            extra_risk += 15

        if external_scripts > 5:
            extra_risk += 15

        if hidden_elements > 20:
            extra_risk += 10

        if any(word in page_text for word in ["verify account", "enter otp", "urgent action", "login now"]):
            extra_risk += 15
                    

# ✅ now safe
        if url_phishing_advanced and not is_safe_domain:
            extra_risk += min(15, url_risk_score)
        if brand_spoof:
            extra_risk += 25   # reduced
        
        # HTTPS check
        if not data.has_https:
            extra_risk += 15
        
        # Long URL
        if data.url_length > 150:
            extra_risk += 10
        
        # Many dots (subdomains)
        if data.dots > 4:
            extra_risk += 10
        
        # ===== GOOGLE SAFE BROWSING =====
        is_unsafe = check_google_safe(data.url)
        if is_unsafe:
            extra_risk += 40
            print("🚨 Google Safe Browsing: Threat detected!")
      
        if is_safe_domain:
            extra_risk = min(extra_risk, 20)
            print(f"✅ Safe domain detected: {domain_only}")
        
        # ===== ML PREDICTION (NEW 🔥) =====
        if phishing_model is not None:
            features = np.array([[
                data.url_length,
                data.dots,
                1 if data.has_https else 0,
                1 if "@" in data.url else 0,
                data.url.count('-'),
                1 if re.search(r'\d+\.\d+\.\d+\.\d+', data.url) else 0,
                1 if data.url_phishing else 0
            ]])

            ml_prediction = phishing_model.predict(features)[0]

            if ml_prediction == 1 and not is_safe_domain:
                extra_risk += 20
                print("🤖 ML detected phishing!")
        
        # ===== FINAL RISK =====
        risk = base_risk + extra_risk
        risk = max(0, min(100, risk))
        
        # ===== FINAL PHISHING DETECTION =====
        phishing_final = (
            data.phishing or 
            data.url_phishing or 
            data.blacklisted or 
            url_phishing_advanced or 
            brand_spoof or
            is_unsafe
        )
        
        # ===== GENERATE MESSAGE =====
        ai_message = generate_ai_message(risk, data, phishing_final, url_risk_score)
        
        print(f"📊 Result - Risk: {risk}%, Phishing: {phishing_final}, Trackers: {num_trackers}")
        
        return {
            "risk": risk,
            "message": ai_message,
            "phishing_detected": phishing_final,
            "url_risk_score": url_risk_score,
            "brand_spoof": brand_spoof
        }
          
    except Exception as e:
        print("❌ Analysis error:", e)
        import traceback
        traceback.print_exc()
        return {
            "risk": 50,
            "message": "Security analysis completed with fallback settings. Be cautious.",
            "phishing_detected": False
        }