from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np
import requests
import os
from dotenv import load_dotenv

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
try:
    risk_model = joblib.load("ai/model.pkl")
    phishing_model = joblib.load("ai/phishing_model.pkl")
except Exception as e:
    print("❌ Model Load Error:", e)
    risk_model = None
    phishing_model = None


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


@app.get("/")
def home():
    return {"message": "AI Backend running 🚀"}


# ===== 🧠 AI EXPLANATION =====
def generate_ai_message(risk, data: Data, phishing_flag):
    reasons = []

    # TRACKERS
    if len(data.trackers) > 3:
        reasons.append("multiple tracking scripts detected")
    elif len(data.trackers) > 0:
        reasons.append("some tracking activity detected")

    # COOKIES
    if "cookies-enabled" in data.trackers:
        reasons.append("cookies are used to monitor user behavior")

    # LOCATION
    if "Allowed" in data.location:
        reasons.append("location access is enabled")
    elif "Requested" in data.location:
        reasons.append("location access is requested")

    # CAMERA
    if "Allowed" in data.camera:
        reasons.append("camera access is enabled")

    # MICROPHONE
    if "Allowed" in data.microphone:
        reasons.append("microphone access is enabled")

    # SENSITIVE INPUT
    if data.sensitive:
        reasons.append("this page contains sensitive input fields")

    # PHISHING ML RESULT
    if phishing_flag == -1:
        reasons.append("AI model detected phishing patterns")

    # RULE-BASED PHISHING
    if data.phishing:
        reasons.append("suspicious content detected")

    # BLACKLIST
    if data.blacklisted:
        reasons.append("this domain is blacklisted")

    # URL PHISHING
    if data.url_phishing:
        reasons.append("suspicious URL pattern detected")

    # RISK LEVEL
    if risk > 80:
        level = "high risk"
    elif risk > 40:
        level = "moderate risk"
    else:
        level = "low risk"

    if reasons:
        return f"This website shows {level} because " + ", ".join(reasons) + "."
    else:
        return f"This website appears {level} with minimal risk."


def check_google_safe(url):
    API_KEY = os.getenv("GOOGLE_API_KEY")

    print("API KEY:", API_KEY)  # 🔥 check load ho rahi hai ya nahi
    print("URL CHECK:", url)

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    body = {
        "client": {"clientId": "privacy-guardian", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(endpoint, json=body)

        print("STATUS:", res.status_code)   # 🔥
        print("RESPONSE:", res.text)        # 🔥

        result = res.json()
        return "matches" in result

    except Exception as e:
        print("ERROR:", e)
        return False

# ===== MAIN ANALYSIS =====
@app.post("/analyze")
def analyze(data: Data):

    print("📥 Incoming Data:", data.dict())

    try:
        # ===== RISK MODEL INPUT =====
        
        num_trackers = len(data.trackers) 
        cookies = 1
        location = 1 if "Allowed" in data.location else 0
        camera = 1 if "Allowed" in data.camera else 0 

        X_risk = np.array([[num_trackers, cookies, location, camera]])

        # ===== BASE RISK =====
        if risk_model:
            base_risk = int(risk_model.predict(X_risk)[0])
        else:
            base_risk = num_trackers * 10

        # ===== PHISHING MODEL =====
        phishing_features = np.array([[
            num_trackers,
            1 if data.phishing else 0,
            1 if data.sensitive else 0,
            1 if data.blacklisted else 0
        ]]) 

        try:
            if phishing_model:
                phishing_result = phishing_model.predict(phishing_features)[0]
            else:
                phishing_result = 1
        except Exception as e:
            print("⚠️ Phishing Model Error:", e)
            phishing_result = 1

        # ===== EXTRA RISK =====
        extra_risk = 0

        unsafe = check_google_safe(data.url)  # better: pass actual URL later
        if "malware" in data.url or "billing" in data.url:
            extra_risk += 25

        if unsafe:
            print("🚨 GOOGLE SAFE BROWSING DETECTED THREAT")
            extra_risk += 70   # 🔥 strong boost

 
        if data.blacklisted:
            extra_risk += 50

        if data.sensitive:
            extra_risk += 20

        if data.phishing:
            extra_risk += 25

        if phishing_result == -1:
            extra_risk += 30

        if "Allowed" in data.microphone:
            extra_risk += 15

        if data.url_phishing:
            extra_risk += 30

        # URL length risk
        if data.url_length > 100:
            extra_risk += 10

        if not data.has_https:
            extra_risk += 15

        if data.dots > 3:
            extra_risk += 10

        # ===== FINAL RISK =====
        risk = base_risk + extra_risk
        risk = min(risk, 100)

        # ===== AI MESSAGE =====
        try:
            ai_message = generate_ai_message(risk, data, phishing_result)
        except Exception as e:
            print("⚠️ AI Message Error:", e)
            ai_message = "AI analysis unavailable"

        return {
            "risk": risk, 
            "message": ai_message,
            "phishing_detected": True if phishing_result == -1 else False
        }

    except Exception as e:
        print("❌ ANALYZE ERROR:", e)
        return {
            "risk": 50,
            "message": "Error analyzing website",
            "phishing_detected": False
        }