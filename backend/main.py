from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import numpy as np

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
risk_model = joblib.load("ai/model.pkl")
phishing_model = joblib.load("ai/phishing_model.pkl")  # 🔥 NEW MODEL


# ===== REQUEST MODEL =====
class Data(BaseModel):
    trackers: list
    location: str
    camera: str
    microphone: str
    sensitive: bool
    phishing: bool
    blacklisted: bool


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


# ===== MAIN ANALYSIS =====
@app.post("/analyze")
def analyze(data: Data):

    # ===== RISK MODEL INPUT =====
    num_trackers = len(data.trackers)
    cookies = 1
    location = 1 if "Allowed" in data.location else 0
    camera = 1 if "Allowed" in data.camera else 0

    X_risk = np.array([[num_trackers, cookies, location, camera]])

    # ===== BASE RISK =====
    base_risk = int(risk_model.predict(X_risk)[0])

    # ===== PHISHING MODEL INPUT (SIMPLIFIED FEATURES) =====
    phishing_features = np.array([[
        num_trackers,
        1 if data.phishing else 0,
        1 if data.sensitive else 0,
        1 if data.blacklisted else 0
    ]])

    try:
        phishing_result = phishing_model.predict(phishing_features)[0]
    except:
        phishing_result = 1  # fallback safe

    # ===== EXTRA RISK =====
    extra_risk = 0

    if data.blacklisted:
        extra_risk += 50

    if data.sensitive:
        extra_risk += 20

    if data.phishing:
        extra_risk += 25

    if phishing_result == -1:  # ML phishing detection
        extra_risk += 30

    if "Allowed" in data.microphone:
        extra_risk += 15

    # ===== FINAL RISK =====
    risk = base_risk + extra_risk
    if risk > 100:
        risk = 100

    # ===== AI MESSAGE =====
    ai_message = generate_ai_message(risk, data, phishing_result)

    return {
        "risk": risk,
        "message": ai_message,
        "phishing_detected": True if phishing_result == -1 else False
    } 