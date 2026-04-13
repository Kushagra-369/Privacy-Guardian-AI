"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// ===== GLOBAL AI DATA =====
let aiRisk = null;
let aiMessage = "";
// ===== BLACKLIST =====
const blacklist = [
    "phishing.com",
    "fakebank.xyz",
    "malicious-site.net"
];
// ===== URL PHISHING DETECTION 🔥 =====
const url = window.location.hostname.toLowerCase();
const suspiciousPatterns = [
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "bank"
];
const fakeBrands = [
    "g00gle",
    "amaz0n",
    "paytm-secure",
    "faceboook",
    "instagrarn"
];
// IP URL check
const isIP = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(url);
// suspicious words
const hasSuspiciousWord = suspiciousPatterns.some(word => url.includes(word));
// fake brand detection
const isFakeBrand = fakeBrands.some(brand => url.includes(brand));
// FINAL FLAG
const urlPhishing = isIP || hasSuspiciousWord || isFakeBrand;
// ===== BRAND SIMILARITY 🔥 =====
const realBrands = [
    "google", "amazon", "facebook", "instagram", "paytm",
    "twitter", "linkedin", "netflix", "spotify", "microsoft",
    "apple", "paypal", "stripe", "visa", "mastercard",
    "flipkart", "ebay", "alibaba", "whatsapp", "telegram",
    "snapchat", "hdfc", "icici", "sbi", "yahoo",
    "bing", "reddit", "twitch", "discord", "tiktok",
    "uber", "ola", "zomato", "swiggy", "amazonpay",
    "googlepay", "phonepe", "freecharge", "mobikwik"
];
function similarity(a, b) {
    let longer = a.length > b.length ? a : b;
    let shorter = a.length > b.length ? b : a;
    let longerLength = longer.length;
    if (longerLength === 0)
        return 1.0;
    function editDistance(s1, s2) {
        let costs = [];
        for (let i = 0; i <= s1.length; i++) {
            let lastValue = i;
            for (let j = 0; j <= s2.length; j++) {
                if (i === 0)
                    costs[j] = j;
                else if (j > 0) {
                    let newValue = costs[j - 1];
                    if (s1.charAt(i - 1) !== s2.charAt(j - 1))
                        newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                    costs[j - 1] = lastValue;
                    lastValue = newValue;
                }
            }
            if (i > 0)
                costs[s2.length] = lastValue;
        }
        return costs[s2.length];
    }
    return (longerLength - editDistance(longer, shorter)) / longerLength;
}
let brandSpoof = false;
realBrands.forEach(brand => {
    const score = similarity(url, brand);
    if (score > 0.6 && url !== brand) {
        brandSpoof = true;
    }
});
const currentDomain = window.location.hostname;
const isBlacklisted = blacklist.some(domain => currentDomain.includes(domain));
// ===== TRACKERS =====
const trackerDomains = [
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.net",
    "amazon-adsystem.com",
    "ads.",
];
const elements = [
    ...Array.from(document.querySelectorAll("script")),
    ...Array.from(document.querySelectorAll("img")),
    ...Array.from(document.querySelectorAll("iframe")),
    ...Array.from(document.querySelectorAll("link")),
];
const detectedTrackers = [];
elements.forEach((el) => {
    const src = el.src || el.href || "";
    trackerDomains.forEach((domain) => {
        if (src.includes(domain)) {
            detectedTrackers.push(domain);
        }
    });
});
// ===== HEURISTICS =====
let heuristicTrackers = [];
if (navigator.cookieEnabled)
    heuristicTrackers.push("cookies-enabled");
const finalTrackers = [
    ...new Set([...detectedTrackers, ...heuristicTrackers]),
];
// ===== PERMISSIONS =====
let locationStatus = "Checking...";
let cameraStatus = "Checking...";
let microphoneStatus = "Checking...";
// Use 'any' to avoid conflict with lib.dom.d.ts PermissionName
if (navigator.permissions) {
    navigator.permissions.query({ name: "geolocation" }).then((res) => {
        locationStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    }).catch(() => { });
    navigator.permissions.query({ name: "camera" }).then((res) => {
        cameraStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    }).catch(() => { });
    navigator.permissions.query({ name: "microphone" }).then((res) => {
        microphoneStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    }).catch(() => { });
}
// ===== SENSITIVE INPUT =====
let hasSensitiveForm = false;
function detectSensitiveForm() {
    const inputs = Array.from(document.querySelectorAll("input"));
    inputs.forEach((input) => {
        const type = (input.type || "").toLowerCase();
        const name = (input.name || "").toLowerCase();
        const placeholder = (input.placeholder || "").toLowerCase();
        if (type === "password" ||
            type === "email" ||
            name.includes("user") ||
            name.includes("login") ||
            name.includes("email") ||
            name.includes("pass") ||
            placeholder.includes("password") ||
            placeholder.includes("email")) {
            hasSensitiveForm = true;
        }
    });
    const formText = document.body.innerText.toLowerCase();
    if (formText.includes("sign up") ||
        formText.includes("login") ||
        formText.includes("create account")) {
        hasSensitiveForm = true;
    }
}
// ===== PHISHING TEXT =====
const pageText = document.body.innerText.toLowerCase();
const suspiciousWords = [
    "enter otp",
    "bank login",
    "verify account",
    "credit card",
    "urgent action",
];
const foundSuspicious = suspiciousWords.some(word => pageText.includes(word));
// ===== RISK =====
let risk = 0;
function calculateRisk() {
    risk = finalTrackers.length * 25;
    if (navigator.cookieEnabled)
        risk += 10;
    if (locationStatus.includes("Allowed"))
        risk += 25;
    if (cameraStatus.includes("Allowed"))
        risk += 25;
    if (microphoneStatus.includes("Allowed"))
        risk += 20;
    // 🔥 NEW — permission requested bhi risky hai
    if (locationStatus.includes("Requested"))
        risk += 10;
    if (cameraStatus.includes("Requested"))
        risk += 10;
    if (microphoneStatus.includes("Requested"))
        risk += 10;
    if (hasSensitiveForm)
        risk += 20;
    if (foundSuspicious)
        risk += 25;
    if (isBlacklisted)
        risk += 50;
    if (urlPhishing)
        risk += 30;
    if (brandSpoof)
        risk += 40;
    if (pageText.includes("malware") || pageText.includes("virus")) {
        risk += 25;
    }
    if (pageText.includes("download") && pageText.includes("malware")) {
        risk += 20;
    }
    if (risk > 100)
        risk = 100;
}
// ===== STORAGE KEYS =====
const STORAGE_KEY_CONTINUE = "pgai_continue_permission";
const STORAGE_KEY_HISTORY = "history";
// Check if user has already chosen "Continue" for this domain
function hasUserContinued() {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve) => {
            chrome.storage.local.get([STORAGE_KEY_CONTINUE], (res) => {
                const continueData = res[STORAGE_KEY_CONTINUE] || {};
                resolve(!!continueData[currentDomain]);
            });
        });
    });
}
function setUserContinued(domain) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve) => {
            chrome.storage.local.get([STORAGE_KEY_CONTINUE], (res) => {
                const continueData = res[STORAGE_KEY_CONTINUE] || {};
                continueData[domain] = true;
                chrome.storage.local.set({ [STORAGE_KEY_CONTINUE]: continueData }, () => {
                    resolve();
                });
            });
        });
    });
}
function addToHistory() {
    chrome.storage.local.get([STORAGE_KEY_HISTORY], (res) => {
        let history = res.history || [];
        history.push({
            url: window.location.hostname,
            risk: risk,
            time: new Date().toLocaleString()
        });
        chrome.storage.local.set({ [STORAGE_KEY_HISTORY]: history });
    });
}
// ===== POPUP FUNCTIONS =====
function showSmallNotification() {
    if (document.getElementById("pgai-notification"))
        return;
    const notification = document.createElement("div");
    notification.id = "pgai-notification";
    notification.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #1e293b;
        color: white;
        padding: 12px 20px;
        border-radius: 12px;
        font-family: Arial, sans-serif;
        font-size: 14px;
        z-index: 999998;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        display: flex;
        align-items: center;
        gap: 12px;
        transition: opacity 0.3s;
    `;
    notification.innerHTML = `
        <span>🛡️ Risk: <strong style="color: #facc15;">${risk}%</strong></span>
        <button id="pgai-view-more" style="
            background: #3b82f6;
            border: none;
            color: white;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        ">View More</button>
        <button id="pgai-notification-close" style="
            background: transparent;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            font-size: 16px;
            padding: 0;
            margin-left: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
        ">✕</button>
    `;
    document.body.appendChild(notification);
    const viewMoreBtn = document.getElementById("pgai-view-more");
    if (viewMoreBtn) {
        viewMoreBtn.addEventListener("click", () => {
            notification.remove();
            showBigPopup(false, false);
        });
    }
    const closeBtn = document.getElementById("pgai-notification-close");
    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            notification.remove();
        });
    }
    // Auto hide after 8 seconds
    setTimeout(() => {
        const notif = document.getElementById("pgai-notification");
        if (notif) {
            notif.style.opacity = "0";
            setTimeout(() => notif.remove(), 300);
        }
    }, 8000);
}
function showBigPopup(showCancelContinue, isBlockedFlow = false) {
    if (document.getElementById("pgai-overlay"))
        return;
    const overlay = document.createElement("div");
    overlay.id = "pgai-overlay";
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.85);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 999999;
    `;
    const popup = document.createElement("div");
    popup.style.cssText = `
        background: #0f172a;
        color: white;
        padding: 25px;
        border-radius: 16px;
        width: 420px;
        font-family: Arial, sans-serif;
        position: relative;
    `;
    // Add close button (X) at top right
    const closeBtn = document.createElement("span");
    closeBtn.innerHTML = "✕";
    closeBtn.style.cssText = `
        position: absolute;
        top: 15px;
        right: 20px;
        font-size: 20px;
        cursor: pointer;
        color: #94a3b8;
    `;
    popup.appendChild(closeBtn);
    let buttonsHtml = "";
    if (showCancelContinue && !isBlockedFlow) {
        buttonsHtml = `
            <div style="display: flex; gap: 12px; margin-top: 20px;">
                <button id="pgai-cancel" style="
                    background: #ef4444;
                    border: none;
                    color: white;
                    padding: 10px;
                    border-radius: 8px;
                    cursor: pointer;
                    flex: 1;
                ">Cancel & Go Back</button>
                <button id="pgai-continue" style="
                    background: #22c55e;
                    border: none;
                    color: white;
                    padding: 10px;
                    border-radius: 8px;
                    cursor: pointer;
                    flex: 1;
                ">Continue Anyway</button>
            </div>
        `;
    }
    else if (isBlockedFlow) {
        buttonsHtml = `
            <div style="display: flex; gap: 12px; margin-top: 20px;">
                <button id="pgai-go-back" style="
                    background: #ef4444;
                    border: none;
                    color: white;
                    padding: 12px;
                    border-radius: 8px;
                    cursor: pointer;
                    width: 100%;
                    font-size: 16px;
                ">← Go Back to Safety</button>
            </div>
        `;
    }
    popup.innerHTML = `
        <h2 style="margin-top: 0;">🛡️ Privacy Guardian AI</h2>

        <p><b>Site:</b> ${window.location.hostname}</p>
        <p><b>Risk:</b> ${risk}%</p>
        <p><b>Blacklist:</b> ${isBlacklisted ? "Yes 🚨" : "No"}</p>

        <p><b>Trackers:</b> ${finalTrackers.join(", ") || "None"}</p>

        <hr/>

        <p><b>Cookies:</b> ${navigator.cookieEnabled}</p>
        <p><b>Location:</b> ${locationStatus}</p>
        <p><b>Camera:</b> ${cameraStatus}</p>
        <p><b>Microphone:</b> ${microphoneStatus}</p>

        <hr/>

        <p><b>Sensitive Form:</b> ${hasSensitiveForm ? "Detected ⚠️" : "None"}</p>
        <p><b>Phishing Signals:</b> ${foundSuspicious ? "Detected 🚨" : "None"}</p>

        <hr/>

        <div style="padding:10px;background:#1e293b;border-radius:10px;">
            <b>🤖 AI Analysis:</b><br/>
            <span id="ai-text">${aiMessage ? aiMessage : "Analyzing..."}</span>
        </div>
        ${buttonsHtml}
    `;
    overlay.appendChild(popup);
    document.body.appendChild(overlay);
    // Update AI text later if needed
    setTimeout(() => {
        const aiText = document.getElementById("ai-text");
        if (aiText && aiMessage)
            aiText.innerText = aiMessage;
    }, 300);
    // Close button (X) behavior
    closeBtn.onclick = () => {
        overlay.remove();
    };
    if (showCancelContinue && !isBlockedFlow) {
        const cancelBtn = document.getElementById("pgai-cancel");
        const continueBtn = document.getElementById("pgai-continue");
        if (cancelBtn) {
            cancelBtn.addEventListener("click", () => {
                window.history.back();
            });
        }
        if (continueBtn) {
            continueBtn.addEventListener("click", () => __awaiter(this, void 0, void 0, function* () {
                overlay.remove();
                yield setUserContinued(currentDomain);
            }));
        }
    }
    if (isBlockedFlow) {
        const goBackBtn = document.getElementById("pgai-go-back");
        if (goBackBtn) {
            goBackBtn.addEventListener("click", () => {
                window.history.back();
            });
        }
    }
}
function showBlockedScreen() {
    document.body.innerHTML = `
        <div style="
            display:flex;
            justify-content:center;
            align-items:center;
            height:100vh;
            background:#2d0000;
            color:#ffcccc;
            font-family:Arial, sans-serif;
            text-align:center;
        ">
            <div style="background:#4a0000; padding:40px; border-radius:20px; border: 2px solid #ff4444;">
                <h1>🚨 ACCESS BLOCKED</h1>
                <p style="font-size:18px;">This website is highly dangerous (Risk > 75%)</p>
                <p style="font-size:14px; margin-top:20px;">To protect your privacy and security, access has been automatically blocked.</p>
                <button id="pgai-blocked-back" style="
                    margin-top:30px;
                    background:#ff4444;
                    border:none;
                    color:white;
                    padding:12px 24px;
                    border-radius:8px;
                    cursor:pointer;
                    font-size:16px;
                ">← Go Back to Safety</button>
            </div>
        </div>
    `;
    const backBtn = document.getElementById("pgai-blocked-back");
    if (backBtn) {
        backBtn.addEventListener("click", () => {
            window.history.back();
        });
    }
}
// ===== AUTO FORM WARNING 🔥 =====
document.addEventListener("submit", function (e) {
    if (risk > 60) {
        e.preventDefault();
        alert("⚠️ Risky site! Do not enter sensitive data.");
    }
});
// ===== MAIN EXECUTION =====
setTimeout(() => __awaiter(void 0, void 0, void 0, function* () {
    detectSensitiveForm();
    calculateRisk();
    // Send data to AI
    try {
        const response = yield fetch("http://127.0.0.1:8000/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                trackers: finalTrackers,
                location: locationStatus,
                camera: cameraStatus,
                microphone: microphoneStatus,
                sensitive: hasSensitiveForm,
                phishing: foundSuspicious,
                blacklisted: isBlacklisted,
                url_phishing: urlPhishing,
                url_length: window.location.href.length,
                has_https: window.location.protocol === "https:",
                dots: (window.location.hostname.match(/\./g) || []).length,
                url: window.location.href
            }),
        });
        const result = yield response.json();
        aiRisk = result.risk;
        aiMessage = result.message || "No AI analysis available";
        // Recalculate risk with AI data if needed
        if (aiRisk !== null)
            risk = aiRisk;
        else
            calculateRisk();
        addToHistory();
        // ===== DECISION TREE =====
        if (isBlacklisted || risk > 75) {
            showBlockedScreen();
            return;
        }
        // Check if user already clicked "Continue" for this domain
        const userContinued = yield hasUserContinued();
        if (userContinued) {
            // User chose to continue previously, no popup
            return;
        }
        if (risk >= 40 && risk <= 75) {
            // Show big popup with Cancel/Continue buttons
            showBigPopup(true, false);
        }
        else if (risk < 40) {
            // Show small notification at bottom right
            showSmallNotification();
        }
    }
    catch (error) {
        // If AI fails, still show based on local risk
        addToHistory();
        if (isBlacklisted || risk > 75) {
            showBlockedScreen();
            return;
        }
        const userContinued = yield hasUserContinued();
        if (userContinued)
            return;
        if (risk >= 40 && risk <= 75) {
            showBigPopup(true, false);
        }
        else if (risk < 40) {
            showSmallNotification();
        }
    }
}), 2200);
