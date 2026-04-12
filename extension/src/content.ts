// ===== GLOBAL AI DATA =====
let aiRisk: number | null = null;
let aiMessage: string = "";

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
const hasSuspiciousWord = suspiciousPatterns.some(word =>
    url.includes(word)
);

// fake brand detection
const isFakeBrand = fakeBrands.some(brand =>
    url.includes(brand)
);

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

function similarity(a: string, b: string) {
    let longer = a.length > b.length ? a : b;
    let shorter = a.length > b.length ? b : a;

    let longerLength = longer.length;
    if (longerLength === 0) return 1.0;

    function editDistance(s1: string, s2: string) {
        let costs = [];
        for (let i = 0; i <= s1.length; i++) {
            let lastValue = i;
            for (let j = 0; j <= s2.length; j++) {
                if (i === 0) costs[j] = j;
                else if (j > 0) {
                    let newValue = costs[j - 1];
                    if (s1.charAt(i - 1) !== s2.charAt(j - 1))
                        newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                    costs[j - 1] = lastValue;
                    lastValue = newValue;
                }
            }
            if (i > 0) costs[s2.length] = lastValue;
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
const isBlacklisted = blacklist.some(domain =>
    currentDomain.includes(domain)
);

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

const detectedTrackers: string[] = [];

elements.forEach((el: any) => {
    const src = el.src || el.href || "";
    trackerDomains.forEach((domain) => {
        if (src.includes(domain)) {
            detectedTrackers.push(domain);
        }
    });
});

// ===== HEURISTICS =====
let heuristicTrackers: string[] = [];

if (navigator.cookieEnabled) heuristicTrackers.push("cookies-enabled");

const finalTrackers = [
    ...new Set([...detectedTrackers, ...heuristicTrackers]),
];

// ===== PERMISSIONS =====
let locationStatus = "Checking...";
let cameraStatus = "Checking...";
let microphoneStatus = "Checking...";

if (navigator.permissions) {
    navigator.permissions.query({ name: "geolocation" as PermissionName }).then(res => {
        locationStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    });

    navigator.permissions.query({ name: "camera" as PermissionName }).then(res => {
        cameraStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    });

    navigator.permissions.query({ name: "microphone" as PermissionName }).then(res => {
        microphoneStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    });
}

// ===== SENSITIVE INPUT =====
let hasSensitiveForm = false;

function detectSensitiveForm() {
    const inputs = Array.from(document.querySelectorAll("input"));

    inputs.forEach((input: any) => {
        const type = (input.type || "").toLowerCase();
        const name = (input.name || "").toLowerCase();
        const placeholder = (input.placeholder || "").toLowerCase();

        if (
            type === "password" ||
            type === "email" ||
            name.includes("user") ||
            name.includes("login") ||
            name.includes("email") ||
            name.includes("pass") ||
            placeholder.includes("password") ||
            placeholder.includes("email")
        ) {
            hasSensitiveForm = true;
        }
    });

    const formText = document.body.innerText.toLowerCase();

    if (
        formText.includes("sign up") ||
        formText.includes("login") ||
        formText.includes("create account")
    ) {
        hasSensitiveForm = true;
    }
}

setTimeout(() => {
    detectSensitiveForm();

    // 🔥 RECALCULATE RISK AFTER DETECTION
    calculateRisk();

}, 2000);
// 🔥 RUN AFTER DELAY (IMPORTANT)

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
    risk = finalTrackers.length * 20;

    if (navigator.cookieEnabled) risk += 10;
    if (locationStatus.includes("Allowed")) risk += 25;
    if (cameraStatus.includes("Allowed")) risk += 25;
    if (microphoneStatus.includes("Allowed")) risk += 20;

    if (hasSensitiveForm) risk += 20;
    if (foundSuspicious) risk += 25;
    if (isBlacklisted) risk += 50;
    if (urlPhishing) risk += 30;
    if (brandSpoof) risk += 40;

    if (risk > 100) risk = 100;
}

setTimeout(() => {

    fetch("http://127.0.0.1:8000/analyze", {
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
    })
        .then(res => res.json())
        .then(result => {
            aiRisk = result.risk;
            aiMessage = result.message || "No AI analysis available";

            showPopup(); // 🔥 correct place
        })
        .catch(() => { });

}, 2200);


// ===== AUTO FORM WARNING 🔥 =====
document.addEventListener("submit", function (e) {
    if (risk > 60) {
        e.preventDefault();
        alert("⚠️ Risky site! Do not enter sensitive data.");
    }
});

// ===== HISTORY TRACKING 🔥 =====
type HistoryItem = {
    url: string;
    risk: number;
    time: string;
};

chrome.storage.local.get(["history"], (res: { history?: HistoryItem[] }) => {
    let history: HistoryItem[] = res.history || [];

    history.push({
        url: window.location.hostname,
        risk: risk,
        time: new Date().toLocaleString()
    });

    chrome.storage.local.set({ history });
});


function showPopup() {
    if (document.getElementById("pgai-overlay")) return;

    if (aiRisk !== null) risk = aiRisk;
    else calculateRisk();

    // ===== AUTO BLOCK =====
    if (isBlacklisted || risk > 85) {
        document.body.innerHTML = `
            <div style="
                display:flex;
                justify-content:center;
                align-items:center;
                height:100vh;
                background:black;
                color:white;
                font-family:Arial;
                text-align:center;
            ">
                <div>
                    <h1>🚨 BLOCKED: Unsafe Website</h1>
                    <p>This site is flagged as dangerous.</p>
                </div>
            </div>
        `;
        return;
    }

    const overlay = document.createElement("div");
    overlay.id = "pgai-overlay";
    overlay.style.cssText = `
        position:fixed;top:0;left:0;width:100%;height:100%;
        background:rgba(0,0,0,0.85);
        display:flex;justify-content:center;align-items:center;
        z-index:999999;
    `;

    const popup = document.createElement("div");
    popup.style.cssText = `
        background:#0f172a;color:white;padding:25px;
        border-radius:16px;width:420px;font-family:Arial;
    `;

    popup.innerHTML = `
        <h2>🛡️ Privacy Guardian AI</h2>

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

        <button id="closeBtn" style="margin-top:10px;">Close</button>
    `;

    overlay.appendChild(popup);
    document.body.appendChild(overlay);

    setTimeout(() => {
        const aiText = document.getElementById("ai-text");
        if (aiText && aiMessage) aiText.innerText = aiMessage;
    }, 300);

    document.getElementById("closeBtn")?.addEventListener("click", () => {
        overlay.remove();
    });
}