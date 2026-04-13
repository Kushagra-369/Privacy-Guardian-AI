// ===== GLOBAL AI DATA =====
let aiRisk: number | null = null;
let aiMessage: string = "";
let popupShownForSession: boolean = false;

// ===== EXTRA PAGE ANALYSIS (NEW 🔥)

// Get full page text (limited for performance)
function getPageText(): string {
    const text = document.body.innerText || "";
    return text.substring(0, 5000); // limit to avoid heavy load
}

// Count iframes (suspicious)
function getIframeCount(): number {
    return document.querySelectorAll("iframe").length;
}

// Count external scripts
function getExternalScripts(): number {
    const scripts = Array.from(document.querySelectorAll("script"));
    return scripts.filter((s: any) => s.src && !s.src.includes(location.hostname)).length;
}

// Detect hidden elements (phishing trick)
function getHiddenElements(): number {
    const elements = Array.from(document.querySelectorAll("*"));
    return elements.filter((el: any) => {
        const style = window.getComputedStyle(el);
        return style.display === "none" || style.visibility === "hidden";
    }).length;
}
const extraPageText = getPageText();
const iframeCount = getIframeCount();
const externalScripts = getExternalScripts();
const hiddenElements = getHiddenElements();
// ===== AGGRESSIVE BLACKLIST =====
const blacklist: string[] = [
    "phishing.com",
    "fakebank.xyz",
    "malicious-site.net",
    "login-verify",
    "secure-account",
    "verify-identity",
    "account-security",
    "banking-verify",
    "paypal-security",
    "amazon-verification"
];

// ===== COMPREHENSIVE SUSPICIOUS PATTERNS =====
const url = window.location.hostname.toLowerCase();
const fullUrl = window.location.href.toLowerCase();


const suspiciousPatterns: string[] = [
    "login", "secure", "verify", "account", "update", "bank",
    "signin", "auth", "authenticate", "validation", "confirm",
    "security", "alert", "warning", "unusual", "suspended",
    "limited", "restricted", "locked", "verify-now", "confirm-identity"
];

const fakeBrands: string[] = [
    "g00gle", "amaz0n", "paytm-secure", "faceboook", "instagrarn",
    "faceb00k", "twittter", "micros0ft", "app1e", "paypa1",
    "netfl1x", "whatsapp-secure", "telegram-secure", "fb-login"
];

// IP URL check
const isIP: boolean = /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(url);

// Check for @ symbol in URL (classic phishing)
const hasAtSymbol: boolean = fullUrl.includes('@');

// Check for URL shorteners
const urlShorteners: string[] = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'];
const isShortened: boolean = urlShorteners.some(s => fullUrl.includes(s));

// Check for suspicious TLDs
const suspiciousTLDs: string[] = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', '.work', '.date', '.download', '.loan', '.win'];
const hasSuspiciousTLD: boolean = suspiciousTLDs.some(tld => url.endsWith(tld));

// Suspicious words in URL
const hasSuspiciousWord: boolean = suspiciousPatterns.some(word =>
    url.includes(word) || fullUrl.includes(word)
);

// Fake brand detection
const isFakeBrand: boolean = fakeBrands.some(brand =>
    url.includes(brand) || fullUrl.includes(brand)
);

// Check for excessive subdomains
const subdomainCount: number = (url.match(/\./g) || []).length;
const excessiveSubdomains: boolean = subdomainCount > 3;

// Check for hyphens in domain
const hasHyphens: boolean = url.includes('-') && url.split('-').length > 2;

// FINAL URL PHISHING FLAG
let urlPhishing: boolean = isIP || hasSuspiciousWord || isFakeBrand ||
    hasAtSymbol || isShortened || hasSuspiciousTLD ||
    excessiveSubdomains || hasHyphens;


// ===== BRAND SIMILARITY (Levenshtein Distance) =====
const realBrands: string[] = [
    "google", "amazon", "facebook", "instagram", "paytm",
    "twitter", "linkedin", "netflix", "spotify", "microsoft",
    "apple", "paypal", "stripe", "visa", "mastercard",
    "flipkart", "ebay", "alibaba", "whatsapp", "telegram",
    "snapchat", "hdfc", "icici", "sbi", "yahoo",
    "bing", "reddit", "twitch", "discord", "tiktok",
    "uber", "ola", "zomato", "swiggy", "amazonpay",
    "googlepay", "phonepe", "freecharge", "mobikwik"
];

function similarity(a: string, b: string): number {
    let longer: string = a.length > b.length ? a : b;
    let shorter: string = a.length > b.length ? b : a;

    let longerLength: number = longer.length;
    if (longerLength === 0) return 1.0;

    function editDistance(s1: string, s2: string): number {
        let costs: number[] = [];
        for (let i = 0; i <= s1.length; i++) {
            let lastValue: number = i;
            for (let j = 0; j <= s2.length; j++) {
                if (i === 0) costs[j] = j;
                else if (j > 0) {
                    let newValue: number = costs[j - 1];
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

let brandSpoof: boolean = false;
let matchedBrand: string = "";

realBrands.forEach(brand => {
    const score: number = similarity(url, brand);
    if (score > 0.6 && url !== brand && !url.includes(brand)) {
        brandSpoof = true;
        matchedBrand = brand;
    }
});

const currentDomain: string = window.location.hostname;
const isBlacklisted: boolean = blacklist.some(domain =>
    currentDomain.includes(domain) || fullUrl.includes(domain)
);

// ===== SAFE DOMAINS =====
const SAFE_DOMAINS: string[] = [
    "google.com", "youtube.com", "leetcode.com", "github.com",
    "linkedin.com", "microsoft.com", "apple.com", "stackoverflow.com",
    "gmail.com", "drive.google.com", "docs.google.com", "wikipedia.org"
];

const isUltraSafe: boolean = SAFE_DOMAINS.some(domain =>
    currentDomain === domain || currentDomain.endsWith("." + domain)
);

// ===== AGGRESSIVE TRACKER DETECTION =====
const trackerDomains: string[] = [
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.net", "facebook.com/tr", "amazon-adsystem.com",
    "ads.", "analytics", "track", "pixel", "beacon",
    "segment.com", "mixpanel.com", "hotjar.com", "clarity.ms",
    "mathtag.com", "scorecardresearch.com", "outbrain.com",
    "taboola.com", "criteo.com", "adnxs.com", "rubiconproject.com"
];

const elements: Element[] = [
    ...Array.from(document.querySelectorAll("script")),
    ...Array.from(document.querySelectorAll("img")),
    ...Array.from(document.querySelectorAll("iframe")),
    ...Array.from(document.querySelectorAll("link")),
];

const detectedTrackers: string[] = [];

elements.forEach((el: any) => {
    const src: string = (el.src || el.href || "").toLowerCase();
    trackerDomains.forEach((domain: string) => {
        if (src.includes(domain)) {
            if (!detectedTrackers.includes(domain)) {
                detectedTrackers.push(domain);
            }
        }
    });
});

// ===== HEURISTICS =====
let heuristicTrackers: string[] = [];

if (navigator.cookieEnabled) heuristicTrackers.push("cookies-enabled");

// Check for localStorage usage
try {
    if (localStorage.length > 0) heuristicTrackers.push("localstorage-usage");
} catch (e) { }

// Check for sessionStorage
try {
    if (sessionStorage.length > 0) heuristicTrackers.push("sessionstorage-usage");
} catch (e) { }

const finalTrackers: string[] = [
    ...new Set([...detectedTrackers, ...heuristicTrackers]),
];

// ===== PERMISSIONS =====
let locationStatus: string = "Checking...";
let cameraStatus: string = "Checking...";
let microphoneStatus: string = "Checking...";

if (navigator.permissions) {
    navigator.permissions.query({ name: "geolocation" as any }).then((res: PermissionStatus) => {
        locationStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    }).catch(() => { locationStatus = "Unknown"; });

    navigator.permissions.query({ name: "camera" as any }).then((res: PermissionStatus) => {
        cameraStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    }).catch(() => { cameraStatus = "Unknown"; });

    navigator.permissions.query({ name: "microphone" as any }).then((res: PermissionStatus) => {
        microphoneStatus = res.state === "granted" ? "Allowed ✅" :
            res.state === "denied" ? "Blocked ❌" : "Requested ⚠️";
    }).catch(() => { microphoneStatus = "Unknown"; });
}

// ===== SENSITIVE INPUT DETECTION =====
let hasSensitiveForm: boolean = false;

function detectSensitiveForm(): void {
    const inputs: Element[] = Array.from(document.querySelectorAll("input, textarea, select"));

    inputs.forEach((input: any) => {
        const type: string = (input.type || "").toLowerCase();
        const name: string = (input.name || "").toLowerCase();
        const id: string = (input.id || "").toLowerCase();
        const className: string = (input.className || "").toLowerCase();
        const placeholder: string = (input.placeholder || "").toLowerCase();

        const sensitiveKeywords = [
            "password", "pass", "pwd", "email", "user", "login",
            "username", "credit", "card", "cvv", "cvc", "ssn",
            "social", "security", "bank", "account", "routing",
            "otp", "2fa", "mfa", "verification"
        ];

        for (const keyword of sensitiveKeywords) {
            if (type === "password" ||
                type === "email" ||
                name.includes(keyword) ||
                id.includes(keyword) ||
                className.includes(keyword) ||
                placeholder.includes(keyword)) {
                hasSensitiveForm = true;
                return;
            }
        }
    });

    const formText: string = document.body.innerText.toLowerCase();
    const sensitiveText = [
        "sign up", "login", "create account", "reset password",
        "forgot password", "verify account", "confirm identity",
        "payment", "credit card", "debit card", "bank transfer",
        "enter otp", "verification code", "two factor"
    ];

    for (const text of sensitiveText) {
        if (formText.includes(text)) {
            hasSensitiveForm = true;
            break;
        }
    }
}

// ===== PHISHING TEXT DETECTION =====
const pageText: string = document.body.innerText.toLowerCase();

const suspiciousWords: string[] = [
    "enter otp", "bank login", "verify account", "credit card",
    "urgent action", "verify your identity", "security alert",
    "unusual activity", "account suspended", "account locked",
    "limited access", "confirm your account", "update payment",
    "verify now", "click here to verify", "immediate action required"
];

const foundSuspicious: boolean = suspiciousWords.some(word => pageText.includes(word));

// Check for fake login forms
const hasFakeLoginForm: boolean =
    pageText.includes("login") &&
    pageText.includes("password") &&
    !pageText.includes("forgot password");

// ===== AGGRESSIVE RISK CALCULATION =====
let risk: number = 0;

function calculateRisk(): void {
    // Base tracker risk
    risk = Math.min(finalTrackers.length * 10, 50);

    // Cookie risk
    if (navigator.cookieEnabled) risk += 10;

    // Permission risks
    if (locationStatus.includes("Allowed")) risk += 35;
    else if (locationStatus.includes("Requested")) risk += 15;

    if (cameraStatus.includes("Allowed")) risk += 35;
    else if (cameraStatus.includes("Requested")) risk += 15;

    if (microphoneStatus.includes("Allowed")) risk += 30;
    else if (microphoneStatus.includes("Requested")) risk += 10;

    // Content risks
    if (hasSensitiveForm) risk += 30;
    if (foundSuspicious) risk += 35;
    if (hasFakeLoginForm) risk += 25;
    if (isBlacklisted) risk += 70;

    // URL risks
    if (urlPhishing) risk += 40;
    if (brandSpoof) risk += 50;
    if (hasAtSymbol) risk += 30;
    if (isShortened) risk += 20;
    if (hasSuspiciousTLD) risk += 25;
    if (excessiveSubdomains) risk += 15;

    // Malware mentions
    const malwareKeywords = ["malware", "virus", "trojan", "ransomware", "spyware", "adware"];
    for (const keyword of malwareKeywords) {
        if (pageText.includes(keyword)) {
            risk += 30;
            break;
        }
    }

    // Check for HTTPS
    if (window.location.protocol !== "https:") {
        risk += 25;
    }

    // Reduce risk for ultra-safe domains
    if (isUltraSafe) {
        risk = Math.min(risk, 20); // 🔥 HARD CAP
    }
    // Clamp risk
    risk = Math.min(100, Math.max(0, risk));

    console.log(`📊 Risk Calculation: ${risk}% | Trackers: ${finalTrackers.length} | URL Phishing: ${urlPhishing} | Brand Spoof: ${brandSpoof}`);
}

// ===== STORAGE KEYS =====
const STORAGE_KEY_CONTINUE: string = "pgai_continue_permission";
const STORAGE_KEY_HISTORY: string = "history";

interface ContinueData {
    [key: string]: boolean;
}

async function hasUserContinued(): Promise<boolean> {
    return new Promise((resolve) => {
        chrome.storage.local.get([STORAGE_KEY_CONTINUE], (res) => {
            const continueData: ContinueData = (res[STORAGE_KEY_CONTINUE] as ContinueData) || {};
            resolve(!!continueData[currentDomain]);
        });
    });
}

async function setUserContinued(domain: string): Promise<void> {
    return new Promise((resolve) => {
        chrome.storage.local.get([STORAGE_KEY_CONTINUE], (res) => {
            const continueData: ContinueData = (res[STORAGE_KEY_CONTINUE] as ContinueData) || {};
            continueData[domain] = true;
            chrome.storage.local.set({ [STORAGE_KEY_CONTINUE]: continueData }, () => {
                resolve();
            });
        });
    });
}

interface HistoryItem {
    url: string;
    risk: number;
    time: string;
}

function addToHistory(): void {
    chrome.storage.local.get([STORAGE_KEY_HISTORY], (res) => {
        let history: HistoryItem[] = (res.history as HistoryItem[]) || [];
        if (history.length > 100) history = history.slice(-100);
        history.push({
            url: window.location.hostname,
            risk: Math.round(risk),
            time: new Date().toLocaleString()
        });
        chrome.storage.local.set({ [STORAGE_KEY_HISTORY]: history });
    });
}

// ===== POPUP FUNCTIONS =====

function showSmallNotification(): void {
    if (document.getElementById("pgai-notification")) return;

    const notification: HTMLDivElement = document.createElement("div");
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
        <span>🛡️ Risk: <strong style="color: ${risk > 30 ? '#facc15' : '#22c55e'};">${Math.round(risk)}%</strong></span>
        <button id="pgai-view-more" style="
            background: #3b82f6;
            border: none;
            color: white;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        ">Details</button>
        <button id="pgai-notification-close" style="
            background: transparent;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            font-size: 16px;
            padding: 0 0 0 8px;
        ">✕</button>
    `;

    document.body.appendChild(notification);

    document.getElementById("pgai-view-more")?.addEventListener("click", () => {
        notification.remove();
        showBigPopup(false, false);
    });

    document.getElementById("pgai-notification-close")?.addEventListener("click", () => {
        notification.remove();
    });

    setTimeout(() => {
        const notif = document.getElementById("pgai-notification");
        if (notif) {
            notif.style.opacity = "0";
            setTimeout(() => notif.remove(), 300);
        }
    }, 10000);
}

function showBigPopup(showCancelContinue: boolean, isBlockedFlow: boolean = false): void {
    if (document.getElementById("pgai-overlay")) return;

    const overlay: HTMLDivElement = document.createElement("div");
    overlay.id = "pgai-overlay";
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.9);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 999999;
    `;

    const popup: HTMLDivElement = document.createElement("div");
    popup.style.cssText = `
        background: #0f172a;
        color: white;
        padding: 25px;
        border-radius: 16px;
        width: 450px;
        max-width: 90%;
        font-family: Arial, sans-serif;
        position: relative;
        border: 1px solid ${risk > 60 ? '#ef4444' : risk > 30 ? '#facc15' : '#22c55e'};
    `;

    const closeBtn: HTMLSpanElement = document.createElement("span");
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

    let buttonsHtml: string = "";
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
                    font-weight: bold;
                ">🚫 Leave Site</button>
                <button id="pgai-continue" style="
                    background: #22c55e;
                    border: none;
                    color: white;
                    padding: 10px;
                    border-radius: 8px;
                    cursor: pointer;
                    flex: 1;
                    font-weight: bold;
                ">⚠️ Continue Anyway</button>
            </div>
        `;
    } else if (isBlockedFlow) {
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
                    font-weight: bold;
                ">← Go Back to Safety</button>
            </div>
        `;
    }

    const riskColor = risk > 60 ? '#ef4444' : risk > 30 ? '#facc15' : '#22c55e';
    const riskWarning = risk > 60 ? '🚨 HIGH RISK' : risk > 30 ? '⚠️ MODERATE RISK' : '✅ LOW RISK';

    popup.innerHTML = `
        <h2 style="margin-top: 0;">🛡️ Privacy Guardian AI</h2>
        <p style="font-size: 12px; color: #94a3b8;">Security Analysis Report</p>
        
        <hr/>
        
        <p><b>🌐 Site:</b> ${window.location.hostname}</p>
        <p><b>📊 Risk Score:</b> <strong style="color: ${riskColor}; font-size: 18px;">${Math.round(risk)}%</strong> - ${riskWarning}</p>
        
        ${isBlacklisted ? '<p><b>🚨 BLACKLISTED:</b> This domain is in our blocklist!</p>' : ''}
        ${brandSpoof ? `<p><b>🎭 BRAND SPOOFING:</b> This site may be impersonating "${matchedBrand}"!</p>` : ''}
        
        <hr/>
        
        <p><b>🔍 Trackers Found:</b> ${finalTrackers.length > 0 ? finalTrackers.length + " (" + finalTrackers.slice(0, 3).join(", ") + (finalTrackers.length > 3 ? "...)" : ")") : "None"}</p>
        
        <p><b>🔐 HTTPS:</b> ${window.location.protocol === "https:" ? "✅ Yes" : "❌ No"}</p>
        <p><b>🍪 Cookies:</b> ${navigator.cookieEnabled ? "Enabled" : "Disabled"}</p>
        
        <hr/>
        
        <p><b>📍 Location:</b> ${locationStatus}</p>
        <p><b>📷 Camera:</b> ${cameraStatus}</p>
        <p><b>🎤 Microphone:</b> ${microphoneStatus}</p>
        
        <hr/>
        
        <p><b>📝 Sensitive Form:</b> ${hasSensitiveForm ? "⚠️ Detected" : "None"}</p>
        <p><b>🎣 Phishing Content:</b> ${foundSuspicious ? "🚨 Detected" : "None"}</p>
        <p><b>🔗 Suspicious URL:</b> ${urlPhishing ? "⚠️ Yes" : "No"}</p>
        
        <hr/>
        
        <div style="padding: 10px; background: #1e293b; border-radius: 10px; margin: 10px 0;">
            <b>🤖 AI Analysis:</b><br/>
            <span id="ai-text" style="font-size: 13px;">${aiMessage || "Analyzing site security..."}</span>
        </div>
        ${buttonsHtml}
    `;

    overlay.appendChild(popup);
    document.body.appendChild(overlay);

    setTimeout(() => {
        const aiText = document.getElementById("ai-text");
        if (aiText && aiMessage) aiText.innerText = aiMessage;
    }, 300);

    closeBtn.onclick = () => overlay.remove();

    if (showCancelContinue && !isBlockedFlow) {
        document.getElementById("pgai-cancel")?.addEventListener("click", () => {
            window.history.back();
        });
        document.getElementById("pgai-continue")?.addEventListener("click", async () => {
            overlay.remove();
            await setUserContinued(currentDomain);
        });
    }

    if (isBlockedFlow) {
        document.getElementById("pgai-go-back")?.addEventListener("click", () => {
            window.history.back();
        });
    }
}

function showBlockedScreen(): void {
    document.body.innerHTML = `
        <div style="
            display:flex;
            justify-content:center;
            align-items:center;
            height:100vh;
            background: linear-gradient(135deg, #2d0000 0%, #1a0000 100%);
            color:#ffcccc;
            font-family:Arial, sans-serif;
            text-align:center;
        ">
            <div style="background:#4a0000; padding:40px; border-radius:20px; border: 3px solid #ff4444;">
                <h1 style="font-size: 32px;">🚨 ACCESS BLOCKED</h1>
                <p style="font-size: 20px; margin: 20px 0;">This website is <strong>HIGHLY DANGEROUS</strong></p>
                <p style="font-size: 16px;">Risk Score: <strong style="color: #ff4444; font-size: 24px;">${Math.round(risk)}%</strong></p>
                <p style="font-size: 14px; margin-top: 20px;">⚠️ This site has been flagged for:</p>
                <ul style="text-align: left; margin: 10px 0;">
                    ${isBlacklisted ? '<li>🚨 Blacklisted domain</li>' : ''}
                    ${brandSpoof ? '<li>🎭 Brand spoofing detected</li>' : ''}
                    ${urlPhishing ? '<li>🔗 Suspicious URL pattern</li>' : ''}
                    ${foundSuspicious ? '<li>🎣 Phishing content detected</li>' : ''}
                </ul>
                <p style="font-size: 14px;">To protect your privacy and security, access has been automatically blocked.</p>
                <button id="pgai-blocked-back" style="
                    margin-top: 30px;
                    background: #ff4444;
                    border: none;
                    color: white;
                    padding: 14px 28px;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 16px;
                    font-weight: bold;
                ">← Go Back to Safety</button>
            </div>
        </div>
    `;

    document.getElementById("pgai-blocked-back")?.addEventListener("click", () => {
        window.history.back();
    });
}

// ===== AUTO FORM WARNING =====
document.addEventListener("submit", function (e: Event) {
    if (risk > 50 && !isUltraSafe) {
        e.preventDefault();
        alert(`⚠️ SECURITY WARNING!\n\nThis site has a ${Math.round(risk)}% risk score.\n\nDo NOT enter any passwords, credit cards, or personal information!\n\nWe strongly recommend leaving this site.`);
    }
});

// ===== MAIN EXECUTION =====
window.addEventListener("load", async () => {

    detectSensitiveForm();
    calculateRisk();

    console.log(`🔍 Security Check for: ${currentDomain}`);
    console.log(`📊 Local Risk: ${risk}%`);

    try {
        const response = await fetch("http://127.0.0.1:8000/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
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
                dots: subdomainCount,
                url: window.location.href,
                page_text: extraPageText,
                iframe_count: iframeCount,
                external_scripts: externalScripts,
                hidden_elements: hiddenElements,
            }),
        });

        const result = await response.json();
        aiRisk = result.risk;
        aiMessage = result.message;

        if (aiRisk !== null) {
            risk = Math.min(100, (risk * 0.6) + (aiRisk * 0.4));
        }

        console.log(`🎯 Final Risk: ${Math.round(risk)}%`);

        risk = Math.round(risk); // 🔥 IMPORTANT

        if (isBlacklisted || (risk >= 85 && urlPhishing)) {
            showBlockedScreen();
        }

     

        if (risk >= 50) {
            showBigPopup(true, false);
        }
        else if (risk >= 20) {
            showSmallNotification();
        }

        console.log("👉 Risk value:", risk);

        if (risk >= 50) {
            console.log("🔥 SHOULD SHOW POPUP");
        }
    } catch (error) {
        console.error("AI Analysis failed:", error);
    }

});