// ===== EXTRA PAGE ANALYSIS (NEW 🔥)
// Get full page text (limited for performance)
export function getPageText() {
    const text = document.body.innerText || "";
    return text.substring(0, 5000); // limit to avoid heavy load
}
// Count iframes (suspicious)
export function getIframeCount() {
    return document.querySelectorAll("iframe").length;
}
// Count external scripts
export function getExternalScripts() {
    const scripts = Array.from(document.querySelectorAll("script"));
    return scripts.filter((s) => s.src && !s.src.includes(location.hostname)).length;
}
// Detect hidden elements (phishing trick)
export function getHiddenElements() {
    const elements = Array.from(document.querySelectorAll("*"));
    return elements.filter((el) => {
        const style = window.getComputedStyle(el);
        return style.display === "none" || style.visibility === "hidden";
    }).length;
}
