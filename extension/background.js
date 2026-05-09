// ============================================================
// 🛡️  PHISHING DETECTOR — background.js
//     This is the "brain" of the extension.
//     It runs in the background and connects content.js ↔ server.
//
//     No popup.html needed — clicking the extension icon
//     directly toggles the result panel inside Gmail.
// ============================================================

const SERVER = "http://localhost:5000";

// ============================================================
// 🖱️  ICON CLICK  — clicking the toolbar icon toggles the panel
// ============================================================
chrome.action.onClicked.addListener(async (tab) => {
    // Only work on Gmail tabs
    if (!tab.url?.includes("mail.google.com")) {
        // On non-Gmail pages, open Gmail instead
        chrome.tabs.create({ url: "https://mail.google.com" });
        return;
    }

    // Tell content.js to show or hide the result panel
    try {
        await chrome.tabs.sendMessage(tab.id, { type: "TOGGLE_PANEL" });
    } catch {
        // content.js might not be loaded yet — inject it manually
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
    }
});

// ============================================================
// 📩  MESSAGE HANDLER  — receives messages from content.js
// ============================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    // content.js asks us to scan an email
    if (message.type === "SCAN_EMAIL") {
        scanEmail(message.data)
            .then(result => {
                // Update the badge icon color based on result
                updateBadge(result.severity, sender.tab?.id);
                sendResponse({ success: true, data: result });
            })
            .catch(err => {
                console.error("❌ Scan failed:", err.message);
                sendResponse({ success: false, error: err.message });
            });
        return true; // keeps the message channel open for async response
    }

    // content.js asks us to scan an attached file
    if (message.type === "SCAN_FILE") {
        scanFile(message.fileUrl, message.filename)
            .then(result => sendResponse({ success: true, data: result }))
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }
});

// ============================================================
// 🧠  SCAN EMAIL  — sends email data to the backend server
// ============================================================
async function scanEmail(data) {
    // 15 second timeout — server shouldn't take longer than this
    const controller = new AbortController();
    const timeout    = setTimeout(() => controller.abort(), 15000);

    try {
        const response = await fetch(`${SERVER}/scan`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({
                email:  data.email              || "",
                urls:  (data.urls   || []).slice(0, 8), // max 8 URLs per scan
                images:(data.images || []).slice(0, 3)
            }),
            signal: controller.signal
        });

        clearTimeout(timeout);

        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        return await response.json();

    } catch (err) {
        clearTimeout(timeout);
        if (err.name === "AbortError") throw new Error("Scan timed out — is the server running?");
        throw err;
    }
}

// ============================================================
// 📎  SCAN FILE  — downloads and scans an email attachment
// ============================================================
async function scanFile(fileUrl, filename) {
    const fileResponse = await fetch(fileUrl);
    const blob         = await fileResponse.blob();

    const form = new FormData();
    form.append("file", blob, filename || "attachment");

    const response = await fetch(`${SERVER}/scan-file`, { method: "POST", body: form });
    if (!response.ok) throw new Error(`File scan failed: ${response.status}`);

    return await response.json();
}

// ============================================================
// 🔴  BADGE  — updates the icon badge color + text
//     Green ✓ = safe   Orange ⚠ = suspicious   Red ! = danger
// ============================================================
function updateBadge(severity, tabId) {
    const config = {
        high:   { text: "!",  color: "#b71c1c" },
        medium: { text: "⚠",  color: "#e65100" },
        low:    { text: "?",  color: "#f57f17" },
        safe:   { text: "✓",  color: "#1b5e20" }
    };

    const { text, color } = config[severity] || config.safe;
    const target = tabId ? { tabId } : {};

    chrome.action.setBadgeText({ text, ...target });
    chrome.action.setBadgeBackgroundColor({ color, ...target });
}

// ============================================================
// 🔔  STARTUP LOG
// ============================================================
chrome.runtime.onInstalled.addListener(() => {
    console.log("🛡️  Phishing Detector installed — open Gmail to start scanning");
});

console.log("🛡️  Background service worker active");
