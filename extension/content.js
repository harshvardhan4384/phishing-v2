

let lastHash      = "";   // remembers last scanned email to avoid re-scanning
let scanRunning   = false; // prevents two scans at the same time

// ============================================================
// 📧  EXTRACT EMAIL TEXT  — reads the visible email body
// ============================================================
function getEmailText() {
    let text = "";

    // Primary Gmail selector
    document.querySelectorAll("div.a3s.aiL").forEach(el => { text += el.innerText + "\n"; });

    // Fallback if above doesn't work
    if (!text.trim()) {
        document.querySelectorAll("div.ii.gt").forEach(el => { text += el.innerText + "\n"; });
    }

    return text.trim();
}

// ============================================================
// 🔗  EXTRACT LINKS  — finds all URLs in the open email
// ============================================================
function getLinks() {
    const seen = new Set();

    document.querySelectorAll("a[href]").forEach(a => {
        let url = a.href;

        // Gmail wraps real URLs inside google.com/url?q= — unwrap them
        if (url.includes("google.com/url?q=")) {
            try { url = new URL(url).searchParams.get("q") || url; } catch { /* skip */ }
        }

        if (url.startsWith("http") && !url.includes("mail.google.com") && !url.includes("accounts.google.com")) {
            seen.add(url);
        }
    });

    return [...seen];
}

// ============================================================
// 🖼️  EXTRACT IMAGES  — finds external images in the email
// ============================================================
function getImages() {
    const seen = new Set();
    document.querySelectorAll("img[src]").forEach(img => {
        if (img.src.startsWith("http") && !img.src.includes("googleusercontent.com")) seen.add(img.src);
    });
    return [...seen];
}

// ============================================================
// 📎  DETECT ATTACHMENTS  — checks for dangerous file types
// ============================================================
function getAttachments() {
    const names = new Set();
    document.querySelectorAll("span.aV3").forEach(el => { if (el.innerText) names.add(el.innerText.trim()); });

    const all       = [...names];
    const dangerous = all.filter(n => /\.(exe|bat|cmd|scr|vbs|js|ps1|sh|msi|hta)$/i.test(n));
    return { all, dangerous };
}

// ============================================================
// 🔑  HASH  — creates a short unique ID for the email text
//     Used to skip re-scanning the same email twice
// ============================================================
function hash(text) {
    let h = 0;
    for (let i = 0; i < text.length; i++) h = (Math.imul(31, h) + text.charCodeAt(i)) | 0;
    return h.toString(36);
}

// ============================================================
// ✅  EXTENSION CHECK  — makes sure extension is still alive
//     (Can break if Chrome reloads the extension mid-session)
// ============================================================
function extensionAlive() {
    try { return !!(chrome?.runtime?.id); } catch { return false; }
}

// ============================================================
// 📤  SEND TO BACKGROUND  — sends data to background.js
//     Has auto-retry in case the service worker is waking up
// ============================================================
function sendMessage(data, callback, tries = 2) {
    if (!extensionAlive()) return callback(null, "Extension was reloaded — please refresh Gmail (F5)");

    try {
        chrome.runtime.sendMessage(data, (response) => {
            // ⚠️  MUST read lastError immediately or Chrome throws an uncaught error
            const err = chrome.runtime.lastError;

            if (err) {
                // Service worker might still be waking up — retry once
                if (tries > 0 && err.message.includes("Could not establish connection")) {
                    return setTimeout(() => sendMessage(data, callback, tries - 1), 800);
                }
                return callback(null, err.message);
            }

            callback(response, null);
        });
    } catch (e) {
        callback(null, e.message);
    }
}

// ============================================================
// 🧠  SCAN EMAIL  — main function called when email opens
// ============================================================
function scanEmail(text) {
    if (scanRunning || !extensionAlive()) return;
    scanRunning = true;

    const links       = getLinks();
    const images      = getImages();
    const attachments = getAttachments();

    console.log(`🛡️  Scanning: ${links.length} links, ${attachments.all.length} attachments`);
    showLoader();

    // Warn about dangerous attachments immediately — don't wait for backend
    if (attachments.dangerous.length > 0) {
        showToast(`🚨 Dangerous attachment: ${attachments.dangerous.join(", ")}`, "high");
    }

    sendMessage(
        { type: "SCAN_EMAIL", data: { email: text, urls: links, images } },
        (response, err) => {
            scanRunning = false;
            hideLoader();

            if (err) {
                if (err.includes("context invalidated") || err.includes("reloaded")) {
                    return showToast("⚠️ Extension reloaded — refresh Gmail (F5)", "medium");
                }
                if (err.includes("ECONNREFUSED") || err.includes("fetch")) {
                    return showToast("🔴 Server offline — run: node server.js", "high");
                }
                return showToast("❌ " + err, "medium");
            }

            if (!response?.success) return showToast("❌ " + (response?.error || "Scan failed"), "medium");

            showPanel({ ...response.data, attachments });
        }
    );
}

// ============================================================
// 👁️  MUTATION OBSERVER  — watches Gmail for new emails
//     Fires every time Gmail loads a new email in the view
// ============================================================
const observer = new MutationObserver(debounce(() => {
    if (!extensionAlive()) return observer.disconnect();

    const text = getEmailText();
    if (!text) return;

    const h = hash(text);
    if (h === lastHash) return; // same email, skip
    lastHash = h;

    scanEmail(text);
}, 1200));

observer.observe(document.body, { childList: true, subtree: true });

// ============================================================
// 📩  LISTEN FOR POPUP MESSAGES
//     popup.js clicks the "Scan" button → asks for email data
// ============================================================
chrome.runtime.onMessage.addListener((msg, _, reply) => {
    if (msg.type === "GET_EMAIL_DATA") {
        reply({ email: getEmailText(), urls: getLinks(), images: getImages() });
    }
    if (msg.type === "TOGGLE_PANEL") {
        document.getElementById("pd-panel") ? removePanel() : scanEmail(getEmailText());
    }
    return true;
});

// ============================================================
// ⏱️  DEBOUNCE  — delays a function so it doesn't fire too often
// ============================================================
function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ============================================================
// 🎨  UI — LOADER (small spinner while scanning)
// ============================================================
function showLoader() {
    if (document.getElementById("pd-loader")) return;
    const el = document.createElement("div");
    el.id = "pd-loader";
    el.innerHTML = `<span style="display:inline-block;width:12px;height:12px;border:2px solid #ffffff44;border-top-color:#fff;border-radius:50%;animation:pdspin .7s linear infinite;margin-right:8px;"></span> Scanning email...`;
    css(el, { position:"fixed", bottom:"20px", right:"20px", padding:"10px 16px",
              background:"#1a73e8", color:"#fff", borderRadius:"8px", fontSize:"12px",
              fontFamily:"Google Sans,sans-serif", zIndex:"99999", display:"flex",
              alignItems:"center", boxShadow:"0 4px 12px rgba(0,0,0,.25)" });
    injectCSS();
    document.body.appendChild(el);
}
function hideLoader() { document.getElementById("pd-loader")?.remove(); }

// ============================================================
// 🎨  UI — TOAST  (quick error/warning message)
// ============================================================
function showToast(msg, severity = "medium") {
    const colors = { high:"#b71c1c", medium:"#e65100", safe:"#1b5e20" };
    const el = document.createElement("div");
    el.innerText = msg;
    css(el, { position:"fixed", top:"20px", right:"20px", padding:"12px 16px",
              background: colors[severity] || colors.medium, color:"#fff",
              borderRadius:"10px", fontSize:"13px", fontFamily:"Google Sans,sans-serif",
              zIndex:"99999", maxWidth:"300px", boxShadow:"0 4px 12px rgba(0,0,0,.3)" });
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 7000);
}

// ============================================================
// 🎨  UI — RESULT PANEL  (main results card shown in Gmail)
// ============================================================
function removePanel() { document.getElementById("pd-panel")?.remove(); }

function showPanel({ verdict, severity, riskScore, details = [], breakdown = {}, attachments }) {
    removePanel();

    const BG  = { high:"#b71c1c", medium:"#e65100", low:"#f57f17", safe:"#1b5e20" };
    const BAR = { high:"#ef5350", medium:"#fb8c00", low:"#fdd835",  safe:"#43a047" };
    const BORDER = { high:"#ff1744", medium:"#ff9100", low:"#ffd600", safe:"#00c853" };
    const bg  = BG[severity]     || BG.safe;
    const bar = BAR[severity]    || BAR.safe;
    const bdr = BORDER[severity] || BORDER.safe;

    // Build URL rows
    const urlRows = (breakdown.urls || []).map(u => {
        let host; try { host = new URL(u.url).hostname; } catch { host = u.url; }
        const icon = u.score >= 40 ? "🚨" : u.score >= 20 ? "⚠️" : "✅";
        return `<div style="font-size:11px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.08)">
                    ${icon} <b>${host}</b> — score: ${u.score}
                    ${u.findings.map(f => `<div style="opacity:.7;padding-left:10px">${f}</div>`).join("")}
                </div>`;
    }).join("");

    // Build attachment warning
    const attachHTML = attachments.dangerous.length > 0
        ? `<div style="background:#7f0000;border-radius:6px;padding:8px;margin:6px 0">
               🚨 <b>Dangerous attachment:</b> ${attachments.dangerous.join(", ")}
           </div>`
        : attachments.all.length > 0
        ? `<div style="padding:4px 0;font-size:11px">📎 Attachments: ${attachments.all.join(", ")}</div>`
        : "";

    // Build findings list
    const findingsHTML = details.length > 0
        ? details.map(d => `<div style="font-size:11px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.08)">${d}</div>`).join("")
        : `<div style="font-size:11px;opacity:.6">No specific issues found</div>`;

    const panel = document.createElement("div");
    panel.id = "pd-panel";
    panel.innerHTML = `
        <!-- Header -->
        <div style="display:flex;align-items:center;gap:8px;padding:12px;border-bottom:1px solid rgba(255,255,255,.15)">
            <span style="font-size:20px">🛡️</span>
            <div>
                <div style="font-weight:700;font-size:13px">${verdict}</div>
                <div style="font-size:10px;opacity:.7">Risk Score: ${riskScore} / 100</div>
            </div>
            <button id="pd-close" style="margin-left:auto;background:rgba(255,255,255,.2);border:none;color:#fff;width:22px;height:22px;border-radius:50%;cursor:pointer;font-size:11px">✕</button>
        </div>

        <!-- Risk bar -->
        <div style="height:4px;background:rgba(255,255,255,.15)">
            <div style="height:4px;width:${Math.min(riskScore,100)}%;background:${bar};transition:width .5s"></div>
        </div>

        <!-- Attachment warning -->
        <div style="padding:0 12px">${attachHTML}</div>

        <!-- URL breakdown -->
        ${urlRows ? `<div style="padding:6px 12px"><div style="font-size:10px;opacity:.6;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">🔗 URLs Checked</div>${urlRows}</div>` : ""}

        <!-- Findings -->
        <div style="padding:6px 12px">
            <div style="font-size:10px;opacity:.6;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">📋 Findings</div>
            ${findingsHTML}
        </div>

        <!-- Footer -->
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-top:1px solid rgba(255,255,255,.12);font-size:10px;opacity:.6">
            <span>Phishing Detector v2.0</span>
            <button id="pd-rescan" style="background:rgba(255,255,255,.2);border:none;color:#fff;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:10px">🔄 Rescan</button>
        </div>`;

    css(panel, {
        position:"fixed", top:"70px", right:"16px", width:"320px", maxHeight:"76vh",
        overflowY:"auto", background:bg, color:"#fff", borderRadius:"12px",
        fontSize:"12px", fontFamily:"Google Sans,Roboto,sans-serif",
        zIndex:"99999", boxShadow:"0 8px 32px rgba(0,0,0,.4)",
        border:`2px solid ${bdr}`
    });

    injectCSS();
    document.body.appendChild(panel);

    document.getElementById("pd-close").onclick   = removePanel;
    document.getElementById("pd-rescan").onclick  = () => { removePanel(); lastHash = ""; scanEmail(getEmailText()); };

    // Auto-hide after 30s only if safe
    if (severity === "safe") setTimeout(removePanel, 30000);
}

// ============================================================
// 🛠️  HELPERS
// ============================================================
// Shorthand to apply multiple CSS properties at once
function css(el, styles) { Object.assign(el.style, styles); }

// Injects the spinner animation CSS — only once per page load
let cssInjected = false;
function injectCSS() {
    if (cssInjected) return;
    cssInjected = true;
    const s = document.createElement("style");
    s.textContent = "@keyframes pdspin { to { transform:rotate(360deg) } }";
    document.head.appendChild(s);
}
