
require("dotenv").config();

const express = require("express");
const axios   = require("axios");
const cors    = require("cors");
const multer  = require("multer");
const pdf     = require("pdf-parse");
const crypto  = require("crypto");
const dns     = require("dns").promises;
const tldts   = require("tldts");

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: "20mb" }));

// Multer handles file uploads (PDFs, docs, etc.) stored in memory
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });

// ── API Keys from .env ────────────────────────────────────
const GOOGLE_KEY = process.env.GOOGLE_API_KEY    || "";
const VT_KEY     = process.env.VIRUSTOTAL_API_KEY || "";

// ============================================================
// 📋  THREAT DATA — lists of known bad patterns
// ============================================================

// Domain endings that are very commonly used in scam sites
const BAD_TLDS = new Set([
    ".xyz",".top",".click",".gq",".ml",".cf",".tk",".ga",
    ".icu",".buzz",".club",".online",".site",".work",".live",
    ".stream",".download",".loan",".racing",".win",".bid",".trade"
]);

// Services that shorten URLs — phishers use these to hide real destinations
const SHORTENERS = new Set([
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
    "tiny.cc","rb.gy","cutt.ly","shorte.st","adf.ly","bc.vc"
]);

// Popular brands that scammers often impersonate
const BRANDS = [
    "paypal","google","apple","microsoft","amazon","facebook",
    "netflix","instagram","twitter","linkedin","dropbox","chase",
    "wellsfargo","bankofamerica","citibank","amex","irs",
    "fedex","ups","dhl","usps","ebay","walmart","coinbase"
];

// Words/phrases that appear a lot in phishing emails
const EMAIL_KEYWORDS = [
    { word: "verify your account",        score: 15 },
    { word: "confirm your identity",      score: 15 },
    { word: "your account will be closed",score: 20 },
    { word: "unusual activity",           score: 12 },
    { word: "unauthorized access",        score: 12 },
    { word: "click here immediately",     score: 15 },
    { word: "update your information",    score: 12 },
    { word: "limited access",             score: 10 },
    { word: "wire transfer",              score: 15 },
    { word: "social security",            score: 15 },
    { word: "you have won",               score: 15 },
    { word: "free gift",                  score: 12 },
    { word: "final notice",               score: 12 },
    { word: "dear customer",              score: 8  },
    { word: "dear user",                  score: 8  },
    { word: "security alert",             score: 10 },
    { word: "suspended",                  score: 10 },
    { word: "urgent",                     score: 8  },
    { word: "credit card",                score: 8  },
    { word: "congratulations",            score: 10 },
    { word: "act now",                    score: 10 },
    { word: "bitcoin",                    score: 10 },
    { word: "crypto",                     score: 8  },
    { word: "password",                   score: 5  },
    { word: "login",                      score: 5  },
    { word: "bank",                       score: 5  }
];

// Dangerous patterns that can appear inside PDF files (malware indicators)
const PDF_THREATS = [
    { pattern: /\/JavaScript/gi,  score: 30, label: "Embedded JavaScript"    },
    { pattern: /\/JS\s/gi,        score: 30, label: "JS shorthand"           },
    { pattern: /\/Launch/gi,      score: 25, label: "Launch action"          },
    { pattern: /\/OpenAction/gi,  score: 20, label: "Auto-open action"       },
    { pattern: /\/EmbeddedFile/gi,score: 20, label: "Embedded file"          },
    { pattern: /\/AA\s/gi,        score: 15, label: "Additional actions"     },
    { pattern: /\/RichMedia/gi,   score: 20, label: "Flash exploit vector"   },
    { pattern: /\/XFA/gi,         score: 15, label: "XFA form (data theft)"  },
    { pattern: /\/JBIG2Decode/gi, score: 15, label: "JBIG2 exploit"          },
    { pattern: /eval\(/gi,        score: 25, label: "eval() obfuscation"     },
    { pattern: /unescape\(/gi,    score: 20, label: "unescape() obfuscation" },
    { pattern: /powershell/gi,    score: 35, label: "PowerShell command"     },
    { pattern: /cmd\.exe/gi,      score: 35, label: "CMD execution"          },
    { pattern: /shellcode/gi,     score: 40, label: "Shellcode reference"    }
];

// ============================================================
// 🔗  GOOGLE SAFE BROWSING  — checks if a URL is known malware
// ============================================================
async function googleSafeBrowsing(url) {
    if (!GOOGLE_KEY) return null;
    try {
        const { data } = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
            {
                client: { clientId: "phishing-detector", clientVersion: "2.0" },
                threatInfo: {
                    threatTypes:      ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                    platformTypes:    ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries:    [{ url }]
                }
            },
            { timeout: 5000 }
        );
        // Returns the threat type if dangerous, null if safe
        return data.matches ? data.matches[0].threatType : null;
    } catch {
        return null; // fail silently — don't crash the scan
    }
}

// ============================================================
// 🦠  VIRUSTOTAL  — checks URL against 70+ antivirus engines
// ============================================================
async function virusTotal(url) {
    if (!VT_KEY) return null;

    // ✅ VirusTotal requires URL-safe base64 encoding
    //    Normal base64 uses + and / which break the URL path
    //    We must replace:  + → -    / → _    and remove =
    const id = Buffer.from(url)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g,  "");

    try {
        const { data } = await axios.get(
            `https://www.virustotal.com/api/v3/urls/${id}`,
            { headers: { "x-apikey": VT_KEY }, timeout: 8000 }
        );

        const s = data?.data?.attributes?.last_analysis_stats;
        return s ? { malicious: s.malicious || 0, suspicious: s.suspicious || 0, harmless: s.harmless || 0 } : null;

    } catch (err) {
        const code = err.response?.status;

        if (code === 404) {
            // URL was never submitted to VT before — submit it for future scans
            try {
                await axios.post(
                    "https://www.virustotal.com/api/v3/urls",
                    new URLSearchParams({ url }),
                    { headers: { "x-apikey": VT_KEY, "Content-Type": "application/x-www-form-urlencoded" }, timeout: 5000 }
                );
            } catch { /* submission failure is fine */ }
            return null; // no result yet — not a threat signal
        }

        if (code === 429) console.warn("⚠️  VirusTotal rate limit hit (free = 4 req/min)");
        if (code === 401) console.error("❌  VirusTotal: invalid API key");
        return null;
    }
}

// ============================================================
// 🌐  URL ANALYSIS  — checks a URL for common scam patterns
// ============================================================
async function analyzeUrl(url) {
    const findings = [];
    let score = 0;

    // Try to parse the URL — skip if malformed
    let parsed;
    try { parsed = new URL(url); } catch { return { score: 0, findings: ["⚠️ Malformed URL"] }; }

    const host   = parsed.hostname.toLowerCase();
    const domain = tldts.parse(host);
    const tld    = domain.publicSuffix ? `.${domain.publicSuffix}` : "";

    // 1. No HTTPS = no encryption = easy to spy on
    if (parsed.protocol === "http:") {
        score += 10;
        findings.push("⚠️ No HTTPS — connection is not encrypted");
    }

    // 2. Suspicious domain ending
    if (BAD_TLDS.has(tld)) {
        score += 15;
        findings.push(`⚠️ High-risk domain ending: ${tld}`);
    }

    // 3. Raw IP address instead of a proper domain name
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        score += 25;
        findings.push("🚨 IP address used instead of domain name");
    }

    // 4. URL shortener hides the real destination
    if (SHORTENERS.has(host)) {
        score += 15;
        findings.push(`⚠️ URL shortener hides real destination: ${host}`);
    }

    // 5. Brand name inside a fake domain (e.g. paypal-security.xyz)
    for (const brand of BRANDS) {
        if (host.includes(brand) && !host.endsWith(`${brand}.com`) && !host.endsWith(`${brand}.net`)) {
            score += 20;
            findings.push(`🚨 Fake "${brand}" domain detected: ${host}`);
            break;
        }
    }

    // 6. Punycode domain — used to make fake sites look like real ones (e.g. аpple.com)
    if (host.includes("xn--")) {
        score += 25;
        findings.push(`🚨 Lookalike domain using special characters: ${host}`);
    }

    // 7. @ symbol in URL tricks browsers into ignoring the real domain
    if (url.includes("@")) {
        score += 20;
        findings.push("🚨 @ symbol in URL — known browser trick to spoof destinations");
    }

    // 8. Too many subdomains (e.g. login.secure.paypal.fakesite.com)
    const subCount = host.split(".").length - 2;
    if (subCount >= 3) {
        score += 10;
        findings.push(`⚠️ Too many subdomains (${subCount}) — common phishing pattern`);
    }

    // 9. Very long URL is often used to hide the real domain
    if (host.length > 50) {
        score += 10;
        findings.push(`⚠️ Suspiciously long URL (${host.length} characters)`);
    }

    // 10. Multiple hyphens in domain (e.g. secure-login-paypal-verify.com)
    if ((host.match(/-/g) || []).length >= 3) {
        score += 8;
        findings.push(`⚠️ Multiple hyphens in domain: ${host}`);
    }

    // 11. Check if domain actually exists
    try { await dns.lookup(host); }
    catch {
        score += 15;
        findings.push(`⚠️ Domain doesn't exist or can't be reached: ${host}`);
    }

    // 12. Google Safe Browsing check
    const threat = await googleSafeBrowsing(url);
    if (threat) {
        score += 50;
        findings.push(`🚨 Google flagged as dangerous: ${threat}`);
    }

    // 13. VirusTotal check
    const vt = await virusTotal(url);
    if (vt) {
        if (vt.malicious > 0) {
            score += vt.malicious * 5;
            findings.push(`🦠 VirusTotal: ${vt.malicious} antivirus engines flagged this URL`);
        } else if (vt.suspicious > 0) {
            score += vt.suspicious * 3;
            findings.push(`⚠️ VirusTotal: ${vt.suspicious} engines flagged as suspicious`);
        } else {
            findings.push(`✅ VirusTotal: clean (checked by ${vt.harmless} engines)`);
        }
    }

    return { score, findings, host };
}

// ============================================================
// 📨  EMAIL TEXT ANALYSIS  — scans the email body for red flags
// ============================================================
function analyzeEmailText(text) {
    const lower    = text.toLowerCase();
    const findings = [];
    let score      = 0;

    // Check for known phishing phrases
    for (const { word, score: s } of EMAIL_KEYWORDS) {
        if (lower.includes(word)) {
            score += s;
            findings.push(`⚠️ Phishing phrase found: "${word}"`);
        }
    }

    // Lots of exclamation marks = fake urgency
    if ((text.match(/!/g) || []).length > 3) {
        score += 5;
        findings.push("⚠️ Excessive urgency (too many exclamation marks)");
    }

    // ALL CAPS words are another urgency trick
    const capsWords = [...new Set(text.match(/\b[A-Z]{4,}\b/g) || [])];
    if (capsWords.length > 2) {
        score += 8;
        findings.push(`⚠️ Urgency tactic — all-caps words: ${capsWords.slice(0, 3).join(", ")}`);
    }

    return { score, findings };
}

// ============================================================
// 📄  PDF SCANNER  — detects malware inside PDF files
// ============================================================
async function scanPdf(buffer, filename) {
    const findings = [];
    let score      = 0;

    // Scan raw file bytes for dangerous PDF commands
    const raw = buffer.toString("binary");
    for (const { pattern, score: s, label } of PDF_THREATS) {
        const hits = raw.match(pattern);
        if (hits) {
            score += s;
            findings.push(`🦠 [${filename}] ${label} found (${hits.length}x)`);
        }
    }

    // Parse the PDF to read its text content
    let parsed;
    try { parsed = await pdf(buffer, { max: 20 }); }
    catch {
        score += 10;
        findings.push(`⚠️ [${filename}] Could not read PDF — may be obfuscated`);
        return { score, findings };
    }

    // Check text content for phishing keywords
    const text = (parsed.text || "").toLowerCase();
    const kwFound = EMAIL_KEYWORDS.filter(({ word }) => text.includes(word)).map(k => k.word);
    if (kwFound.length > 0) {
        score += kwFound.length * 5;
        findings.push(`⚠️ [${filename}] Phishing words in PDF text: ${kwFound.join(", ")}`);
    }

    // Extract and check any URLs embedded inside the PDF
    const urls = [...new Set((parsed.text || "").match(/https?:\/\/[^\s"'<>)]+/g) || [])].slice(0, 5);
    if (urls.length > 0) findings.push(`🔗 [${filename}] Links inside PDF: ${urls.join(", ")}`);

    // File fingerprint for reference
    findings.push(`🔑 [${filename}] SHA-256: ${crypto.createHash("sha256").update(buffer).digest("hex").slice(0, 32)}...`);

    return { score, findings, embeddedUrls: urls };
}

// ============================================================
// 🗂️  OFFICE FILE SCANNER  — detects macros in Word/Excel files
// ============================================================
function scanOfficeFile(buffer, filename) {
    const findings = [];
    let score      = 0;
    const raw      = buffer.toString("binary");

    const checks = [
        { pattern: /vbaProject/,      score: 40, msg: "VBA macro detected — high malware risk" },
        { pattern: /AutoOpen|Document_Open/, score: 35, msg: "Auto-run macro found"             },
        { pattern: /Shell\(/,         score: 40, msg: "Shell execution command in macro"        },
        { pattern: /CreateObject/,    score: 35, msg: "CreateObject — can run system commands"  },
        { pattern: /powershell/i,     score: 45, msg: "PowerShell execution command"            },
        { pattern: /cmd\.exe/i,       score: 45, msg: "CMD execution command"                   }
    ];

    for (const { pattern, score: s, msg } of checks) {
        if (pattern.test(raw)) {
            score += s;
            findings.push(`🚨 [${filename}] ${msg}`);
        }
    }

    if (findings.length === 0) findings.push(`✅ [${filename}] No macro threats found`);
    return { score, findings };
}

// ============================================================
// 🏠  ROOT  — open this in browser to check server is running
// ============================================================
app.get("/", (req, res) => {
    res.json({
        status:    "✅ Phishing Detector is running",
        version:   "2.0",
        endpoints: ["POST /scan", "POST /scan-file"],
        apis: {
            googleSafeBrowsing: !!GOOGLE_KEY,
            virusTotal:         !!VT_KEY
        }
    });
});

// ============================================================
// 📬  POST /scan  — main endpoint: scans an email
//     Body: { email: "...", urls: [...], images: [...] }
// ============================================================
app.post("/scan", async (req, res) => {
    console.log("📩 Scan request received");

    const { email = "", urls = [] } = req.body;
    let totalScore = 0;
    const allFindings = [];
    const urlResults  = [];

    // 1. Analyse the email text
    const emailResult = analyzeEmailText(email);
    totalScore += emailResult.score;
    allFindings.push(...emailResult.findings);

    // 2. Analyse each URL (max 8 to stay within API limits)
    await Promise.all([...new Set(urls)].slice(0, 8).map(async (url) => {
        if (!url || typeof url !== "string") return;
        const result = await analyzeUrl(url);
        totalScore += result.score;
        allFindings.push(...result.findings.map(f => `[${result.host}] ${f}`));
        urlResults.push({ url, ...result });
    }));

    // 3. Build final verdict
    const { verdict, severity } = getVerdict(totalScore);

    console.log(`✅ Scan complete — score: ${totalScore} — ${verdict}`);

    res.json({
        verdict, severity,
        riskScore: totalScore,
        details:   allFindings,
        breakdown: { urls: urlResults }
    });
});

// ============================================================
// 📎  POST /scan-file  — scans an uploaded file (PDF, Word, etc.)
//     Form data: file field
// ============================================================
app.post("/scan-file", upload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const { buffer, originalname: name, mimetype, size } = req.file;
    const findings = [];
    let score      = 0;

    console.log(`📎 Scanning file: ${name}`);

    // Route to the right scanner based on file type
    if (mimetype === "application/pdf" || name.endsWith(".pdf")) {
        const result = await scanPdf(buffer, name);
        score    += result.score;
        findings.push(...result.findings);

        // Also scan any URLs embedded inside the PDF
        for (const url of (result.embeddedUrls || []).slice(0, 3)) {
            const urlResult = await analyzeUrl(url);
            if (urlResult.score > 0) {
                score += urlResult.score;
                findings.push(...urlResult.findings.map(f => `[PDF link] ${f}`));
            }
        }

    } else if (mimetype.includes("officedocument") || /\.(docx|xlsx|pptx|doc|xls|ppt)$/i.test(name)) {
        const result = scanOfficeFile(buffer, name);
        score    += result.score;
        findings.push(...result.findings);

    } else if (/\.(zip|rar|7z)$/i.test(name)) {
        score += 10;
        findings.push(`⚠️ [${name}] Archive file — may contain hidden malicious files`);
        if (/\.(pdf|doc|jpg)\.(zip|rar)$/i.test(name)) {
            score += 25;
            findings.push(`🚨 [${name}] Double file extension — common malware trick`);
        }

    } else if (/\.(exe|bat|cmd|scr|vbs|ps1|sh|jar|msi)$/i.test(name)) {
        score += 80;
        findings.push(`🚨 [${name}] Executable file — NEVER open this from an email`);
    }

    // Check file hash against VirusTotal database
    if (VT_KEY) {
        const hash = crypto.createHash("sha256").update(buffer).digest("hex");
        try {
            const { data } = await axios.get(
                `https://www.virustotal.com/api/v3/files/${hash}`,
                { headers: { "x-apikey": VT_KEY }, timeout: 6000 }
            );
            const s = data?.data?.attributes?.last_analysis_stats;
            if (s?.malicious > 0) {
                score += s.malicious * 4;
                findings.push(`🦠 VirusTotal matched this file — ${s.malicious} engines flagged it as malicious`);
            } else if (s) {
                findings.push(`✅ VirusTotal file hash: clean`);
            }
        } catch { /* file not in VT database is normal */ }
    }

    const { verdict, severity } = getVerdict(score);

    res.json({
        verdict, severity,
        riskScore: score,
        fileInfo:  { name, size: `${(size / 1024).toFixed(1)} KB`, type: mimetype },
        findings
    });
});

// ============================================================
// 🏁  VERDICT HELPER  — converts a score into a human label
// ============================================================
function getVerdict(score) {
    if (score >= 80) return { verdict: "🚨 HIGH RISK — Likely Phishing",    severity: "high"   };
    if (score >= 40) return { verdict: "⚠️ SUSPICIOUS — Be Careful",        severity: "medium" };
    if (score >= 15) return { verdict: "🔶 Slightly Suspicious",             severity: "low"    };
    return             { verdict: "✅ Looks Safe",                           severity: "safe"   };
}

// ============================================================
// 🚀  START SERVER
// ============================================================
app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n🚀  Server running →  http://localhost:${PORT}`);
    console.log(`🔑  Google Safe Browsing : ${GOOGLE_KEY  ? "✅ Active" : "❌ No key in .env"}`);
    console.log(`🦠  VirusTotal           : ${VT_KEY      ? "✅ Active" : "❌ No key in .env"}\n`);
});

// ============================================================
// 📝  .env FILE SETUP (create this file next to server.js)
//
//     PORT=5000
//     GOOGLE_API_KEY=get free key at → console.cloud.google.com
//     VIRUSTOTAL_API_KEY=get free key at → virustotal.com
// ============================================================
