<div align="center">

# 🛡️ CAPTIVE AUDIT

**Captive Portal Security Audit Toolkit**

A defensive security assessment toolkit for auditing your own captive portal infrastructure. Run directly from Android via Termux.

[![Live Guide](https://img.shields.io/badge/📖_Live_Guide-GitHub_Pages-e8a838?style=for-the-badge)](https://devtint.github.io/CAPTIVE_AUDIT/)
[![Telegram](https://img.shields.io/badge/Telegram-@BadCodeWriter-2AABEE?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/BadCodeWriter)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational-4caf7d?style=for-the-badge)](LICENSE)

</div>

---

## ⚠️ Disclaimer

> **This toolkit is for authorized security testing ONLY.** Only run against infrastructure you **own** or have **written permission** to test. Unauthorized use against third-party systems is **illegal**. By using this tool, you confirm you have proper authorization.

---

## 📋 What's Included

| File | Purpose |
|------|---------|
| `captive_portal_audit.py` | Full 7-check security audit with JSON report output |
| `starlink.py` | Turbo Network Engine — multi-threaded auth probe |
| `index.html` + `style.css` | GitHub Pages guide & JSON report analyzer |

---

## 🔍 Security Checks (captive_portal_audit.py)

The audit tool performs **7 automated security checks**:

| # | Check | What It Tests |
|---|-------|--------------|
| C1 | Portal Detection | Redirect chain analysis, HTTP vs HTTPS |
| C2 | Session ID Exposure | Tokens in URLs, HTML source, hidden fields |
| C3 | Auth Endpoint | WifiDog gateway accepts fake tokens? |
| C4 | Voucher API | Weak voucher codes accepted? |
| C5 | Token Binding | Session reuse from different device context |
| C6 | HTTPS Enforcement | TLS on portal login pages |
| C7 | Rate Limiting | Brute-force protection on auth paths |

Output: A structured `captive_portal_audit_report.json` with findings and hardening recommendations.

---

## 🚀 Quick Start (Termux)

```bash
# 1. Update Termux
pkg update -y && pkg upgrade -y

# 2. Install Python & Git
pkg install python git -y

# 3. Install dependencies
pip install requests urllib3

# 4. Clone and run
git clone https://github.com/devtint/CAPTIVE_AUDIT.git
cd CAPTIVE_AUDIT

# Run Security Audit
python captive_portal_audit.py

# Run Turbo Engine
python starlink.py
```

> 📖 **Full step-by-step guide with screenshots:** [devtint.github.io/CAPTIVE_AUDIT](https://devtint.github.io/CAPTIVE_AUDIT/)

---

## 📊 Report Analyzer

Upload your `captive_portal_audit_report.json` to the **web-based analyzer** for a visual breakdown:

- ✅ Pass / ⚠️ Warn / ❌ Fail summary cards
- Detailed findings with severity badges
- Hardening recommendations

**→ [Open Analyzer](https://devtint.github.io/CAPTIVE_AUDIT/#analyzer)**

---

## 🛠️ Requirements

- **Android** with [Termux](https://f-droid.org/en/packages/com.termux/) (F-Droid version)
- **Python 3.8+**
- `requests`, `urllib3` (auto-installed by `starlink.py`)
- Connected to the target captive portal WiFi network

---

## 📁 Project Structure

```
CAPTIVE_AUDIT/
├── captive_portal_audit.py   # Security audit tool (7 checks)
├── starlink.py               # Turbo Network Engine
├── index.html                # GitHub Pages — guide & analyzer
├── style.css                 # Clarity UI stylesheet
└── README.md                 # This file
```

---

## 🤝 Contact

Have questions or want to contribute?

[![Telegram](https://img.shields.io/badge/Telegram-@BadCodeWriter-2AABEE?style=flat-square&logo=telegram&logoColor=white)](https://t.me/BadCodeWriter)

---

<div align="center">
<sub>Built for authorized security research. Stay ethical. Stay secure.</sub>
</div>
