#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Captive Portal Security Audit Tool
====================================
PURPOSE : Defensive assessment tool to check if YOUR OWN captive portal
          is vulnerable to token-scraping and auth-bypass techniques.

USAGE   : python captive_portal_audit.py
          (fully interactive — no command-line arguments needed)

IMPORTANT: Only run this against infrastructure you OWN or have written
           permission to test.
"""

import requests
import re
import sys
import time
import json
import os
from urllib.parse import urlparse, parse_qs, urljoin
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI Colors ──────────────────────────────────────────────
RED    = "\033[1;31m"
GREEN  = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[1;36m"
WHITE  = "\033[0;37m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

PASS_TAG = f"{GREEN}[PASS]{RESET}"
FAIL_TAG = f"{RED}[FAIL]{RESET}"
WARN_TAG = f"{YELLOW}[WARN]{RESET}"
INFO_TAG = f"{CYAN}[INFO]{RESET}"

findings = []

# ════════════════════════════════════════════════════════════
# LANGUAGE STRINGS  (English + Myanmar)
# ════════════════════════════════════════════════════════════
LANG = {
    "en": {
        "choose_lang":     "Choose language / ဘာသာစကား ရွေးချယ်ပါ",
        "lang_1":          "1. English",
        "lang_2":          "2. မြန်မာဘာသာ (Myanmar)",
        "lang_prompt":     "Enter choice [1-2]: ",
        "banner_title":    "CAPTIVE PORTAL SECURITY AUDIT TOOL",
        "banner_sub":      "Defensive assessment — run only on systems you own",
        "disclaimer": (
            "  WARNING: This tool is for auditing YOUR OWN portal only.\n"
            "  Unauthorized use against others' systems is illegal.\n"
            "  By continuing you confirm you have permission to test."
        ),
        "press_enter":     "Press Enter to continue...",
        "main_menu":       "MAIN MENU",
        "opt_1":           "1. Run Full Security Audit",
        "opt_2":           "2. Change Language",
        "opt_3":           "3. Exit",
        "menu_prompt":     "Select option [1-3]: ",
        "enter_portal":    "Enter portal URL (e.g. http://192.168.1.1): ",
        "enter_gw_host":   "Gateway host/IP (Enter to auto-detect): ",
        "enter_gw_port":   "Gateway port    (Enter for default 2060): ",
        "starting":        "Starting audit...",
        "done":            "Audit complete.",
        "saved":           "Full JSON report saved to",
        "back_menu":       "Press Enter to return to menu...",
        "goodbye":         "Goodbye. Stay secure.",
        "invalid":         "Invalid option — try again.",
        # Sections
        "s1":       "CHECK 1 : Portal Detection & Redirect Chain",
        "s2":       "CHECK 2 : Session ID / Token Exposure in URL",
        "s3":       "CHECK 3 : WifiDog Auth Endpoint Direct Access",
        "s4":       "CHECK 4 : Voucher / Payment API Endpoint",
        "s5":       "CHECK 5 : Token Binding & Session Reuse",
        "s6":       "CHECK 6 : HTTPS Enforcement",
        "s7":       "CHECK 7 : Rate Limiting on Auth Requests",
        "s_sum":    "AUDIT SUMMARY REPORT",
        "s_reco":   "HARDENING RECOMMENDATIONS",
        # Labels
        "l_target":   "Target",
        "l_date":     "Date",
        "l_duration": "Duration",
        "l_passed":   "checks passed",
        "l_warned":   "warnings (review recommended)",
        "l_failed":   "vulnerabilities found",
        "l_critical": "Critical Issues to Fix",
        "l_warnings": "Warnings to Review",
        # Check messages
        "c1a_no_redir":  "No captive portal redirect detected from this network.",
        "c1a_no_redir_d":"Run script from inside the portal's network segment.",
        "c1a_found":     "Portal redirect detected",
        "c1b_http":      "Portal uses plain HTTP for login redirect.",
        "c1b_http_fix":  "Fix: Force HTTPS redirect. HTTP exposes tokens in transit.",
        "c1b_https":     "Portal redirects over HTTPS.",
        "c1a_direct":    "Direct portal URL responded",
        "c1a_err":       "Could not reach portal",
        "c2a_fail":      "Session ID / token exposed in URL.",
        "c2a_fix":       "Fix: Never put auth tokens in URLs. Use POST body + signed HttpOnly cookies.",
        "c2a_pass":      "Session ID not found in URL parameters.",
        "c2b_fail":      "Session ID embedded raw in HTML source.",
        "c2b_fix":       "Fix: Keep tokens server-side. Never render raw tokens in client HTML.",
        "c2b_pass":      "Session ID not found in HTML body.",
        "c2c_warn":      "Long token in hidden form field — verify it is only a CSRF token.",
        "c2c_pass":      "No suspicious hidden-field token detected.",
        "c2_err":        "Session ID check error",
        "c3a_crit":      "Auth endpoint ACCEPTED a fake token — CRITICAL vulnerability!",
        "c3a_crit_d":    "Fix: Validate tokens server-side with HMAC signatures. Never grant on token presence alone.",
        "c3a_warn":      "Auth endpoint returned HTTP 200 — manual review recommended.",
        "c3a_pass":      "Auth endpoint rejected fake token correctly",
        "c3a_404":       "Auth endpoint returned 404 — path may differ from /wifidog/auth.",
        "c3a_unexpected":"Auth endpoint returned unexpected status",
        "c3a_no_conn":   "Cannot reach gateway — likely a different network subnet.",
        "c3a_no_conn_d": "Run from inside the portal LAN to test the gateway directly.",
        "c3a_err":       "Auth endpoint check error",
        "c4a_crit":      "Voucher API accepted a weak test code!",
        "c4a_crit_d":    "Fix: Use one-time codes tied to payment records. Lock out after 5 failures.",
        "c4a_rate":      "Voucher API is rate-limiting (HTTP 429). Good.",
        "c4a_pass":      "Voucher API rejected test payload correctly",
        "c4a_404":       "Voucher endpoint not found at /api/auth/voucher/",
        "c4b_warn":      "Voucher API returned unexpected status",
        "c4_err":        "Voucher check error",
        "c5a_no_sid":    "No session ID captured — skipping token binding check.",
        "c5a_no_sid_d":  "Provide a valid portal URL to capture a session ID.",
        "c5a_fail":      "Token reused from a different device context — binding missing!",
        "c5a_fix":       "Fix: Bind tokens to client MAC address. Reject auth if MAC mismatches.",
        "c5a_pass":      "Token not trivially reusable from a different device.",
        "c5a_no_gw":     "Could not reach gateway for token-binding test.",
        "c5b_info":      "Manual check: replay the same token after successful auth — it should be rejected.",
        "c6a_pass":      "Portal served over HTTPS.",
        "c6a_fail":      "Portal login served over plain HTTP.",
        "c6a_fix":       "Fix: Use Let's Encrypt TLS + HSTS. All portal pages must be HTTPS.",
        "c6b_info":      "HTTPS endpoint exists",
        "c6b_warn":      "HTTPS available but HTTP still in use — enforce redirect.",
        "c6b_fix":       "Fix: Add HTTP→HTTPS redirect in nginx/Apache/portal config.",
        "c6b_warn2":     "Could not verify HTTPS availability.",
        "c7a_pass":      "Rate limiting active — HTTP 429 after rapid requests.",
        "c7a_fail":      "No rate limiting detected on portal auth paths.",
        "c7a_fix":       "Fix: nginx limit_req or fail2ban. Max 10 req/min per IP. Lock after 5 bad vouchers.",
        # Recommendations list: (number, title, detail)
        "reco": [
            ("1", "Use signed, time-limited tokens (HMAC-SHA256)",
             "Generate: HMAC(secret, sessionId+timestamp+MAC). Verify every auth call. Expire in 5–15 min."),
            ("2", "Bind sessions to client MAC address",
             "Record MAC at session creation. Reject auth if MAC doesn't match the original."),
            ("3", "One-time-use tokens only",
             "Invalidate the token immediately after first successful auth. Re-auth needs a fresh token."),
            ("4", "Never expose tokens in URLs",
             "Use POST body or secure HttpOnly cookies. URL tokens are logged by proxies and browsers."),
            ("5", "Enforce HTTPS end-to-end",
             "Use Let's Encrypt + HSTS. HTTP portals leak tokens to anyone on the same WiFi."),
            ("6", "Rate-limit all auth endpoints",
             "nginx limit_req. Lock IP after 5 failed voucher attempts for 15 minutes."),
            ("7", "Use a hardened captive portal solution",
             "Consider pfSense, OpenWRT+nodogsplash, or commercial platforms with active security updates."),
        ],
    },

    "mm": {
        "choose_lang":     "Choose language / ဘာသာစကား ရွေးချယ်ပါ",
        "lang_1":          "1. English",
        "lang_2":          "2. မြန်မာဘာသာ (Myanmar)",
        "lang_prompt":     "ရွေးချယ်မှု ထည့်ပါ [1-2]: ",
        "banner_title":    "CAPTIVE PORTAL လုံခြုံရေး စစ်ဆေးကိရိယာ",
        "banner_sub":      "ကိုယ်ပိုင် portal များကိုသာ စစ်ဆေးရန် — ခွင့်ပြုချက်ရှိသော စနစ်သာ အသုံးပြုပါ",
        "disclaimer": (
            "  သတိချပ်ပါ: ဤကိရိယာသည် သင်၏ portal ကိုသာ စစ်ဆေးရန်ဖြစ်သည်။\n"
            "  အခြားသူ၏ စနစ်ကို ခွင့်မပြုဘဲ အသုံးပြုခြင်းသည် တရားမဝင်ပါ။\n"
            "  ဆက်လက်ခြင်းဖြင့် စစ်ဆေးခွင့်ရှိကြောင်း အတည်ပြုသည်။"
        ),
        "press_enter":     "Enter နှိပ်၍ ဆက်လက်ပါ...",
        "main_menu":       "ပင်မ မီနူး",
        "opt_1":           "1. လုံခြုံရေး စစ်ဆေးချက် အပြည့်အစုံ စတင်ရန်",
        "opt_2":           "2. ဘာသာစကား ပြောင်းရန်",
        "opt_3":           "3. ထွက်ရန်",
        "menu_prompt":     "ရွေးချယ်မှု [1-3]: ",
        "enter_portal":    "Portal URL ထည့်ပါ (ဥပမာ http://192.168.1.1): ",
        "enter_gw_host":   "Gateway host/IP (auto-detect အတွက် Enter): ",
        "enter_gw_port":   "Gateway port (default 2060 အတွက် Enter): ",
        "starting":        "စစ်ဆေးချက် စတင်နေသည်...",
        "done":            "စစ်ဆေးချက် ပြီးဆုံးသည်။",
        "saved":           "JSON အစီရင်ခံစာ သိမ်းဆည်းပြီး",
        "back_menu":       "မီနူးသို့ ပြန်သွားရန် Enter နှိပ်ပါ...",
        "goodbye":         "ထွက်သည်။ လုံခြုံပါစေ။",
        "invalid":         "မမှန်ကန်သော ရွေးချယ်မှု — ထပ်ကြိုးစားပါ။",
        # Sections
        "s1":    "စစ်ဆေးချက် ၁ : Portal ရှာဖွေမှုနှင့် Redirect ကွင်းဆက်",
        "s2":    "စစ်ဆေးချက် ၂ : Session ID / Token URL တွင် ထွက်ပေါ်မှု",
        "s3":    "စစ်ဆေးချက် ၃ : WifiDog Auth Endpoint တိုက်ရိုက်ဝင်ရောက်မှု",
        "s4":    "စစ်ဆေးချက် ၄ : Voucher / ငွေပေးချေမှု API",
        "s5":    "စစ်ဆေးချက် ၅ : Token ချုပ်နှောင်မှုနှင့် Session ပြန်သုံးမှု",
        "s6":    "စစ်ဆေးချက် ၆ : HTTPS အသုံးချမှု",
        "s7":    "စစ်ဆေးချက် ၇ : Auth တောင်းဆိုမှုများပေါ် Rate Limiting",
        "s_sum": "စစ်ဆေးချက် အကျဉ်းချုပ် အစီရင်ခံစာ",
        "s_reco":"လုံခြုံရေး အကြံပြုချက်များ",
        # Labels
        "l_target":   "ပစ်မှတ်",
        "l_date":     "နေ့စွဲ",
        "l_duration": "ကြာချိန်",
        "l_passed":   "စစ်ဆေးချက် အောင်မြင်သည်",
        "l_warned":   "သတိပေးချက် (ပြန်လည်သုံးသပ်ပါ)",
        "l_failed":   "အားနည်းချက် တွေ့ရှိသည်",
        "l_critical": "ပြင်ဆင်ရမည့် အရေးကြီးသောပြဿနာများ",
        "l_warnings": "ပြန်လည်သုံးသပ်ရမည့် သတိပေးချက်များ",
        # Check messages
        "c1a_no_redir":  "ဤကွန်ရက်မှ captive portal redirect မတွေ့ရှိပါ။",
        "c1a_no_redir_d":"Portal ကွန်ရက်အတွင်းမှ script ကို လုပ်ဆောင်ပါ။",
        "c1a_found":     "Portal redirect တွေ့ရှိသည်",
        "c1b_http":      "Portal သည် login redirect အတွက် plain HTTP ကို အသုံးပြုသည်။",
        "c1b_http_fix":  "ပြင်ဆင်မှု: HTTPS သို့ redirect လုပ်ပါ။ HTTP သည် token များကို ဖေါ်ထုတ်သည်။",
        "c1b_https":     "Portal သည် HTTPS ဖြင့် redirect လုပ်သည်။",
        "c1a_direct":    "Portal URL တိုက်ရိုက် တုံ့ပြန်သည်",
        "c1a_err":       "Portal URL သို့ ဝင်ရောက်မရပါ",
        "c2a_fail":      "Session ID / token သည် URL တွင် မြင်သာနေသည်။",
        "c2a_fix":       "ပြင်ဆင်မှု: URL တွင် auth token မထည့်ပါနှင့်။ POST body + signed cookie သုံးပါ။",
        "c2a_pass":      "URL parameter တွင် Session ID မတွေ့ရှိပါ။",
        "c2b_fail":      "Session ID သည် HTML source တွင် ထည့်သွင်းထားသည်။",
        "c2b_fix":       "ပြင်ဆင်မှု: Client HTML တွင် raw token မပြပါနှင့်။ Server-side session သုံးပါ။",
        "c2b_pass":      "HTML body တွင် Session ID မတွေ့ရှိပါ။",
        "c2c_warn":      "Hidden field တွင် token တွေ့ရှိသည် — CSRF token ဟုတ်မဟုတ် စစ်ဆေးပါ။",
        "c2c_pass":      "သံသယဖြစ်ဖွယ် hidden field token မတွေ့ရှိပါ။",
        "c2_err":        "Session ID စစ်ဆေးချက် အမှား",
        "c3a_crit":      "Auth endpoint သည် အတု token ကို လက်ခံသည် — အရေးကြီးသော အားနည်းချက်!",
        "c3a_crit_d":    "ပြင်ဆင်မှု: HMAC လက်မှတ်ဖြင့် server-side token စစ်ဆေးပါ။ Token ရှိရုံဖြင့် access မပေးပါနှင့်။",
        "c3a_warn":      "Auth endpoint HTTP 200 ပြန်လာသည် — ကိုယ်တိုင် စစ်ဆေးပါ။",
        "c3a_pass":      "Auth endpoint သည် အတု token ကို မှန်ကန်စွာ ငြင်းဆိုသည်",
        "c3a_404":       "Auth endpoint 404 ပြန်လာသည် — လမ်းကြောင်း /wifidog/auth နှင့် ကွဲနိုင်သည်။",
        "c3a_unexpected":"Auth endpoint မမျှော်လင့်သော status ပြန်လာသည်",
        "c3a_no_conn":   "Gateway သို့ ချိတ်ဆက်မရပါ — subnet ကွဲနိုင်သည်။",
        "c3a_no_conn_d": "Gateway စစ်ဆေးရန် portal LAN အတွင်းမှ လုပ်ဆောင်ပါ။",
        "c3a_err":       "Auth endpoint စစ်ဆေးချက် အမှား",
        "c4a_crit":      "Voucher API သည် အားနည်းသော test code ကို လက်ခံသည်!",
        "c4a_crit_d":    "ပြင်ဆင်မှု: ငွေပေးချေမှု မှတ်တမ်းနှင့် ချိတ်ဆက်ထားသော one-time code သုံးပါ။ ကြိမ် ၅ ကြိမ် မအောင်ပါက lock လုပ်ပါ။",
        "c4a_rate":      "Voucher API သည် rate-limit လုပ်နေသည် (HTTP 429)။ ကောင်းသည်။",
        "c4a_pass":      "Voucher API သည် test payload ကို မှန်ကန်စွာ ငြင်းဆိုသည်",
        "c4a_404":       "Voucher endpoint /api/auth/voucher/ တွင် မတွေ့ရှိပါ",
        "c4b_warn":      "Voucher API မမျှော်လင့်သော status ပြန်လာသည်",
        "c4_err":        "Voucher စစ်ဆေးချက် အမှား",
        "c5a_no_sid":    "Session ID မရှိပါ — token binding စစ်ဆေးချက် ကျော်သည်။",
        "c5a_no_sid_d":  "Session ID ရရှိရန် မှန်ကန်သော portal URL ထည့်ပါ။",
        "c5a_fail":      "Token သည် မတူသော device မှ လက်ခံသည် — binding မရှိပါ!",
        "c5a_fix":       "ပြင်ဆင်မှု: Token ကို client MAC နှင့် ချိတ်ဆက်ပါ။ MAC မကိုက်ပါက ငြင်းဆိုပါ။",
        "c5a_pass":      "Token သည် မတူသော device မှ လွယ်ကူစွာ ပြန်သုံး၍မရပါ။",
        "c5a_no_gw":     "Token binding စစ်ဆေးရန် gateway သို့ ဝင်ရောက်မရပါ။",
        "c5b_info":      "ကိုယ်တိုင်စစ်ဆေးပါ: Auth အောင်မြင်ပြီးနောက် တူညီသော token ပြန်သုံးပါက ငြင်းဆိုသင့်သည်။",
        "c6a_pass":      "Portal သည် HTTPS ဖြင့် ပေးဆောင်နေပြီ။",
        "c6a_fail":      "Portal login page သည် plain HTTP ဖြင့် ပေးဆောင်နေသည်။",
        "c6a_fix":       "ပြင်ဆင်မှု: Let's Encrypt TLS + HSTS သုံးပါ။ Portal pages အားလုံး HTTPS ဖြစ်ရမည်။",
        "c6b_info":      "HTTPS endpoint ရှိနေသည်",
        "c6b_warn":      "HTTPS ရှိသော်လည်း HTTP ဆက်သုံးနေသည် — redirect enforce လုပ်ပါ။",
        "c6b_fix":       "ပြင်ဆင်မှု: nginx/Apache တွင် HTTP→HTTPS redirect ထည့်ပါ။",
        "c6b_warn2":     "HTTPS ရှိမရှိ စစ်ဆေး၍မရပါ။",
        "c7a_pass":      "Rate limiting အလုပ်လုပ်နေသည် — HTTP 429 ပြန်လာသည်။",
        "c7a_fail":      "Portal auth path များတွင် rate limiting မတွေ့ရှိပါ။",
        "c7a_fix":       "ပြင်ဆင်မှု: nginx limit_req သုံးပါ။ IP တစ်ခုလျှင် မိနစ် ၁ request ၁၀ ခွင့်ပြုပါ။",
        # Recommendations
        "reco": [
            ("၁", "လက်မှတ်ထိုးထားသော time-limited token သုံးပါ (HMAC-SHA256)",
             "ထုတ်လုပ်မှု: HMAC(secret, sessionId+timestamp+MAC)။ Auth တိုင်း စစ်ဆေးပါ။ ၅–၁၅ မိနစ်တွင် ကုန်ဆုံးရမည်။"),
            ("၂", "Session ကို client MAC address နှင့် ချိတ်ဆက်ပါ",
             "Session စတင်သည့်အခါ client MAC မှတ်တမ်းတင်ပါ။ MAC မတူပါက auth ငြင်းဆိုပါ။"),
            ("၃", "One-time-use token သာ သုံးပါ",
             "ပထမ auth အောင်မြင်ပြီးနောက် token ကို ချက်ချင်း ပျက်ပြယ်စေပါ။ Re-auth တွင် token အသစ်လိုသည်။"),
            ("၄", "Token ကို URL တွင် မထည့်ပါနှင့်",
             "POST body သို့မဟုတ် secure HttpOnly cookie သုံးပါ။ URL token များသည် proxy log တွင် ကျန်ရှိနေသည်။"),
            ("၅", "HTTPS ကို အဆုံးစွန်အထိ enforce လုပ်ပါ",
             "Let's Encrypt + HSTS သုံးပါ။ HTTP portal များသည် WiFi ပေါ်ရှိ မည်သူမဆို token ခိုးနိုင်သည်။"),
            ("၆", "Auth endpoint အားလုံးတွင် rate-limit ထည့်ပါ",
             "nginx limit_req သုံးပါ။ Voucher ၅ ကြိမ် မအောင်မြင်ပါက IP ကို ၁၅ မိနစ် ပိတ်ပါ။"),
            ("၇", "ခိုင်မာသော captive portal solution သုံးပါ",
             "pfSense, OpenWRT+nodogsplash, သို့မဟုတ် စီးပွားဖြစ် security solution ကို စဉ်းစားပါ။"),
        ],
    },
}

CURRENT_LANG = "en"

def T(key):
    """Translate key using current language, fall back to English."""
    return LANG[CURRENT_LANG].get(key, LANG["en"].get(key, key))

# ════════════════════════════════════════════════════════════
# UI HELPERS
# ════════════════════════════════════════════════════════════
def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def section(title):
    print(f"\n{BOLD}{CYAN}{'─'*64}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*64}{RESET}")

def log(level, check_id, message, detail=""):
    tag = {"PASS": PASS_TAG, "FAIL": FAIL_TAG, "WARN": WARN_TAG, "INFO": INFO_TAG}.get(level, INFO_TAG)
    print(f"  {tag} [{check_id}] {message}")
    if detail:
        for line in detail.split("\n"):
            print(f"         {WHITE}{line}{RESET}")
    findings.append({"level": level, "id": check_id, "message": message, "detail": detail})

def show_banner():
    clear()
    print(f"\n{BOLD}{CYAN}{'═'*64}")
    print(f"  {T('banner_title')}")
    print(f"  {DIM}{T('banner_sub')}{RESET}{BOLD}{CYAN}")
    print(f"{'═'*64}{RESET}")


# ════════════════════════════════════════════════════════════
# LANGUAGE SELECTION
# ════════════════════════════════════════════════════════════
def select_language():
    show_banner()
    print(f"\n  {BOLD}{CYAN}{T('choose_lang')}{RESET}")
    print(f"\n  {T('lang_1')}")
    print(f"  {T('lang_2')}")
    while True:
        choice = input(f"\n  {T('lang_prompt')}").strip()
        if choice == "1":
            return "en"
        elif choice == "2":
            return "mm"
        else:
            print(f"  {YELLOW}Please enter 1 or 2.  ၁ သို့မဟုတ် ၂ ထည့်ပါ။{RESET}")


# ════════════════════════════════════════════════════════════
# INPUT COLLECTION
# ════════════════════════════════════════════════════════════
def collect_inputs():
    show_banner()
    print(f"\n  {YELLOW}{T('disclaimer')}{RESET}")
    input(f"\n  {T('press_enter')}")
    show_banner()
    print(f"\n  {CYAN}{'─'*50}{RESET}\n")

    portal_url = ""
    while not portal_url:
        portal_url = input(f"  {BOLD}{T('enter_portal')}{RESET}").strip()
        if portal_url and not portal_url.startswith("http"):
            portal_url = "http://" + portal_url

    gw_host_raw = input(f"  {BOLD}{T('enter_gw_host')}{RESET}").strip()
    gw_host = gw_host_raw if gw_host_raw else None

    gw_port_raw = input(f"  {BOLD}{T('enter_gw_port')}{RESET}").strip()
    gw_port = int(gw_port_raw) if gw_port_raw.isdigit() else 2060

    return portal_url, gw_host, gw_port


# ════════════════════════════════════════════════════════════
# CHECK 1 — Portal Detection
# ════════════════════════════════════════════════════════════
def check_portal_detection(session, portal_url):
    section(T("s1"))
    try:
        r = session.get(
            "http://connectivitycheck.gstatic.com/generate_204",
            allow_redirects=True, timeout=8, verify=False
        )
        if r.status_code == 204 and "connectivitycheck" in r.url:
            log("WARN", "C1-A", T("c1a_no_redir"), T("c1a_no_redir_d"))
            return None

        redirect_url = r.url
        log("INFO", "C1-A", f"{T('c1a_found')} → {redirect_url}")

        if urlparse(redirect_url).scheme == "http":
            log("FAIL", "C1-B", T("c1b_http"), T("c1b_http_fix"))
        else:
            log("PASS", "C1-B", T("c1b_https"))
        return redirect_url

    except requests.exceptions.ConnectionError:
        try:
            r = session.get(portal_url, verify=False, timeout=8)
            log("INFO", "C1-A", f"{T('c1a_direct')}: HTTP {r.status_code}")
            return portal_url
        except Exception as e:
            log("WARN", "C1-A", f"{T('c1a_err')}: {e}")
            return None
    except Exception as e:
        log("WARN", "C1-A", f"{T('c1a_err')}: {e}")
        return None


# ════════════════════════════════════════════════════════════
# CHECK 2 — Session ID Exposure
# ════════════════════════════════════════════════════════════
def check_session_id_in_url(session, portal_url):
    section(T("s2"))
    sid = None
    try:
        r1 = session.get(portal_url, verify=False, timeout=8, allow_redirects=True)

        js_match = re.search(r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", r1.text)
        if js_match:
            next_url = urljoin(portal_url, js_match.group(1))
            r1 = session.get(next_url, verify=False, timeout=8)

        qs = parse_qs(urlparse(r1.url).query)
        if any(k in qs for k in ("sessionId", "token", "sid")):
            sid = (qs.get("sessionId") or qs.get("token") or qs.get("sid"))[0]
            log("FAIL", "C2-A", T("c2a_fail"),
                f"Value: {sid[:12]}...\n{T('c2a_fix')}")
        else:
            log("PASS", "C2-A", T("c2a_pass"))

        sid_body = re.search(r'sessionId[=\s:]+([a-zA-Z0-9\-_]{8,})', r1.text)
        if sid_body:
            if not sid:
                sid = sid_body.group(1)
            log("FAIL", "C2-B", T("c2b_fail"), T("c2b_fix"))
        else:
            log("PASS", "C2-B", T("c2b_pass"))

        hidden = re.search(
            r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([a-zA-Z0-9\-_]{10,})["\']',
            r1.text
        )
        log("WARN" if hidden else "PASS", "C2-C",
            T("c2c_warn") if hidden else T("c2c_pass"))

        return sid
    except Exception as e:
        log("WARN", "C2-X", f"{T('c2_err')}: {e}")
        return None


# ════════════════════════════════════════════════════════════
# CHECK 3 — Auth Endpoint Direct Access
# ════════════════════════════════════════════════════════════
def check_auth_endpoint(session, portal_url, gw_host=None, gw_port=None):
    section(T("s3"))

    if not gw_host:
        parsed = urlparse(portal_url)
        qs = parse_qs(parsed.query)
        gw_host = qs.get("gw_address", [parsed.hostname])[0]
        gw_port = qs.get("gw_port", [str(gw_port or 2060)])[0]

    fake_token = "AUDIT_TEST_FAKE_TOKEN_000000"
    test_url   = f"http://{gw_host}:{gw_port}/wifidog/auth?token={fake_token}"

    try:
        r = requests.get(test_url, timeout=6, verify=False)
        body_lower = r.text.lower()
        if r.status_code == 200 and any(
            w in body_lower for w in ["auth", "grant", "allow", "success", "welcome"]
        ):
            log("FAIL", "C3-A", T("c3a_crit"),
                f"URL: {test_url}\nResponse: {r.text[:200]}\n{T('c3a_crit_d')}")
        elif r.status_code == 200:
            log("WARN", "C3-A", T("c3a_warn"), f"Response: {r.text[:200]}")
        elif r.status_code in (401, 403):
            log("PASS", "C3-A", f"{T('c3a_pass')} (HTTP {r.status_code}).")
        elif r.status_code == 404:
            log("INFO", "C3-A", T("c3a_404"))
        else:
            log("WARN", "C3-A", f"{T('c3a_unexpected')}: HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        log("INFO", "C3-A", T("c3a_no_conn"), T("c3a_no_conn_d"))
    except Exception as e:
        log("WARN", "C3-A", f"{T('c3a_err')}: {e}")


# ════════════════════════════════════════════════════════════
# CHECK 4 — Voucher Endpoint
# ════════════════════════════════════════════════════════════
def check_voucher_endpoint(session, portal_url):
    section(T("s4"))
    parsed = urlparse(portal_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    voucher_url = f"{base}/api/auth/voucher/"

    payloads = [
        {"accessCode": "000000", "sessionId": "fake_audit", "apiVersion": 1},
        {"accessCode": "123456", "sessionId": "fake_audit", "apiVersion": 1},
        {"accessCode": "111111", "sessionId": "fake_audit", "apiVersion": 1},
    ]
    try:
        for payload in payloads:
            r = session.post(voucher_url, json=payload, timeout=6, verify=False)
            bl = r.text.lower()
            if r.status_code == 200 and any(
                w in bl for w in ["success", "token", "grant", "auth", "valid"]
            ):
                log("FAIL", "C4-A",
                    f"{T('c4a_crit')} (code: {payload['accessCode']})",
                    f"Response: {r.text[:200]}\n{T('c4a_crit_d')}")
                return
            elif r.status_code == 429:
                log("PASS", "C4-A", T("c4a_rate")); return
            elif r.status_code in (401, 403):
                log("PASS", "C4-A", f"{T('c4a_pass')} (HTTP {r.status_code})."); return
            elif r.status_code == 404:
                log("INFO", "C4-A", T("c4a_404")); return
            else:
                log("WARN", "C4-B", f"{T('c4b_warn')}: HTTP {r.status_code}")
    except requests.exceptions.ConnectionError:
        log("INFO", "C4-A", f"{T('c4a_404')} — {voucher_url}")
    except Exception as e:
        log("WARN", "C4-A", f"{T('c4_err')}: {e}")


# ════════════════════════════════════════════════════════════
# CHECK 5 — Token Binding
# ════════════════════════════════════════════════════════════
def check_token_binding(session, portal_url, sid):
    section(T("s5"))
    if not sid:
        log("INFO", "C5-A", T("c5a_no_sid"), T("c5a_no_sid_d"))
        return

    parsed = urlparse(portal_url)
    qs = parse_qs(parsed.query)
    gw_host = qs.get("gw_address", [parsed.hostname])[0]
    gw_port = qs.get("gw_port", ["2060"])[0]
    auth_url = f"http://{gw_host}:{gw_port}/wifidog/auth?token={sid}"

    alt = requests.Session()
    alt.headers["User-Agent"] = (
        "Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36"
    )
    try:
        r = alt.get(auth_url, timeout=6, verify=False)
        if r.status_code == 200 and any(
            w in r.text.lower() for w in ["auth", "grant", "allow", "success"]
        ):
            log("FAIL", "C5-A", T("c5a_fail"), T("c5a_fix"))
        else:
            log("PASS", "C5-A", T("c5a_pass"))
    except Exception:
        log("INFO", "C5-A", T("c5a_no_gw"))

    log("INFO", "C5-B", T("c5b_info"))


# ════════════════════════════════════════════════════════════
# CHECK 6 — HTTPS
# ════════════════════════════════════════════════════════════
def check_https(portal_url):
    section(T("s6"))
    parsed = urlparse(portal_url)
    base_https = f"https://{parsed.netloc}"

    if parsed.scheme == "https":
        log("PASS", "C6-A", T("c6a_pass"))
    else:
        log("FAIL", "C6-A", T("c6a_fail"), T("c6a_fix"))

    try:
        r = requests.get(base_https, timeout=6, verify=False)
        if r.status_code < 400:
            log("INFO", "C6-B", f"{T('c6b_info')}: {base_https} (HTTP {r.status_code})")
            if parsed.scheme == "http":
                log("WARN", "C6-B", T("c6b_warn"), T("c6b_fix"))
        else:
            log("WARN", "C6-B", T("c6b_warn2"))
    except Exception:
        if parsed.scheme == "http":
            log("WARN", "C6-B", T("c6b_warn2"))


# ════════════════════════════════════════════════════════════
# CHECK 7 — Rate Limiting
# ════════════════════════════════════════════════════════════
def check_rate_limiting(session, portal_url):
    section(T("s7"))
    parsed = urlparse(portal_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in ["/login", "/auth", "/portal", "/"]:
        try:
            codes = []
            for _ in range(8):
                r = session.get(base + path, verify=False, timeout=4)
                codes.append(r.status_code)
                time.sleep(0.1)
            if 429 in codes:
                log("PASS", "C7-A", f"{T('c7a_pass')} ({path})")
                return
        except Exception:
            continue
    log("FAIL", "C7-A", T("c7a_fail"), T("c7a_fix"))


# ════════════════════════════════════════════════════════════
# REPORT
# ════════════════════════════════════════════════════════════
def print_report(portal_url, start_time):
    section(T("s_sum"))
    failed  = [f for f in findings if f["level"] == "FAIL"]
    warned  = [f for f in findings if f["level"] == "WARN"]
    passed  = [f for f in findings if f["level"] == "PASS"]
    elapsed = time.time() - start_time

    print(f"\n  {BOLD}{T('l_target')}:{RESET}    {portal_url}")
    print(f"  {BOLD}{T('l_date')}:{RESET}      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {BOLD}{T('l_duration')}:{RESET}  {elapsed:.1f}s\n")
    print(f"  {GREEN}PASS{RESET}  {len(passed):>3}  {T('l_passed')}")
    print(f"  {YELLOW}WARN{RESET}  {len(warned):>3}  {T('l_warned')}")
    print(f"  {RED}FAIL{RESET}  {len(failed):>3}  {T('l_failed')}\n")

    if failed:
        print(f"  {BOLD}{RED}{T('l_critical')}:{RESET}")
        for f in failed:
            print(f"    {RED}✗{RESET} [{f['id']}] {f['message']}")
    if warned:
        print(f"\n  {BOLD}{YELLOW}{T('l_warnings')}:{RESET}")
        for w in warned:
            print(f"    {YELLOW}△{RESET} [{w['id']}] {w['message']}")

    section(T("s_reco"))
    for num, title, detail in T("reco"):
        print(f"\n  {CYAN}{num}.{RESET} {BOLD}{title}{RESET}")
        print(f"     {WHITE}{detail}{RESET}")

    report_file = "captive_portal_audit_report.json"
    report_data = {
        "target":    portal_url,
        "language":  CURRENT_LANG,
        "timestamp": datetime.now().isoformat(),
        "summary":   {"pass": len(passed), "warn": len(warned), "fail": len(failed)},
        "findings":  findings,
        "recommendations": [
            {"id": r[0], "title": r[1], "detail": r[2]} for r in T("reco")
        ],
    }
    with open(report_file, "w", encoding="utf-8") as fp:
        json.dump(report_data, fp, indent=2, ensure_ascii=False)

    print(f"\n\n  {GREEN}[✓]{RESET} {T('saved')}: {BOLD}{report_file}{RESET}\n")


# ════════════════════════════════════════════════════════════
# RUN AUDIT
# ════════════════════════════════════════════════════════════
def run_audit():
    global findings
    findings = []

    portal_url, gw_host, gw_port = collect_inputs()

    show_banner()
    print(f"\n  {CYAN}{T('starting')}{RESET}\n")
    start_time = time.time()

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (CaptivePortalAudit/2.0 SecurityCheck)"

    detected = check_portal_detection(session, portal_url)
    effective = detected or portal_url
    sid = check_session_id_in_url(session, effective)
    check_auth_endpoint(session, effective, gw_host, gw_port)
    check_voucher_endpoint(session, effective)
    check_token_binding(session, effective, sid)
    check_https(effective)
    check_rate_limiting(session, effective)

    print_report(portal_url, start_time)
    print(f"  {GREEN}{T('done')}{RESET}")
    input(f"\n  {T('back_menu')}")


# ════════════════════════════════════════════════════════════
# MAIN MENU
# ════════════════════════════════════════════════════════════
def main_menu():
    global CURRENT_LANG
    CURRENT_LANG = select_language()

    while True:
        show_banner()
        print(f"\n  {BOLD}{T('main_menu')}{RESET}\n")
        print(f"  {GREEN}{T('opt_1')}{RESET}")
        print(f"  {CYAN}{T('opt_2')}{RESET}")
        print(f"  {RED}{T('opt_3')}{RESET}")

        choice = input(f"\n  {BOLD}{T('menu_prompt')}{RESET}").strip()

        if choice == "1":
            try:
                run_audit()
            except KeyboardInterrupt:
                print(f"\n  {YELLOW}Audit interrupted.{RESET}")
                input(f"  {T('back_menu')}")
        elif choice == "2":
            CURRENT_LANG = select_language()
        elif choice == "3":
            print(f"\n  {GREEN}{T('goodbye')}{RESET}\n")
            sys.exit(0)
        else:
            print(f"\n  {RED}{T('invalid')}{RESET}")
            time.sleep(1)


# ════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Program terminated.{RESET}\n")
        sys.exit(0)
