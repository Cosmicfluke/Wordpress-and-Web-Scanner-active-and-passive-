# Stealth and WAF evasion controls.
# STEALTH_MODE: random delays + UA rotation, enabled via --stealth.
# WAF_EVASION_MODE: full browser headers + cover requests, auto-enabled
#                   when waf.py detects a firewall.

import time
import random

# Using SystemRandom rather than the default random module. Nothing here
# is security-sensitive (user-agent choice, delay timing), but this
# satisfies static analysis that flags the default PRNG regardless of
# context, and there's no real downside to using it.
_rng = random.SystemRandom()

STEALTH_MODE     = False
WAF_EVASION_MODE = False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

ACCEPT_LANG = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-AU,en;q=0.8,en-US;q=0.6",
]

COVER_PATHS = ["/", "/about/", "/contact/", "/blog/", "/?p=1", "/sample-page/"]


def enable():
    global STEALTH_MODE
    STEALTH_MODE = True


def enable_waf_evasion():
    global WAF_EVASION_MODE
    WAF_EVASION_MODE = True


def random_ua():
    return _rng.choice(USER_AGENTS)


def random_headers():
    return {
        "User-Agent"               : random_ua(),
        "Accept"                   : _rng.choice(ACCEPT_HEADERS),
        "Accept-Language"          : _rng.choice(ACCEPT_LANG),
        "Accept-Encoding"          : "gzip, deflate, br",
        "Connection"               : "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest"           : "document",
        "Sec-Fetch-Mode"           : "navigate",
        "Sec-Fetch-Site"           : "none",
        "Sec-Fetch-User"           : "?1",
        "Cache-Control"            : "max-age=0",
    }


def jitter(min_s=1.5, max_s=4.5):
    if STEALTH_MODE or WAF_EVASION_MODE:
        time.sleep(_rng.uniform(min_s, max_s))


def short_jitter():
    if STEALTH_MODE:
        time.sleep(_rng.uniform(0.3, 1.2))
    elif WAF_EVASION_MODE:
        time.sleep(_rng.uniform(0.8, 2.5))


def cover_request(base_url):
    if not WAF_EVASION_MODE:
        return
    from utils.http import get
    try:
        get(base_url.rstrip("/") + _rng.choice(COVER_PATHS), timeout=5)
    except Exception:
        pass
    time.sleep(_rng.uniform(1.0, 3.0))