# Shared HTTP wrapper. All modules go through here so stealth mode,
# header rotation, and SSL handling stay in one place.

import requests
import urllib3

from utils import stealth

# Certificate verification is deliberately disabled. This tool targets
# live pentest engagements where self-signed certs, expired certs, and
# internal CAs are common and expected, not a defect. Verification is
# controlled here in a single place rather than repeated per request.
VERIFY_SSL = False  # NOSONAR - intentional for security testing, see comment above

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _headers(extra=None, cookie=None):
    h = stealth.random_headers() if (stealth.WAF_EVASION_MODE or stealth.STEALTH_MODE) else {"User-Agent": DEFAULT_UA}
    if extra:
        h.update(extra)
    if cookie:
        h["Cookie"] = cookie
    return h


def get(url, allow_redirects=True, timeout=10, headers=None, cookie=None):
    stealth.short_jitter()
    try:
        return requests.get(
            url,
            allow_redirects = allow_redirects,
            headers         = _headers(headers, cookie),
            timeout         = timeout,
            verify          = VERIFY_SSL,
        )
    except requests.exceptions.RequestException:
        return None


def post(url, data, headers=None, allow_redirects=True, timeout=10, cookie=None):
    stealth.jitter()
    try:
        return requests.post(
            url,
            data            = data,
            headers         = _headers(headers, cookie),
            allow_redirects = allow_redirects,
            timeout         = timeout,
            verify          = VERIFY_SSL,
        )
    except requests.exceptions.RequestException:
        return None


def post_json(url, payload, headers=None, timeout=10, cookie=None):
    stealth.jitter()
    try:
        return requests.post(
            url,
            json    = payload,
            headers = _headers(headers, cookie),
            timeout = timeout,
            verify  = VERIFY_SSL,
        )
    except requests.exceptions.RequestException:
        return None
