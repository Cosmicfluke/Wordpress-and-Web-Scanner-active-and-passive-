# WordPress recon module.
# Confirms target is WordPress and fingerprints the core version.
# Always tries alternate paths alongside homepage detection — handles
# Cloudflare caching and custom themes that strip WP indicators.

import re
from colorama import Fore, Style
from utils.http import get

VERSION_PATTERNS = [
    re.compile(r'<meta name="generator" content="WordPress ([\d.]+)"', re.I),
    re.compile(r'wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)'),
    re.compile(r'wp-includes/css/dist/block-library/style\.min\.css\?ver=([\d.]+)'),
]

WP_INDICATORS = ["wp-content", "wp-includes", "wp-json"]


def _is_wp_html(html):
    return any(s in html for s in WP_INDICATORS)


def _detect_via_fallback(base_url):
    """
    Try known WordPress paths to confirm detection when the homepage
    doesn't contain WP indicators (Cloudflare cache, custom themes, etc).
    """
    for path in ["/wp-login.php", "/wp-json/", "/feed/", "/wp-admin/"]:
        resp = get(base_url.rstrip("/") + path)
        if not resp:
            continue

        # wp-login.php returning a login form is definitive.
        if path == "/wp-login.php" and resp.status_code == 200 and "user_login" in resp.text:
            return True, resp.text

        # Any other path with WP strings in a 200 response confirms it.
        if resp.status_code == 200 and _is_wp_html(resp.text):
            return True, resp.text

        # WordPress adds a Link: <.../wp-json/>; rel="https://api.w.org/" header
        # to every response — even when the body has been stripped by a CDN.
        if "wp-json" in resp.headers.get("Link", ""):
            return True, resp.text

    return False, ""


def is_wordpress(base_url):
    resp = get(base_url)
    if resp is None:
        return False, ""

    html = resp.text

    # Hard block on homepage — go straight to fallback.
    if resp.status_code in (403, 406, 503):
        print(f"{Fore.YELLOW}[!] Homepage blocked ({resp.status_code}) — trying alternate paths{Style.RESET_ALL}")
        return _detect_via_fallback(base_url)

    # Homepage loaded fine and contains WP indicators — confirmed.
    if _is_wp_html(html):
        return True, html

    # Also check the Link header on the homepage response itself.
    if "wp-json" in resp.headers.get("Link", ""):
        return True, html

    # Homepage returned 200 but no WP indicators — could be Cloudflare
    # serving a cached page or a custom theme. Try alternate paths.
    print(f"{Fore.YELLOW}[!] WP indicators not found on homepage — trying alternate paths{Style.RESET_ALL}")
    fallback_confirmed, fallback_html = _detect_via_fallback(base_url)

    if fallback_confirmed:
        # Return homepage HTML for asset scanning, confirmed via fallback.
        return True, html or fallback_html

    return False, html


def fingerprint_version(base_url, html):
    # Try page source first — fastest and most reliable.
    for pattern in VERSION_PATTERNS:
        m = pattern.search(html)
        if m:
            return m.group(1)

    # readme.html is often left in place and always has the version.
    resp = get(f"{base_url.rstrip('/')}/readme.html")
    if resp and resp.status_code == 200:
        m = re.search(r"Version ([\d.]+)", resp.text)
        if m:
            return m.group(1)

    # wp-json root exposes the WP version in the "version" field.
    resp = get(f"{base_url.rstrip('/')}/wp-json/")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            version = data.get("version") or data.get("gmt_offset")
            if version and re.match(r"[\d.]+", str(version)):
                return str(version)
        except ValueError:
            pass

    return None


def run(base_url):
    print(f"{Fore.CYAN}[*] Checking if target is WordPress...{Style.RESET_ALL}")

    confirmed, html = is_wordpress(base_url)
    result = {"is_wordpress": confirmed, "version": None, "html": html}

    if not confirmed:
        print(f"{Fore.RED}[-] Target does not appear to be WordPress{Style.RESET_ALL}")
        return result

    print(f"{Fore.GREEN}[+] WordPress confirmed{Style.RESET_ALL}")

    version = fingerprint_version(base_url, html)
    result["version"] = version

    if version:
        print(f"{Fore.GREEN}[+] WordPress version: {version}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Could not fingerprint WordPress version{Style.RESET_ALL}")

    return result
