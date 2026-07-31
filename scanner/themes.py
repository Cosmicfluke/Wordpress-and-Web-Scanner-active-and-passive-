"""
Theme detection: identify active theme from HTML, fingerprint version, CVE lookup.
"""

import re
from colorama import Fore, Style
from utils.http import get
from utils import wpscan_db

THEME_REF = re.compile(r"wp-content/themes/([a-zA-Z0-9_\-]+)/[^'\"]*\?ver=([\d.]+)")
THEME_REF_NOVER = re.compile(r"wp-content/themes/([a-zA-Z0-9_\-]+)/")


def detect_active_theme(html):
    m = THEME_REF.search(html)
    if m:
        return m.group(1), m.group(2)
    m = THEME_REF_NOVER.search(html)
    if m:
        return m.group(1), None
    return None, None


def fingerprint_via_style_css(base_url, slug):
    """style.css header often discloses 'Version: x.y.z' even when query string doesn't."""
    url = f"{base_url.rstrip('/')}/wp-content/themes/{slug}/style.css"
    resp = get(url)
    if resp and resp.status_code == 200:
        m = re.search(r"Version:\s*([\d.]+)", resp.text)
        if m:
            return m.group(1)
    return None


def run(base_url, html):
    print(f"{Fore.CYAN}[*] Detecting active theme...{Style.RESET_ALL}")
    slug, version = detect_active_theme(html)

    if not slug:
        print(f"{Fore.YELLOW}[!] Could not detect active theme{Style.RESET_ALL}")
        return {}

    if not version:
        version = fingerprint_via_style_css(base_url, slug)

    ver_str = version or "unknown"
    print(f"{Fore.GREEN}[+] Theme: {slug} (version: {ver_str}){Style.RESET_ALL}")

    vulns = wpscan_db.theme_vulns(slug, version)
    for v in vulns:
        cvss = v.get("cvss") or "?"
        print(f"{Fore.RED}    [CVE] {v['title']} (CVSS: {cvss}){Style.RESET_ALL}")

    return {slug: {"version": version, "vulnerabilities": vulns}}
