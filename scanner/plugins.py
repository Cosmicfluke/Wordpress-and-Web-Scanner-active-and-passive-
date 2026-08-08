# Plugin detection: passive scan from HTML + WAF-aware active wordlist probing.
# When WAF evasion mode is on, cover requests are interspersed between probes.

import re
import random
from colorama import Fore, Style
from utils.http import get
from utils import wpscan_db, stealth

_rng = random.SystemRandom()

PLUGIN_REF = re.compile(r"wp-content/plugins/([a-zA-Z0-9_\-]+)/[^'\"]*\?ver=([\d.]+)")
PLUGIN_REF_NOVER = re.compile(r"wp-content/plugins/([a-zA-Z0-9_\-]+)/")

DEFAULT_WORDLIST = [
    "akismet","yoast-seo","wordpress-seo","elementor","contact-form-7",
    "woocommerce","jetpack","wp-super-cache","wpforms-lite","all-in-one-seo-pack",
    "duplicate-post","classic-editor","really-simple-ssl","wordfence",
    "updraftplus","ninja-forms","wp-fastest-cache","litespeed-cache",
    "w3-total-cache","wp-rocket","rankmath","wp-mail-smtp","sucuri-scanner",
    "ithemes-security","all-in-one-wp-security-and-firewall","loginizer",
    "wp-file-manager","wps-hide-login","advanced-custom-fields","acf-pro",
    "gravityforms","bbpress","buddypress","woocommerce-subscriptions",
    "woocommerce-memberships","the-events-calendar","tablepress",
    "wp-migrate-db","duplicator","backup-buddy","managewp-worker",
    "mainwp-child","wp-optimize","smush","imagify","shortpixel-image-optimiser",
    "elementor-pro","essential-addons-for-elementor","elementskit-lite",
    "happy-elementor-addons","premium-addons-for-elementor",
    "ultimate-addons-for-elementor","crocoblock","king-composer",
    "beaver-builder-lite-version","divi-builder","visual-composer",
    "wpbakery-page-builder","fusion-builder","brizy","oxygen",
    "wp-members","user-role-editor","members","capability-manager-enhanced",
    "profile-builder","ultimate-member","paid-memberships-pro",
    "restrict-content","s2member","learndash","lifterms","tutor",
    "wplms","learnpress","sensei-lms","moodle",
    "easy-digital-downloads","give","charitable","stripe-payments",
    "paypal-for-woocommerce","checkout-plugins-stripe-woo",
    "polylang","wpml","translatepress","weglot",
    "wp-loco","loco-translate","say-what",
    "wp-seopress","squirrly-seo","premium-seo-pack","the-seo-framework",
    "broken-link-checker","google-analytics-for-wordpress","monsterinsights",
    "cookie-law-info","gdpr-cookie-compliance","complianz",
    "wp-hide-security-enhancer","hide-my-wp","wp-cerber",
    "anti-spam","cleantalk","zero-spam",
    "insert-headers-and-footers","header-footer-code-manager",
    "custom-post-type-ui","pods","toolset-types",
    "ninja-tables","wp-table-builder",
    "popup-maker","popups-for-divi","mailchimp-for-wp",
    "fluent-smtp","postman-smtp",
    "ewww-image-optimizer","robin-image-optimizer",
    "autoptimize","flying-scripts","asset-cleanup",
    "svg-support","safe-svg","enhanced-media-library",
    "media-library-assistant","real-media-library",
    "wp-cloudflare-page-cache","sg-cachepress","hummingbird-performance",
    "redis-cache","wp-redis","object-cache-pro",
]


def detect_from_html(html):
    found = {}
    for slug, ver in PLUGIN_REF.findall(html):
        found[slug] = ver
    for slug in PLUGIN_REF_NOVER.findall(html):
        found.setdefault(slug, None)
    return found


def _probe_single(base_url, slug):
    for path in [
        f"/wp-content/plugins/{slug}/readme.txt",
        f"/wp-content/plugins/{slug}/README.txt",
        f"/wp-content/plugins/{slug}/{slug}.php",
    ]:
        resp = get(base_url.rstrip("/") + path)
        if resp and resp.status_code == 200:
            m = re.search(r"(?:Stable tag|Version):\s*([\d.]+)", resp.text, re.I)
            return m.group(1) if m else "detected"
    return None


def probe_wordlist(base_url, wordlist, waf_detected=False):
    found = {}
    slugs = list(wordlist)

    if waf_detected:
        _rng.shuffle(slugs)

    for i, slug in enumerate(slugs):
        ver = _probe_single(base_url, slug)
        if ver:
            found[slug] = ver

        if waf_detected and i % 3 == 2:
            stealth.cover_request(base_url)

    return found


def run(base_url, html, wordlist=None, active_probe=False, waf_detected=False):
    print(f"{Fore.CYAN}[*] Detecting plugins from page source...{Style.RESET_ALL}")
    plugins = detect_from_html(html)

    if active_probe:
        wl = wordlist or DEFAULT_WORDLIST
        mode = "WAF-evasion mode" if waf_detected else "standard mode"
        print(f"{Fore.CYAN}[*] Active plugin probe ({len(wl)} slugs, {mode})...{Style.RESET_ALL}")
        plugins.update(probe_wordlist(base_url, wl, waf_detected=waf_detected))

    results = {}
    if not plugins:
        print(f"{Fore.YELLOW}[!] No plugins detected{Style.RESET_ALL}")
        return results

    for slug, ver in plugins.items():
        ver_str = ver or "unknown"
        print(f"{Fore.GREEN}[+] Plugin: {slug} (version: {ver_str}){Style.RESET_ALL}")
        vulns = wpscan_db.plugin_vulns(slug, ver)
        results[slug] = {"version": ver, "vulnerabilities": vulns}
        for v in vulns:
            cvss = v.get("cvss") or "?"
            print(f"{Fore.RED}    [CVE] {v['title']} (CVSS: {cvss}){Style.RESET_ALL}")

    return results