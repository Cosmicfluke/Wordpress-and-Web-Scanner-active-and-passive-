"""
Application-level checks: WP_DEBUG, open registration, info-leaking feeds,
oembed/sitemap disclosure, and open redirects.
"""

import re
from colorama import Fore, Style
from utils.http import get
from utils.severity import finding, badge, HIGH, MEDIUM, LOW, INFO


def check_debug_mode(base_url, html):
    findings = []
    debug_patterns = [
        r"<b>Fatal error</b>",
        r"<b>Warning</b>:",
        r"<b>Notice</b>:",
        r"Stack trace:",
        r"wp-content/debug\.log",
        r"define\('WP_DEBUG',\s*true\)",
    ]
    for pattern in debug_patterns:
        if re.search(pattern, html, re.I):
            findings.append(finding(
                title="WordPress Debug Mode Enabled / PHP Errors Exposed",
                severity=HIGH,
                description="PHP errors, warnings, or debug output are visible in page source.",
                impact="Exposes server paths, database structure, and code logic to attackers.",
                remediation="Set WP_DEBUG to false in wp-config.php. Never enable debug mode on production.",
                evidence=re.search(pattern, html, re.I).group(0)[:120],
            ))
            break
    return findings


def check_open_registration(base_url):
    findings = []
    url = f"{base_url.rstrip('/')}/wp-login.php?action=register"
    resp = get(url)
    if resp and resp.status_code == 200 and "user_login" in resp.text and "user_email" in resp.text:
        findings.append(finding(
            title="Open User Registration Enabled",
            severity=MEDIUM,
            description="WordPress user registration is publicly accessible at /wp-login.php?action=register.",
            impact="Anyone can create an account. If subscriber role has excessive permissions or a vulnerable plugin grants elevated access, this becomes a foothold.",
            remediation='Disable "Anyone can register" in Settings > General, unless explicitly required.',
            evidence=f"Registration page responded with HTTP 200",
        ))
    return findings


def check_feed_disclosure(base_url):
    findings = []
    feeds = ["/feed/", "/?feed=rss2", "/?feed=atom"]
    for path in feeds:
        url = base_url.rstrip("/") + path
        resp = get(url)
        if resp and resp.status_code == 200 and ("<rss" in resp.text or "<feed" in resp.text):
            # Check if author info leaks
            if "<author>" in resp.text or "<dc:creator>" in resp.text:
                findings.append(finding(
                    title="RSS/Atom Feed Discloses Author Usernames",
                    severity=LOW,
                    description=f"The feed at {path} includes author display names or usernames.",
                    impact="Username enumeration via feed. Combined with xmlrpc or login brute-force, reduces attack complexity.",
                    remediation="Use a plugin to anonymise feed author data, or restrict feed access if not needed.",
                    evidence=f"Feed accessible at: {url}",
                ))
            break
    return findings


def check_oembed_disclosure(base_url):
    findings = []
    url = f"{base_url.rstrip('/')}/?oembed=1&url={base_url}&format=json"
    resp = get(url)
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            author = data.get("author_name") or data.get("author_url")
            if author:
                findings.append(finding(
                    title="oEmbed Endpoint Discloses Author Information",
                    severity=LOW,
                    description="The WordPress oEmbed endpoint returns author names or URLs.",
                    impact="Contributes to user enumeration. Low impact alone, part of a wider recon chain.",
                    remediation="Disable oEmbed if not needed, or filter the author fields from the response.",
                    evidence=f"author_name: {data.get('author_name')} | author_url: {data.get('author_url')}",
                ))
        except ValueError:
            pass
    return findings


def check_sitemap(base_url):
    findings = []
    paths = ["/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"]
    for path in paths:
        url = base_url.rstrip("/") + path
        resp = get(url)
        if resp and resp.status_code == 200 and "<urlset" in resp.text or (resp and "<sitemapindex" in resp.text):
            findings.append(finding(
                title="XML Sitemap Publicly Accessible",
                severity=INFO,
                description=f"An XML sitemap was found at {path}.",
                impact="Enumerates all public URLs, posts, categories, and pages. Useful for attacker reconnaissance.",
                remediation="Restrict sitemap access if the site is not intended to be indexed, or review what the sitemap exposes.",
                evidence=f"Sitemap found: {url}",
            ))
            break
    return findings


def run(base_url, html, active=False):
    print(f"{Fore.CYAN}[*] Running application-level checks...{Style.RESET_ALL}")
    findings = []

    # Note: open redirect is checked in injection.py, not here — avoids
    # reporting the same finding twice under two different sections.
    for check_fn, args in [
        (check_debug_mode,        (base_url, html)),
        (check_open_registration, (base_url,)),
        (check_feed_disclosure,   (base_url,)),
        (check_oembed_disclosure, (base_url,)),
        (check_sitemap,           (base_url,)),
    ]:
        results = check_fn(*args)
        for f in results:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No application-level issues found{Style.RESET_ALL}")

    return findings
