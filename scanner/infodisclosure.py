"""
Information disclosure checks: PHP path errors, wp-json private post exposure,
comment author email harvesting, Jetpack/Yoast data leaks, mu-plugins detection.
"""

import re
from colorama import Fore, Style
from utils.http import get
from utils.severity import finding, badge, HIGH, MEDIUM, LOW, INFO


def check_path_disclosure(base_url):
    findings = []
    triggers = [
        "/?author=9999999",
        "/wp-includes/rss-functions.php",
        "/wp-admin/admin-ajax.php",
    ]
    path_pattern = re.compile(r"(/home/|/var/www/|/srv/|/usr/share/nginx/|C:\\|/opt/)[^\s<\"']+", re.I)

    for path in triggers:
        resp = get(base_url.rstrip("/") + path)
        if resp and resp.status_code in (200, 400, 500):
            m = path_pattern.search(resp.text)
            if m:
                findings.append(finding(
                    title="Full Server Path Disclosed in Response",
                    severity=MEDIUM,
                    description=f"A server-side file path was found in the response from {path}.",
                    impact="Reveals server directory structure, helping attackers target file inclusion or path traversal attacks.",
                    remediation="Disable PHP error display on production (display_errors = Off in php.ini). Set WP_DEBUG to false.",
                    evidence=f"Path found: {m.group(0)[:120]}",
                ))
                break
    return findings


def check_wpjson_private_posts(base_url):
    findings = []
    endpoints = [
        "/wp-json/wp/v2/posts?status=draft",
        "/wp-json/wp/v2/posts?status=private",
        "/wp-json/wp/v2/pages?status=draft",
        "/wp-json/wp/v2/media?per_page=5",
    ]
    for ep in endpoints:
        resp = get(base_url.rstrip("/") + ep)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    findings.append(finding(
                        title=f"wp-json Exposes Non-Public Content: {ep.split('?')[0]}",
                        severity=MEDIUM,
                        description=f"The REST API endpoint {ep} returned content that may include non-public posts or media.",
                        impact="Draft, private, or unpublished content may be readable without authentication.",
                        remediation="Review REST API permissions. Disable public access to sensitive post types via the REST API or a plugin.",
                        evidence=f"Endpoint returned {len(data)} item(s)",
                    ))
            except ValueError:
                pass
    return findings


def check_comment_email_harvest(base_url):
    findings = []
    resp = get(f"{base_url.rstrip('/')}/wp-json/wp/v2/comments?per_page=5")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            emails = []
            for comment in data:
                author_email = comment.get("author_email", "")
                if author_email and "@" in author_email:
                    emails.append(author_email)
            if emails:
                findings.append(finding(
                    title="Comment Author Email Addresses Exposed via REST API",
                    severity=MEDIUM,
                    description="The wp-json/wp/v2/comments endpoint returns commenter email addresses.",
                    impact="Email addresses can be harvested for phishing or used to enumerate valid accounts.",
                    remediation="Filter email fields from the REST API response. Use a plugin to disable comment author email exposure.",
                    evidence=f"Emails found: {', '.join(emails[:3])}{'...' if len(emails) > 3 else ''}",
                ))
        except ValueError:
            pass
    return findings


def check_yoast_sitemap_leak(base_url):
    findings = []
    resp = get(f"{base_url.rstrip('/')}/wp-sitemap-users-1.xml")
    if resp and resp.status_code == 200 and "<urlset" in resp.text:
        usernames = re.findall(r"/author/([^/]+)/", resp.text)
        if usernames:
            findings.append(finding(
                title="Yoast/Core Sitemap Leaks Author Usernames",
                severity=LOW,
                description="The WordPress user sitemap exposes author slugs which often match login usernames.",
                impact="Username enumeration via sitemap. Reduces brute-force complexity.",
                remediation="Disable the user sitemap in Yoast SEO settings or via a filter hook.",
                evidence=f"Usernames found: {', '.join(set(usernames[:5]))}",
            ))
    return findings


def check_mu_plugins(base_url):
    findings = []
    resp = get(f"{base_url.rstrip('/')}/wp-content/mu-plugins/")
    if resp and resp.status_code == 200 and ("Index of" in resp.text or "mu-plugins" in resp.text):
        findings.append(finding(
            title="Must-Use Plugins Directory Listing Exposed",
            severity=MEDIUM,
            description="The wp-content/mu-plugins/ directory is publicly listable.",
            impact="Reveals must-use plugins, their names, and versions. May expose custom business logic.",
            remediation="Disable directory listing in web server config (Options -Indexes in Apache or autoindex off in Nginx).",
            evidence=f"Directory listing accessible at /wp-content/mu-plugins/",
        ))
    return findings


def check_wp_json_full_dump(base_url):
    findings = []
    resp = get(f"{base_url.rstrip('/')}/wp-json/")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            name = data.get("name", "")
            description = data.get("description", "")
            url = data.get("url", "")
            if name or description:
                findings.append(finding(
                    title="wp-json Root Endpoint Exposes Site Metadata",
                    severity=INFO,
                    description="The WordPress REST API root endpoint discloses site name, description, and URL structure.",
                    impact="Useful for attacker reconnaissance. Confirms WordPress installation and reveals site configuration.",
                    remediation="Restrict the REST API to authenticated users if it is not needed publicly.",
                    evidence=f"Name: {name} | Description: {description[:80]}",
                ))
        except ValueError:
            pass
    return findings


def run(base_url):
    print(f"{Fore.CYAN}[*] Checking for information disclosure...{Style.RESET_ALL}")
    findings = []

    for fn, args in [
        (check_path_disclosure,        (base_url,)),
        (check_wpjson_private_posts,   (base_url,)),
        (check_comment_email_harvest,  (base_url,)),
        (check_yoast_sitemap_leak,     (base_url,)),
        (check_mu_plugins,             (base_url,)),
        (check_wp_json_full_dump,      (base_url,)),
    ]:
        results = fn(*args)
        for f in results:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No information disclosure issues found{Style.RESET_ALL}")

    return findings
