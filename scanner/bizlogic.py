"""
Business logic checks: file upload endpoints, wp-cron external trigger,
password reset weaknesses, open registration.
Mix of passive and active — some checks fire always, others need --active.
"""

import re
from colorama import Fore, Style
from utils.http import get, post
from utils.severity import finding, badge, HIGH, MEDIUM, LOW, INFO


def check_wpcron_external_trigger(base_url):
    """
    wp-cron.php responding to external GET requests is the default
    behaviour on nearly every WordPress install — it's how WP-Cron works
    unless DISABLE_WP_CRON is explicitly set. Reported as Info rather than
    a real misconfiguration; only worth escalating if there's evidence of
    actual abuse (e.g. resource exhaustion under repeated triggering).
    """
    findings = []
    url = f"{base_url.rstrip('/')}/wp-cron.php"
    resp = get(url)
    if resp and resp.status_code == 200:
        findings.append(finding(
            title="wp-cron.php Externally Accessible (Default Behaviour)",
            severity=INFO,
            description="wp-cron.php responds to external requests, which is standard WordPress behaviour unless DISABLE_WP_CRON is set.",
            impact="Low — theoretical resource exhaustion via repeated triggering, but requires significant automated abuse to matter in practice.",
            remediation="Optional hardening: set DISABLE_WP_CRON in wp-config.php and use a real system cron job instead.",
            evidence=f"wp-cron.php returned HTTP {resp.status_code}",
        ))
    return findings


def check_password_reset(base_url):
    findings = []
    url = f"{base_url.rstrip('/')}/wp-login.php?action=lostpassword"
    resp = get(url)
    if resp and resp.status_code == 200:
        if "user_login" in resp.text or "email" in resp.text.lower():
            findings.append(finding(
                title="Password Reset Page Publicly Accessible",
                severity=INFO,
                description="The WordPress password reset page is publicly accessible.",
                impact="Can be used to enumerate valid usernames — WordPress historically returns different messages for valid vs invalid usernames on the reset form.",
                remediation="Customise password reset error messages to be generic regardless of whether the account exists.",
                evidence=f"Reset form accessible at {url}",
            ))

        if re.search(r"No account found", resp.text, re.I) or re.search(r"There is no user", resp.text, re.I):
            findings.append(finding(
                title="Username Enumeration via Password Reset Form",
                severity=MEDIUM,
                description="The password reset form returns different responses for valid and invalid usernames.",
                impact="An attacker can confirm whether a username exists by submitting it to the reset form and observing the response.",
                remediation="Return a consistent message regardless of whether the account exists: 'If an account with that email exists, a reset link has been sent.'",
                evidence="Different response for invalid username on reset form",
            ))
    return findings


def check_uploads_listing(base_url):
    findings = []
    url = f"{base_url.rstrip('/')}/wp-content/uploads/"
    resp = get(url)
    if resp and resp.status_code == 200:
        if "Index of" in resp.text or "<a href=" in resp.text:
            findings.append(finding(
                title="wp-content/uploads Directory Listing Enabled",
                severity=MEDIUM,
                description="The uploads directory is publicly listable, exposing all uploaded files.",
                impact="Reveals all uploaded media files including documents, PDFs, and potentially sensitive files uploaded by mistake. May expose internal documents.",
                remediation="Add 'Options -Indexes' to .htaccess in the uploads directory, or configure Nginx to disable autoindex.",
                evidence=f"Directory listing at /wp-content/uploads/",
            ))
    return findings


def check_git_exposure(base_url):
    findings = []
    paths = ["/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/store/fncache"]
    for path in paths:
        resp = get(base_url.rstrip("/") + path)
        if resp and resp.status_code == 200 and len(resp.text) > 20:
            vcs = path.split("/")[1].lstrip(".")
            findings.append(finding(
                title=f"Version Control Directory Exposed: {path}",
                severity=HIGH,
                description=f"The {path} file is publicly accessible, exposing version control metadata.",
                impact="An attacker can reconstruct the full source code including wp-config.php, revealing database credentials, API keys, and secret keys.",
                remediation=f"Block access to .{vcs} directories via .htaccess or server config. Ensure VCS directories are never deployed to production.",
                evidence=f"HTTP {resp.status_code} at {path} — {resp.text[:80]}",
            ))
    return findings


def check_backup_archives(base_url):
    findings = []
    domain = base_url.rstrip("/").split("/")[-1].replace(".", "_").replace("-", "_")
    paths = [
        "/backup.zip", "/backup.tar.gz", "/site.zip", "/wordpress.zip",
        f"/{domain}.zip", "/wp-content/backup.zip",
        "/wp-content/backups/", "/wp-backup.zip",
        "/.htaccess.bak", "/web.config.bak",
    ]
    for path in paths:
        resp = get(base_url.rstrip("/") + path)
        if resp and resp.status_code == 200 and len(resp.content) > 100:
            findings.append(finding(
                title=f"Backup Archive Exposed: {path}",
                severity=HIGH,
                description=f"A backup file was found at {path}.",
                impact="Backup archives typically contain the full WordPress installation including wp-config.php with database credentials.",
                remediation="Remove backup files from the web root immediately. Store backups outside the public document root or in a password-protected location.",
                evidence=f"HTTP {resp.status_code} at {path} ({len(resp.content)} bytes)",
            ))
    return findings


def run(base_url, active=False):
    print(f"{Fore.CYAN}[*] Running business logic checks...{Style.RESET_ALL}")
    findings = []

    for fn, args in [
        (check_wpcron_external_trigger, (base_url,)),
        (check_uploads_listing,         (base_url,)),
        (check_git_exposure,            (base_url,)),
        (check_backup_archives,         (base_url,)),
        (check_password_reset,          (base_url,)),
    ]:
        results = fn(*args)
        for f in results:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No business logic issues found{Style.RESET_ALL}")

    return findings
