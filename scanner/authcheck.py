"""
Authentication checks: login page exposure, brute-force protection,
default credential testing, CAPTCHA detection, lockout behaviour.
Active checks — only runs with --active flag.
"""

import re
from colorama import Fore, Style
from utils.http import get, post
from utils.severity import finding, badge, CRITICAL, HIGH, MEDIUM, LOW, INFO

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "wordpress"),
    ("administrator", "administrator"),
    ("admin", "letmein"),
]


def check_login_page_exposed(base_url):
    findings = []
    url = f"{base_url.rstrip('/')}/wp-login.php"
    resp = get(url)
    if resp and resp.status_code == 200 and "user_login" in resp.text:
        findings.append(finding(
            title="WordPress Login Page Publicly Accessible",
            severity=LOW,
            description="The wp-login.php page is publicly accessible with no access restriction.",
            impact="Enables targeted brute-force attacks against discovered usernames. Increases attack surface.",
            remediation="Restrict access to wp-login.php by IP via .htaccess or server config. Consider renaming via a plugin like WPS Hide Login.",
            evidence=f"HTTP 200 at {url}",
        ))
    return findings


def check_captcha(base_url):
    url = f"{base_url.rstrip('/')}/wp-login.php"
    resp = get(url)
    if resp is None:
        return None
    captcha_patterns = [
        r"g-recaptcha", r"recaptcha", r"hcaptcha", r"cf-turnstile",
        r"captcha", r"turnstile", r"math.*captcha"
    ]
    for p in captcha_patterns:
        if re.search(p, resp.text, re.I):
            return True
    return False


def check_lockout(base_url):
    """
    Send 5 failed logins and check if the 6th is blocked.
    Returns True if lockout/rate-limiting is detected.
    """
    url = f"{base_url.rstrip('/')}/wp-login.php"
    findings = []
    blocked = False

    for i in range(6):
        resp = post(url, data={
            "log": "lockout_test_user_xzqw",
            "pwd": f"wrong_password_{i}",
            "wp-submit": "Log+In",
            "redirect_to": "/wp-admin/",
            "testcookie": "1",
        })
        if resp is None:
            break
        if resp.status_code in (429, 403, 503):
            blocked = True
            break
        lockout_patterns = [
            r"too many failed login",
            r"locked out",
            r"temporarily blocked",
            r"too many attempts",
            r"slow down",
            r"rate limit",
        ]
        for p in lockout_patterns:
            if re.search(p, resp.text, re.I):
                blocked = True
                break
        if blocked:
            break

    if not blocked:
        findings.append(finding(
            title="No Login Brute-Force Protection Detected",
            severity=HIGH,
            description="After 6 failed login attempts, the WordPress login page did not block or throttle requests.",
            impact="An attacker can brute-force login credentials without being locked out. Combined with a known username, this is a direct path to account takeover.",
            remediation="Install a login protection plugin (Wordfence, Limit Login Attempts Reloaded, or similar). Enable lockout after 5 failed attempts.",
            evidence="6 consecutive failed logins returned no lockout response",
        ))
    else:
        print(f"{Fore.GREEN}[+] Login lockout/rate-limiting is active{Style.RESET_ALL}")

    return findings


def check_default_creds(base_url, discovered_users=None):
    """Test a small set of default/common credentials."""
    findings = []
    url = f"{base_url.rstrip('/')}/wp-login.php"
    creds_to_test = list(DEFAULT_CREDS)

    if discovered_users:
        for u in discovered_users:
            slug = u.get("slug") or u.get("name", "")
            if slug:
                creds_to_test.insert(0, (slug, slug))
                creds_to_test.insert(0, (slug, "password"))
                creds_to_test.insert(0, (slug, "123456"))

    for username, password in creds_to_test:
        resp = post(url, data={
            "log": username,
            "pwd": password,
            "wp-submit": "Log+In",
            "redirect_to": "/wp-admin/",
            "testcookie": "1",
        }, allow_redirects=True)

        if resp is None:
            continue

        if resp.status_code == 200 and "wp-admin" in resp.url:
            findings.append(finding(
                title=f"Default Credentials Valid: {username} / {password}",
                severity=CRITICAL,
                description=f"The credential pair {username}:{password} successfully authenticated to wp-admin.",
                impact="Full administrative access to the WordPress installation. Complete site compromise.",
                remediation="Change the password immediately. Enforce strong password policy. Enable MFA.",
                evidence=f"Successful login: {username}:{password} -> {resp.url}",
            ))
            print(f"{Fore.RED}[!!!] VALID CREDENTIALS: {username} / {password}{Style.RESET_ALL}")
            break

        if "incorrect" in resp.text.lower() or "invalid" in resp.text.lower():
            continue

    return findings


def _build_multicall_payload(attempt_count):
    """Build a system.multicall request wrapping N distinct fake login attempts."""
    calls = ""
    for i in range(attempt_count):
        calls += f"""
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>lotr_probe_user</string></value>
        <value><string>lotr_probe_pw_{i}</string></value>
      </data></array></value></member>
    </struct></value>"""

    return f"""<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>{calls}
  </data></array></value></param></params>
</methodCall>"""


def check_xmlrpc_bruteforce(base_url):
    """
    Test whether system.multicall genuinely batches multiple auth attempts
    into a single request — the actual amplification vector, independent
    of whether any individual credential pair is valid.

    We send 3 distinct fake login attempts in one multicall and count how
    many individual results come back. If multicall is disabled or blocked,
    WordPress returns a single top-level fault (method not found) instead
    of processing each item. If all 3 come back as separate results, the
    server processed all 3 attempts in one HTTP request — that's the
    amplification vulnerability, regardless of the fault content of each.
    """
    findings     = []
    url          = f"{base_url.rstrip('/')}/xmlrpc.php"
    attempt_count = 3

    payload = _build_multicall_payload(attempt_count)
    resp    = post(url, data=payload, headers={"Content-Type": "text/xml"})

    if resp is None or resp.status_code != 200 or "<methodResponse>" not in resp.text:
        return findings

    # A single top-level fault means multicall itself was rejected —
    # e.g. "server error, requested method does not exist" (-32601).
    # This is the expected secure response when multicall is disabled.
    top_level_fault = resp.text.count("<fault>") == 1 and resp.text.count("<struct>") <= 2

    if top_level_fault:
        return findings  # multicall blocked — not vulnerable

    # Count how many individual result structs came back inside the
    # outer <array><data> block. Each processed attempt produces its
    # own <value> entry, whether it succeeded or failed individually.
    result_count = resp.text.count("<member><name>faultCode</name>") \
                 + resp.text.count("<member><name>faultString</name>") \
                 + resp.text.count("isAdmin")  # present in successful wp.getUsersBlogs results

    # Rough proxy: did the server produce roughly as many result entries
    # as attempts we sent? If so, it processed each one individually.
    individual_results = resp.text.count("<value><struct>") + resp.text.count("<value><array>")

    if individual_results >= attempt_count or result_count >= attempt_count:
        findings.append(finding(
            title       = "xmlrpc.php system.multicall Batches Multiple Auth Attempts",
            severity    = MEDIUM,
            description = (
                f"Sending {attempt_count} distinct login attempts wrapped in a single "
                f"system.multicall request returned {attempt_count} individually "
                f"processed results, confirming the server processes each attempt "
                f"separately within one HTTP request."
            ),
            impact = (
                "An attacker can test hundreds of password guesses in a single HTTP "
                "request via multicall, bypassing IP-based or per-request rate limiting "
                "that only counts requests, not attempts within a request."
            ),
            remediation = (
                "Disable xmlrpc.php entirely if not needed. If required, restrict access "
                "to trusted IPs and disable system.multicall specifically via a plugin "
                "such as Disable XML-RPC."
            ),
            evidence = f"{attempt_count} attempts sent, {individual_results} individual results returned",
        ))
        print(f"{Fore.YELLOW}[!] xmlrpc multicall batches multiple auth attempts{Style.RESET_ALL}")

    return findings


def run(base_url, discovered_users=None):
    print(f"{Fore.CYAN}[*] Running authentication checks (active)...{Style.RESET_ALL}")
    findings = []

    for fn, args in [
        (check_login_page_exposed, (base_url,)),
        (check_xmlrpc_bruteforce,  (base_url,)),
        (check_lockout,            (base_url,)),
        (check_default_creds,      (base_url, discovered_users)),
    ]:
        results = fn(*args)
        for f in results:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    captcha = check_captcha(base_url)
    if captcha is False:
        findings.append(finding(
            title="No CAPTCHA on Login Page",
            severity=LOW,
            description="No CAPTCHA or bot-detection challenge was found on the WordPress login page.",
            impact="Automated login attempts are not challenged, making brute-force attacks easier.",
            remediation="Add CAPTCHA to the login page using a plugin such as Google reCAPTCHA or hCaptcha.",
            evidence="No CAPTCHA pattern detected in wp-login.php HTML",
        ))
        print(f"  {badge('Low')} No CAPTCHA on login page")
    elif captcha:
        print(f"{Fore.GREEN}[+] CAPTCHA detected on login page{Style.RESET_ALL}")

    return findings
