"""
Injection and active vulnerability checks.
All checks in this module are active — only runs with --active flag.
"""

import re
from colorama import Fore, Style
from utils.http import get, post
from utils.severity import finding, badge, CRITICAL, HIGH, MEDIUM, LOW


XSS_PAYLOADS = [
    "<script>alert('LOTR-XSS')</script>",
    '"><img src=x onerror=alert(1)>',
    "';alert('LOTR')//",
]

XSS_PARAMS = ["s", "q", "search", "p", "name", "comment", "message"]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1 AND 1=1--",
    "1' ORDER BY 1--",
]

SQLI_ERROR_PATTERNS = [
    r"You have an error in your SQL syntax",
    r"Warning.*mysql_",
    r"ORA-[0-9]{4}",
    r"Microsoft OLE DB Provider",
    r"ODBC SQL Server Driver",
    r"PostgreSQL.*ERROR",
    r"SQLite.*exception",
    r"Division by zero",
    r"supplied argument is not a valid MySQL",
]


def check_reflected_xss(base_url):
    findings = []
    for payload in XSS_PAYLOADS:
        for param in XSS_PARAMS:
            url = f"{base_url.rstrip('/')}/?{param}={payload}"
            resp = get(url)
            if resp and payload in resp.text:
                findings.append(finding(
                    title=f"Reflected XSS via {param} Parameter",
                    severity=HIGH,
                    description=f"The parameter '{param}' reflects unsanitised input in the response.",
                    impact="An attacker can craft a malicious URL that executes JavaScript in the victim's browser, enabling session hijacking, credential theft, or malware delivery.",
                    remediation="Sanitise and encode all user-supplied input before reflecting it in HTML output. Use wp_kses() or esc_html() in WordPress templates.",
                    evidence=f"Payload reflected: {payload[:80]} via ?{param}=",
                ))
                return findings
    return findings


def check_sqli(base_url):
    findings = []
    for payload in SQLI_PAYLOADS:
        url = f"{base_url.rstrip('/')}/?s={payload}"
        resp = get(url)
        if resp:
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, resp.text, re.I):
                    findings.append(finding(
                        title="SQL Injection Error Triggered via Search Parameter",
                        severity=CRITICAL,
                        description=f"A SQL error was returned when the search parameter received a SQL injection payload.",
                        impact="Database content may be readable or modifiable. Depending on DB permissions, could lead to full server compromise.",
                        remediation="Use prepared statements and parameterised queries. Ensure WP_DEBUG is off in production to suppress error output.",
                        evidence=f"SQL error triggered by payload: {payload}",
                    ))
                    return findings
    return findings


def check_ssrf_xmlrpc(base_url):
    """
    Test SSRF via xmlrpc.php pingback.pingback to internal addresses.
    We test with an obviously non-routable address to avoid real SSRF.
    """
    findings = []
    url = f"{base_url.rstrip('/')}/xmlrpc.php"
    payload = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.pingback</methodName>
  <params>
    <param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param>
    <param><value><string>{base_url}/</string></value></param>
  </params>
</methodCall>"""

    resp = post(url, data=payload, headers={"Content-Type": "text/xml"})
    if resp and resp.status_code == 200:
        if "faultCode" not in resp.text:
            findings.append(finding(
                title="SSRF via xmlrpc.php Pingback",
                severity=HIGH,
                description="The xmlrpc.php pingback.pingback method accepted a request to an internal address (169.254.169.254).",
                impact="An attacker can use the WordPress server as a proxy to reach internal services, cloud metadata APIs, or internal network hosts.",
                remediation="Disable xmlrpc.php if not required. If needed, disable pingback support specifically via a filter hook.",
                evidence="Pingback to 169.254.169.254 did not return a fault response",
            ))
    return findings


def check_open_redirect(base_url):
    findings = []
    payloads = [
        f"{base_url.rstrip('/')}/wp-login.php?redirect_to=https://evil.example.com",
        f"{base_url.rstrip('/')}/?redirect_to=https://evil.example.com",
        f"{base_url.rstrip('/')}/wp-login.php?redirect_to=//evil.example.com",
    ]
    for url in payloads:
        resp = get(url, allow_redirects=False)
        if resp and resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if "evil.example.com" in location:
                findings.append(finding(
                    title="Open Redirect via redirect_to Parameter",
                    severity=MEDIUM,
                    description="The redirect_to parameter accepts arbitrary external URLs without validation.",
                    impact="Phishing attacks using legitimate-looking WordPress URLs that redirect to attacker-controlled sites.",
                    remediation="Validate redirect_to against a whitelist of allowed internal paths. Reject any value containing an external domain.",
                    evidence=f"Redirect to: {location}",
                ))
                break
    return findings


def run(base_url):
    print(f"{Fore.CYAN}[*] Running injection checks (active)...{Style.RESET_ALL}")
    findings = []

    for fn, args in [
        (check_reflected_xss,   (base_url,)),
        (check_sqli,            (base_url,)),
        (check_ssrf_xmlrpc,     (base_url,)),
        (check_open_redirect,   (base_url,)),
    ]:
        results = fn(*args)
        for f in results:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No injection issues found{Style.RESET_ALL}")

    return findings
