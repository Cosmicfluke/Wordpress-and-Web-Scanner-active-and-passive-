"""
HTTP security header checks, CORS policy, cookie flags, and server info disclosure.
These are passive — one GET to the homepage, then inspect the response.
"""

from colorama import Fore, Style
from utils.http import get
from utils.severity import finding, badge, CRITICAL, HIGH, MEDIUM, LOW, INFO

SECURITY_HEADERS = [
    {
        "header"     : "Strict-Transport-Security",
        "severity"   : HIGH,
        "title"      : "Missing HTTP Strict Transport Security (HSTS)",
        "description": "The Strict-Transport-Security header is not set. Browsers will not enforce HTTPS connections.",
        "impact"     : "Users may be downgraded to HTTP connections, enabling MitM attacks and cookie theft.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "header"     : "Content-Security-Policy",
        "severity"   : HIGH,
        "title"      : "Missing Content Security Policy (CSP)",
        "description": "No Content-Security-Policy header is present.",
        "impact"     : "XSS attacks have no browser-level mitigation. Inline scripts and external resources load without restriction.",
        "remediation": "Define a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
    },
    {
        "header"     : "X-Content-Type-Options",
        "severity"   : MEDIUM,
        "title"      : "Missing X-Content-Type-Options Header",
        "description": "X-Content-Type-Options: nosniff is not set.",
        "impact"     : "Browsers may MIME-sniff responses, potentially executing scripts served as non-JS content types.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header"     : "X-Frame-Options",
        "severity"   : MEDIUM,
        "title"      : "Missing X-Frame-Options Header",
        "description": "X-Frame-Options is not set and frame-ancestors is absent from CSP.",
        "impact"     : "The site may be embedded in iframes, enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors 'self'",
    },
    {
        "header"     : "Referrer-Policy",
        "severity"   : LOW,
        "title"      : "Missing Referrer-Policy Header",
        "description": "Referrer-Policy is not configured.",
        "impact"     : "Full URLs including query strings may be sent in the Referer header to third-party sites, leaking session tokens or sensitive parameters.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header"     : "Permissions-Policy",
        "severity"   : LOW,
        "title"      : "Missing Permissions-Policy Header",
        "description": "Permissions-Policy (formerly Feature-Policy) is not set.",
        "impact"     : "Browser features like camera, microphone, and geolocation are not restricted for embedded scripts.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
]

SERVER_HEADERS = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]


def check_cors(resp, base_url):
    """Check CORS policy for dangerous misconfigurations."""
    findings = []
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*" and acac == "true":
        findings.append(finding(
            title="CORS: Wildcard Origin with Credentials Allowed",
            severity=CRITICAL,
            description="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
            impact="Any origin can make credentialed cross-origin requests. Full account takeover possible from any domain.",
            remediation="Never combine wildcard ACAO with credentials. Explicitly whitelist trusted origins.",
            evidence=f"ACAO: {acao} | ACAC: {acac}",
        ))
    elif acao == "*":
        findings.append(finding(
            title="CORS: Wildcard Origin Allowed",
            severity=MEDIUM,
            description="Access-Control-Allow-Origin: * permits any origin to read responses.",
            impact="Sensitive API responses may be readable by any website the user visits.",
            remediation="Restrict ACAO to explicitly trusted origins unless the endpoint serves only public data.",
            evidence=f"ACAO: {acao}",
        ))
    return findings


def check_cookies(resp):
    """Inspect Set-Cookie headers for missing security flags."""
    findings = []
    raw_cookies = resp.headers.get("Set-Cookie", "")
    if not raw_cookies:
        return findings

    cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else [raw_cookies]

    for cookie in cookies:
        name = cookie.split("=")[0].strip()
        lower = cookie.lower()

        if "secure" not in lower:
            findings.append(finding(
                title=f"Cookie Missing Secure Flag: {name}",
                severity=MEDIUM,
                description=f"The cookie '{name}' does not have the Secure flag set.",
                impact="Cookie may be transmitted over HTTP, exposing session tokens to interception.",
                remediation="Set the Secure flag on all cookies: Set-Cookie: name=value; Secure",
                evidence=cookie[:120],
            ))

        if "httponly" not in lower:
            findings.append(finding(
                title=f"Cookie Missing HttpOnly Flag: {name}",
                severity=MEDIUM,
                description=f"The cookie '{name}' does not have the HttpOnly flag set.",
                impact="JavaScript can read this cookie, enabling session token theft via XSS.",
                remediation="Set the HttpOnly flag: Set-Cookie: name=value; HttpOnly",
                evidence=cookie[:120],
            ))

        if "samesite" not in lower:
            findings.append(finding(
                title=f"Cookie Missing SameSite Attribute: {name}",
                severity=LOW,
                description=f"The cookie '{name}' has no SameSite attribute.",
                impact="Cookie is sent on all cross-site requests, increasing CSRF risk.",
                remediation="Set SameSite=Lax or SameSite=Strict: Set-Cookie: name=value; SameSite=Lax",
                evidence=cookie[:120],
            ))

    return findings


def check_server_disclosure(resp):
    """Check for server software and version disclosure."""
    findings = []
    for h in SERVER_HEADERS:
        val = resp.headers.get(h)
        if val:
            findings.append(finding(
                title=f"Server Information Disclosure via {h} Header",
                severity=LOW,
                description=f"The response includes the {h} header revealing server software details.",
                impact="Attackers can fingerprint server software and target known vulnerabilities for that version.",
                remediation=f"Remove or genericise the {h} header at the web server configuration level.",
                evidence=f"{h}: {val}",
            ))
    return findings


def run(base_url):
    print(f"{Fore.CYAN}[*] Checking HTTP security headers, CORS, cookies...{Style.RESET_ALL}")
    findings = []

    resp = get(base_url)
    if resp is None:
        print(f"{Fore.RED}[-] Could not fetch target for header checks{Style.RESET_ALL}")
        return findings

    # Security headers
    for check in SECURITY_HEADERS:
        if check["header"] not in resp.headers:
            # Special case: X-Frame-Options can be replaced by CSP frame-ancestors
            if check["header"] == "X-Frame-Options":
                csp = resp.headers.get("Content-Security-Policy", "")
                if "frame-ancestors" in csp:
                    continue
            f = finding(
                title=check["title"],
                severity=check["severity"],
                description=check["description"],
                impact=check["impact"],
                remediation=check["remediation"],
                evidence=f"Header absent from response",
            )
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    # CORS
    cors_findings = check_cors(resp, base_url)
    for f in cors_findings:
        findings.append(f)
        print(f"  {badge(f['severity'])} {f['title']}")

    # Cookies
    cookie_findings = check_cookies(resp)
    for f in cookie_findings:
        findings.append(f)
        print(f"  {badge(f['severity'])} {f['title']}")

    # Server disclosure
    server_findings = check_server_disclosure(resp)
    for f in server_findings:
        findings.append(f)
        print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] All security headers present{Style.RESET_ALL}")

    return findings
