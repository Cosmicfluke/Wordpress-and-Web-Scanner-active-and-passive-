# File upload vulnerability module.
#
# Phase 1 — Discovery: find upload endpoints via HTML crawl and path probing.
# Phase 2 — Bypass: attempt real bypass techniques against discovered endpoints.
#
# We flag findings only on strong positive evidence. Auth redirects and login
# pages are explicitly rejected to prevent false positives.

import re
import requests

from colorama import Fore, Style

from utils.http import get, VERIFY_SSL
from utils.severity import finding, badge, CRITICAL, HIGH, MEDIUM, LOW


UPLOAD_ENDPOINTS = [
    "/upload",
    "/uploads",
    "/file/upload",
    "/files/upload",
    "/api/upload",
    "/api/v1/upload",
    "/api/v2/upload",
    "/media/upload",
    "/image/upload",
    "/images/upload",
    "/attachment/upload",
    "/attachments",
    "/document/upload",
    "/documents/upload",
    "/import",
    "/admin/upload",
    "/admin/media",
    "/wp-admin/async-upload.php",
    "/wp-json/wp/v2/media",
    "/filemanager/upload",
    "/assets/upload",
    "/storage/upload",
    "/user/avatar",
    "/profile/avatar",
    "/profile/photo",
    "/account/avatar",
]

UPLOAD_FORM_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']file["\']', re.I),
    re.compile(r'enctype=["\']multipart/form-data["\']', re.I),
    re.compile(r'<form[^>]+upload', re.I),
]

# Stub content — not functional code, just enough to test if the server
# stores the file by extension rather than validating the content.
PHP_STUB   = b"<?php /* LOTR-SCANNER-PROBE */ echo 'LOTR'; ?>"
JPEG_MAGIC = b"\xff\xd8\xff\xe0"

# Shared MIME type used across every bypass attempt below — kept as a
# single constant rather than repeated per call.
MIME_JPEG = "image/jpeg"

# Marker embedded in every probe filename so we can find it again in a
# response without a backtracking-prone regex (see _find_probe_reference).
PROBE_MARKER = "lotr_probe"


def _discover_via_crawl(base_url, html):
    for pattern in UPLOAD_FORM_PATTERNS:
        if pattern.search(html):
            return [base_url]
    return []


def _discover_via_probe(base_url):
    """
    Probe known upload paths. Only treat 200, 401, and 405 as hits.
    403 means the endpoint exists but is blocked — no point attempting bypass.
    """
    found = []
    for path in UPLOAD_ENDPOINTS:
        url  = base_url.rstrip("/") + path
        resp = get(url)
        if not resp:
            continue
        if resp.status_code in (200, 401, 405):
            found.append(url)
            print(f"{Fore.YELLOW}    [i] Upload endpoint found: {url} (HTTP {resp.status_code}){Style.RESET_ALL}")
    return found


def _post_file(endpoint, filename, content, mime_type, cookie=None):
    """Send a multipart file upload request."""
    headers = {"Cookie": cookie} if cookie else {}
    files   = {"file": (filename, content, mime_type)}
    try:
        return requests.post(
            endpoint,
            files   = files,
            headers = headers,
            timeout = 10,
            verify  = VERIFY_SSL,
        )
    except Exception:
        return None


def _attempt_mime_bypass(endpoint, cookie=None):
    # Send a PHP file disguised as an image — the most common bypass.
    return _post_file(endpoint, f"{PROBE_MARKER}.php", PHP_STUB, MIME_JPEG, cookie)


def _attempt_double_extension(endpoint, cookie=None):
    # Servers that strip only the last extension may store this as .php.
    return _post_file(endpoint, f"{PROBE_MARKER}.php.jpg", PHP_STUB, MIME_JPEG, cookie)


def _attempt_null_byte(endpoint, cookie=None):
    # Null byte truncates the filename on older PHP/server combinations.
    return _post_file(endpoint, f"{PROBE_MARKER}.php\x00.jpg", PHP_STUB, MIME_JPEG, cookie)


def _attempt_polyglot(endpoint, cookie=None):
    # Valid JPEG header prepended to PHP — passes image validation, executes as PHP.
    polyglot = JPEG_MAGIC + b"\n" + PHP_STUB
    return _post_file(endpoint, f"{PROBE_MARKER}.jpg", polyglot, MIME_JPEG, cookie)


def _find_probe_reference(text):
    """
    Look for our probe marker reflected back in the response body,
    e.g. inside a src="..." attribute pointing at the stored file.

    Written as a bounded single-quantifier match rather than two adjacent
    unbounded character classes either side of the marker, which avoids
    the super-linear backtracking risk that pattern would otherwise carry.
    """
    match = re.search(rf'{PROBE_MARKER}[\w.\-]*', text)
    return match.group(0) if match else None


def _server_accepted_upload(resp):
    """
    Determine whether the server genuinely stored an uploaded file.

    We require strong positive evidence — a file URL or path in the JSON
    response. We explicitly reject auth redirects and login pages, which
    caused false positives when wp-admin redirected unauthenticated requests
    to wp-login.php and earlier logic saw a 200 with no error keywords.
    """
    if resp is None:
        return False, None

    # Reject auth redirects — check final URL after any redirects.
    final_url = getattr(resp, "url", "")
    if any(s in final_url for s in ["wp-login", "login", "signin", "auth"]):
        return False, None

    if resp.status_code not in (200, 201):
        return False, None

    body_lower = resp.text.lower()

    # Reject responses that look like login or auth pages.
    auth_signals = [
        "user_login", "user_pass", "wp-login", "login_form",
        "log in", "sign in", "lost your password", "enter your",
        "please log in", "you are not allowed",
    ]
    if any(signal in body_lower for signal in auth_signals):
        return False, None

    # Strong positive signals — server returned file metadata in the body.
    field_patterns = [
        re.compile(r'"url"\s*:\s*"([^"]+)"'),
        re.compile(r'"path"\s*:\s*"([^"]+)"'),
        re.compile(r'"filename"\s*:\s*"([^"]+)"'),
        re.compile(r'"file"\s*:\s*"([^"]+)"'),
        re.compile(r'"location"\s*:\s*"([^"]+)"'),
    ]

    for pattern in field_patterns:
        match = pattern.search(resp.text)
        if match:
            return True, match.group(1)

    probe_ref = _find_probe_reference(resp.text)
    if probe_ref:
        return True, probe_ref

    # No strong evidence — don't flag it.
    return False, None


def run(base_url, html="", cookie=None, active=False):
    print(f"{Fore.CYAN}[*] Checking for file upload vulnerabilities...{Style.RESET_ALL}")
    findings = []

    endpoints = list(set(
        (_discover_via_crawl(base_url, html) if html else []) +
        _discover_via_probe(base_url)
    ))

    if not endpoints:
        print(f"{Fore.GREEN}[+] No upload endpoints found{Style.RESET_ALL}")
        return findings

    findings.append(finding(
        title       = "File Upload Endpoint(s) Discovered",
        severity    = LOW,
        description = f"Found {len(endpoints)} upload endpoint(s): {', '.join(endpoints[:5])}",
        impact      = "Upload endpoints are high-risk surfaces and should be reviewed for bypass techniques.",
        remediation = "Validate file types by magic bytes, not extension or MIME header. Store uploads outside the web root.",
        evidence    = "\n".join(endpoints[:10]),
    ))

    if not active:
        print(f"{Fore.YELLOW}    [i] Run with --active to attempt bypass techniques{Style.RESET_ALL}")
        return findings

    print(f"{Fore.CYAN}[*] Attempting upload bypass techniques...{Style.RESET_ALL}")

    bypass_techniques = [
        ("MIME type spoofing",  _attempt_mime_bypass),
        ("Double extension",    _attempt_double_extension),
        ("Null byte injection", _attempt_null_byte),
        ("Polyglot JPEG+PHP",   _attempt_polyglot),
    ]

    for endpoint in endpoints:
        for name, fn in bypass_techniques:
            resp           = fn(endpoint, cookie=cookie)
            accepted, path = _server_accepted_upload(resp)

            if accepted:
                evidence = f"Endpoint: {endpoint} | Technique: {name}"
                if path:
                    evidence += f" | File stored at: {path}"

                findings.append(finding(
                    title       = f"File Upload Bypass Succeeded: {name}",
                    severity    = CRITICAL,
                    description = (
                        f"The upload endpoint at {endpoint} accepted a PHP stub "
                        f"using '{name}'. The server returned file metadata confirming "
                        f"storage. No code was executed — this confirms the bypass only."
                    ),
                    impact      = (
                        "An attacker can upload a PHP webshell and achieve RCE if the "
                        "file is served by PHP. This is a Critical severity finding."
                    ),
                    remediation = (
                        "Validate uploads by magic bytes, not Content-Type or extension. "
                        "Use an allowlist of safe file types. Store uploads outside the "
                        "web root or in a directory with PHP execution disabled."
                    ),
                    evidence    = evidence,
                ))

                print(f"  {badge('Critical')} Upload bypass confirmed: {name} on {endpoint}")
                break  # One confirmed bypass per endpoint is enough.

    if len(findings) == 1:
        print(f"{Fore.GREEN}[+] Upload endpoints found but no bypasses succeeded{Style.RESET_ALL}")

    return findings
