# IDOR detection module.
#
# Tests for Insecure Direct Object Reference vulnerabilities by manipulating
# ID parameters in URLs and looking for responses that indicate unauthorised
# access to other objects.
#
# We cover three ID types:
#   - Numeric: id=1 -> id=2, id=100 -> id=99, id=101
#   - UUID: substitute a known UUID pattern with a crafted one
#   - Common param names: user_id, account_id, order_id, etc.
#
# This module works best when you provide a session cookie via --cookie,
# because IDOR is about cross-account access. Without auth, we can still
# detect unauthenticated access to objects that should be protected.

import re
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from colorama import Fore, Style

from utils.http import get
from utils.severity import finding, badge, HIGH, MEDIUM, LOW


# Parameters that almost certainly reference objects by ID.
ID_PARAM_NAMES = [
    "id", "user_id", "account_id", "order_id", "invoice_id", "doc_id",
    "document_id", "file_id", "post_id", "comment_id", "message_id",
    "ticket_id", "customer_id", "product_id", "report_id", "record_id",
    "uid", "pid", "oid", "aid", "cid", "tid", "rid",
]

UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.I,
)


def _extract_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params


def _rebuild_url(parsed, params, name, value):
    fuzzed          = dict(params)
    fuzzed[name]    = [str(value)]
    return urlunparse(parsed._replace(query=urlencode(fuzzed, doseq=True)))


def _looks_like_different_object(original_resp, fuzzed_resp):
    """
    Heuristic: did we get a substantively different response?

    If both responses are 200 and the content differs meaningfully, that
    suggests we accessed a different object — potential IDOR.
    If the fuzzed response is 403 or 401, the access control is working.
    If the fuzzed response is 404 or identical to the original, not an IDOR.
    """
    if fuzzed_resp.status_code in (401, 403):
        return False  # Access control is doing its job

    if fuzzed_resp.status_code == 404:
        return False  # Object doesn't exist

    if original_resp.status_code != 200 or fuzzed_resp.status_code != 200:
        return False

    # Significant content change suggests different object was returned
    orig_len  = len(original_resp.text)
    fuzz_len  = len(fuzzed_resp.text)
    diff_ratio = abs(orig_len - fuzz_len) / max(orig_len, 1)

    # If content is meaningfully different (>5% size change) and non-trivial
    if diff_ratio > 0.05 and fuzz_len > 100:
        return True

    return False


def _test_numeric_id(target_url, param_name, original_value, cookie=None):
    """
    Increment and decrement a numeric ID to probe for IDOR.

    We try +1, -1, and a few common low IDs (1, 2, 3) which often belong
    to admin or seed accounts created during setup.
    """
    findings     = []
    parsed, params = _extract_params(target_url)

    try:
        num = int(original_value)
    except ValueError:
        return findings

    candidates = set()
    candidates.add(num + 1)
    candidates.add(num - 1) if num > 1 else None
    candidates.update([1, 2, 3])
    candidates.discard(num)  # Don't test the original value

    original_resp = get(target_url, cookie=cookie)
    if original_resp is None:
        return findings

    for candidate_id in sorted(candidates):
        if candidate_id < 1:
            continue

        fuzzed_url  = _rebuild_url(parsed, params, param_name, candidate_id)
        fuzzed_resp = get(fuzzed_url, cookie=cookie)

        if fuzzed_resp and _looks_like_different_object(original_resp, fuzzed_resp):
            findings.append(finding(
                title       = f"Potential IDOR via Numeric '{param_name}' Parameter",
                severity    = HIGH,
                description = (
                    f"Changing {param_name}={original_value} to {param_name}={candidate_id} "
                    f"returned a different 200 response with substantively different content."
                ),
                impact      = (
                    "An attacker may be able to access, modify, or delete another user's "
                    "data by manipulating the ID parameter. This is one of the most common "
                    "high-severity findings in web applications."
                ),
                remediation = (
                    "Enforce object-level authorisation on every request. Verify that the "
                    "authenticated user owns or has permission to access the requested object "
                    "before returning or modifying it. Never rely on IDs being hard to guess."
                ),
                evidence    = (
                    f"Original: {param_name}={original_value} ({len(original_resp.text)} bytes) | "
                    f"Fuzzed: {param_name}={candidate_id} ({len(fuzzed_resp.text)} bytes)"
                ),
            ))
            break  # One confirmed hit per parameter is sufficient

    return findings


def _test_uuid_param(target_url, param_name, original_value, cookie=None):
    """
    Substitute a UUID parameter with a crafted UUID.

    We use a well-known nil UUID and a random UUID. If either returns a
    200 with different content, access control on UUID-keyed objects may
    be missing.
    """
    findings      = []
    parsed, params = _extract_params(target_url)

    original_resp = get(target_url, cookie=cookie)
    if original_resp is None:
        return findings

    test_uuids = [
        "00000000-0000-0000-0000-000000000001",  # common seed account ID
        str(uuid.uuid4()),                        # random UUID
    ]

    for test_uuid in test_uuids:
        fuzzed_url  = _rebuild_url(parsed, params, param_name, test_uuid)
        fuzzed_resp = get(fuzzed_url, cookie=cookie)

        if fuzzed_resp and _looks_like_different_object(original_resp, fuzzed_resp):
            findings.append(finding(
                title       = f"Potential IDOR via UUID '{param_name}' Parameter",
                severity    = HIGH,
                description = (
                    f"Substituting the UUID in '{param_name}' returned a different "
                    f"200 response, suggesting the server returned a different object "
                    f"without verifying ownership."
                ),
                impact      = "Access to another user's data or resources without authorisation.",
                remediation = (
                    "Validate that the authenticated user owns the object identified by "
                    "the UUID on every request. UUID unpredictability is not a security control."
                ),
                evidence    = (
                    f"Original UUID: {original_value} | "
                    f"Test UUID: {test_uuid} | "
                    f"Response size changed: {len(original_resp.text)} -> {len(fuzzed_resp.text)} bytes"
                ),
            ))
            break

    return findings


def _looks_like_real_email(value):
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", value.strip(), re.I))


def _looks_like_real_token(value):
    # Real secrets are long and high-entropy. Short or low-variety
    # strings (like UI labels) don't qualify.
    value = value.strip()
    if len(value) < 20:
        return False
    unique_chars = len(set(value))
    return unique_chars >= 10


def _check_unauthenticated_access(target_url):
    """
    Check whether JSON API endpoints leak sensitive data without auth.

    Restricted to responses that are actually JSON — running this against
    arbitrary HTML pages caused false positives on UI labels like
    '"email":{"title":"Email"}' (a social share button) and unrelated
    analytics tokens embedded in page scripts.
    """
    findings = []

    resp = get(target_url, cookie=None)
    if resp is None or resp.status_code != 200 or len(resp.text) <= 200:
        return findings

    content_type = resp.headers.get("Content-Type", "")
    if "json" not in content_type.lower():
        return findings  # Only evaluate genuine API/JSON responses

    try:
        import json as json_module
        data = json_module.loads(resp.text)
    except ValueError:
        return findings  # Not valid JSON despite the header — skip

    # Walk the parsed JSON looking for keys with values that actually
    # look like sensitive data, not just a matching key name.
    sensitive_keys = {"email", "username", "user_id", "account", "password", "token", "api_key"}

    def _scan(node):
        hits = []
        if isinstance(node, dict):
            for key, value in node.items():
                key_lower = key.lower()
                if key_lower in sensitive_keys and isinstance(value, str):
                    if key_lower == "email" and _looks_like_real_email(value):
                        hits.append((key, value))
                    elif key_lower in ("token", "api_key", "password") and _looks_like_real_token(value):
                        hits.append((key, value))
                    elif key_lower in ("username", "user_id", "account") and value.strip():
                        hits.append((key, value))
                hits.extend(_scan(value))
        elif isinstance(node, list):
            for item in node:
                hits.extend(_scan(item))
        return hits

    matches = _scan(data)

    if matches:
        sample = ", ".join(f"{k}={v[:30]}" for k, v in matches[:3])
        findings.append(finding(
            title       = "Sensitive Data Accessible Without Authentication",
            severity    = HIGH,
            description = (
                "A JSON API endpoint returned fields containing what appears to be "
                "real user data without requiring authentication."
            ),
            impact      = (
                "Any unauthenticated user can access potentially sensitive data. "
                "This may constitute a data breach depending on the content exposed."
            ),
            remediation = (
                        "Require authentication on all endpoints that return user data. "
                        "Return 401 for unauthenticated requests and 403 for unauthorised ones."
                    ),
                    evidence    = f"Fields found: {sample}",
                ))

    return findings

    return findings


def run(target_url, cookie=None):
    print(f"{Fore.CYAN}[*] Testing for IDOR vulnerabilities...{Style.RESET_ALL}")

    if not cookie:
        print(f"{Fore.YELLOW}    [i] No --cookie provided. Auth-dependent IDOR checks limited.{Style.RESET_ALL}")

    findings        = []
    parsed, params  = _extract_params(target_url)

    if not params:
        print(f"{Fore.YELLOW}    [i] No query parameters found in URL to fuzz{Style.RESET_ALL}")
        unauth = _check_unauthenticated_access(target_url)
        for f in unauth:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")
        return findings

    for param_name, values in params.items():
        original_value = values[0] if values else ""

        # Numeric ID
        if re.match(r"^\d+$", original_value):
            hits = _test_numeric_id(target_url, param_name, original_value, cookie)
            findings.extend(hits)

        # UUID
        elif UUID_PATTERN.match(original_value):
            hits = _test_uuid_param(target_url, param_name, original_value, cookie)
            findings.extend(hits)

        # Known ID param name with an unrecognised value format
        elif param_name.lower() in ID_PARAM_NAMES:
            # Try numeric substitution anyway with small integers
            hits = _test_numeric_id(target_url, param_name, "1", cookie)
            findings.extend(hits)

    # Also check for unauth access regardless of params
    unauth = _check_unauthenticated_access(target_url)
    findings.extend(unauth)

    for f in findings:
        print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No IDOR issues detected{Style.RESET_ALL}")

    return findings
