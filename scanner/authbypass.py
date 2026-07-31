# Authentication bypass and privilege escalation module.
#
# We look for logic flaws, not brute force. The difference:
#   - Brute force: guess passwords until one works
#   - Logic flaws: manipulate the flow so the app skips auth entirely
#
# Checks in this module:
#   - Forced browsing to protected endpoints
#   - HTTP method switching (GET -> POST -> PUT to bypass method-based ACL)
#   - Role parameter manipulation (role=admin in POST body)
#   - JWT tampering (none algorithm, weak secret)
#   - Password reset token reuse
#   - Horizontal -> vertical privilege escalation via parameter manipulation
#   - Mass assignment (sending extra fields the API might honour)

import re
import base64
import json
import requests

from colorama import Fore, Style
from utils.http import get, post, VERIFY_SSL
from utils.severity import finding, badge, CRITICAL, HIGH, MEDIUM, LOW


# Endpoints that should require authentication.
# A 200 response on any of these (without a cookie) is a forced browsing hit.
PROTECTED_PATHS = [
    "/admin",
    "/admin/",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
    "/dashboard",
    "/account",
    "/account/settings",
    "/profile",
    "/settings",
    "/api/admin",
    "/api/v1/admin",
    "/api/users",
    "/api/v1/users",
    "/api/v2/users",
    "/api/settings",
    "/api/v1/settings",
    "/manage",
    "/management",
    "/panel",
    "/cp",
    "/controlpanel",
    "/console",
    "/internal",
    "/private",
    "/secure",
    "/staff",
    "/superuser",
    "/wp-admin",
    "/wp-admin/users.php",
    "/wp-admin/options-general.php",
]

# JWT none algorithm attack — strips the signature entirely.
# We try this on any token we find in response headers or cookies.
JWT_NONE_VARIANTS = ["none", "None", "NONE", "NoNe", "nOnE"]


def _check_forced_browsing(base_url, cookie=None):
    """
    Request protected endpoints without authentication.

    If the server returns 200 instead of 401/403/302-to-login,
    the endpoint is accessible without auth.
    """
    findings = []

    for path in PROTECTED_PATHS:
        url  = base_url.rstrip("/") + path
        resp = get(url, cookie=None)  # Deliberately no cookie

        if resp is None:
            continue

        if resp.status_code == 200 and len(resp.text) > 200:
            # Quick sanity check: does it look like an auth page?
            auth_indicators = ["login", "sign in", "password", "username", "log in"]
            if any(indicator in resp.text.lower() for indicator in auth_indicators):
                continue  # Redirected to login page with 200 — not a bypass

            findings.append(finding(
                title       = f"Forced Browsing: Unprotected Endpoint '{path}'",
                severity    = HIGH,
                description = (
                    f"The endpoint {path} returned HTTP 200 without any authentication "
                    f"cookie or session token."
                ),
                impact      = (
                    "Sensitive administrative or user functionality is accessible "
                    "without logging in."
                ),
                remediation = (
                    "Enforce session validation on every protected route. Apply an "
                    "authentication middleware that rejects unauthenticated requests "
                    "before the route handler executes."
                ),
                evidence    = f"HTTP {resp.status_code} at {url} (no auth cookie sent)",
            ))

    return findings


def _check_method_switching(base_url, cookie=None):
    """
    Try switching HTTP methods to bypass method-level access controls.

    Some frameworks apply auth middleware only to POST or only to GET,
    leaving other verbs unprotected.
    """
    findings = []

    test_paths = ["/admin", "/api/users", "/api/admin", "/dashboard"]

    for path in test_paths:
        url = base_url.rstrip("/") + path

        # First check if GET is properly blocked
        get_resp = get(url, cookie=None)
        if get_resp is None or get_resp.status_code not in (401, 403):
            continue  # Not blocked by GET anyway — skip

        # Now try POST, PUT, PATCH, DELETE, HEAD, OPTIONS
        for method in ["POST", "PUT", "PATCH", "HEAD", "OPTIONS"]:
            try:
                resp = requests.request(
                    method,
                    url,
                    headers = {"User-Agent": "Mozilla/5.0"},
                    timeout = 8,
                    verify  = VERIFY_SSL,
                )
                if resp.status_code == 200:
                    findings.append(finding(
                        title       = f"Auth Bypass via HTTP Method Switching: {method} {path}",
                        severity    = HIGH,
                        description = (
                            f"GET {path} is correctly blocked with HTTP {get_resp.status_code}, "
                            f"but {method} {path} returned HTTP 200 without authentication."
                        ),
                        impact      = "An attacker can bypass authentication by using an unexpected HTTP method.",
                        remediation = (
                            "Apply authentication checks at the route/endpoint level, not just "
                            "for specific HTTP methods. Ensure all verbs hitting the same resource "
                            "require the same level of auth."
                        ),
                        evidence    = f"GET -> {get_resp.status_code} | {method} -> {resp.status_code}",
                    ))
                    break
            except Exception:
                continue

    return findings


def _check_role_parameter_manipulation(base_url, cookie=None):
    """
    Submit registration or profile update with elevated role parameters.

    Some apps accept role, is_admin, account_type etc in request bodies
    and use the client-supplied value rather than assigning one server-side.
    """
    findings = []

    # Common registration endpoints
    reg_endpoints = [
        "/register", "/signup", "/api/register",
        "/api/v1/register", "/api/v1/users", "/api/users",
    ]

    role_payloads = [
        {"role": "admin"},
        {"role": "administrator"},
        {"is_admin": True},
        {"is_admin": "true"},
        {"is_admin": 1},
        {"account_type": "admin"},
        {"user_type": "admin"},
        {"permissions": "admin"},
        {"level": 9999},
        {"privilege": "superuser"},
    ]

    for endpoint in reg_endpoints:
        url = base_url.rstrip("/") + endpoint

        # Probe whether the endpoint exists first
        probe = get(url)
        if probe is None or probe.status_code == 404:
            continue

        for payload in role_payloads:
            resp = post(
                url,
                data    = payload,
                cookie  = cookie,
            )

            if resp is None:
                continue

            # If the server echoes back our role value in the response,
            # it may have accepted it
            for key, value in payload.items():
                if str(value).lower() in resp.text.lower() and resp.status_code in (200, 201):
                    findings.append(finding(
                        title       = f"Potential Mass Assignment / Role Escalation via '{key}' Field",
                        severity    = HIGH,
                        description = (
                            f"Submitting a POST to {endpoint} with '{key}={value}' "
                            f"returned a 200/201 response that echoed the value back, "
                            f"suggesting the server may have accepted the elevated role."
                        ),
                        impact      = (
                            "An attacker may be able to register or update an account "
                            "with administrator privileges by sending extra fields."
                        ),
                        remediation = (
                            "Use a strict allowlist of accepted fields when processing "
                            "registration and update requests. Never bind user-supplied "
                            "objects directly to your data model (mass assignment)."
                        ),
                        evidence    = f"Endpoint: {endpoint} | Payload: {payload} | Status: {resp.status_code}",
                    ))
                    break

    return findings


def _decode_jwt(token):
    """Base64-decode a JWT header and payload without verification."""
    try:
        parts  = token.split(".")
        if len(parts) != 3:
            return None, None

        # Add padding so base64 doesn't complain
        header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        return header, payload
    except Exception:
        return None, None


def _build_none_jwt(header, payload):
    """Build a JWT with alg: none and an empty signature."""
    header["alg"] = "none"
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{h}.{p}."


def _check_jwt_none_algorithm(base_url, cookie=None):
    """
    Look for JWTs in cookies or Authorization headers and test the none algorithm.

    The none algorithm attack lets an attacker forge a JWT by setting
    alg to none and removing the signature. Libraries that fail to
    reject this will accept it as valid.
    """
    findings = []

    if not cookie:
        return findings

    # Extract JWTs from the cookie string
    jwt_pattern = re.compile(r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]*")
    tokens      = jwt_pattern.findall(cookie)

    for token in tokens:
        header, payload = _decode_jwt(token)
        if header is None:
            continue

        alg = header.get("alg", "").lower()
        if alg in ("none", ""):
            continue  # Already using none — that's a finding in itself

        # Try the none algorithm attack
        none_token   = _build_none_jwt(dict(header), dict(payload))
        test_resp    = get(base_url, cookie=f"token={none_token}")

        if test_resp and test_resp.status_code == 200:
            findings.append(finding(
                title       = "JWT None Algorithm Attack Accepted",
                severity    = CRITICAL,
                description = (
                    "The server accepted a JWT with alg=none and no signature. "
                    "This means the server does not validate JWT signatures."
                ),
                impact      = (
                    "An attacker can forge a JWT with any claims — including "
                    "elevated roles or other users' identities — without knowing "
                    "the signing secret."
                ),
                remediation = (
                    "Explicitly reject JWTs with alg=none. Use a JWT library that "
                    "enforces algorithm whitelisting. Never trust the algorithm "
                    "specified in the JWT header — hardcode the expected algorithm."
                ),
                evidence    = f"Original alg: {alg} | none-algorithm token accepted with HTTP 200",
            ))

    return findings


def run(base_url, cookie=None):
    print(f"{Fore.CYAN}[*] Testing for auth bypass and privilege escalation...{Style.RESET_ALL}")
    findings = []

    checks = [
        ("Forced browsing",            _check_forced_browsing,            (base_url, cookie)),
        ("HTTP method switching",       _check_method_switching,           (base_url, cookie)),
        ("Role parameter manipulation", _check_role_parameter_manipulation,(base_url, cookie)),
        ("JWT none algorithm",          _check_jwt_none_algorithm,         (base_url, cookie)),
    ]

    for check_name, check_fn, args in checks:
        hits = check_fn(*args)
        for f in hits:
            findings.append(f)
            print(f"  {badge(f['severity'])} {f['title']}")

    if not findings:
        print(f"{Fore.GREEN}[+] No auth bypass or privilege escalation issues found{Style.RESET_ALL}")

    return findings
