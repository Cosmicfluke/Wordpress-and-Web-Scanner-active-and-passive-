"""
TLS/SSL checks: protocol version, weak ciphers, certificate basics.
Uses the ssl module — no extra dependencies.
"""

import ssl
import socket
from urllib.parse import urlparse
from colorama import Fore, Style
from utils.severity import finding, badge, HIGH, MEDIUM, LOW, INFO

WEAK_PROTOCOLS = {
    "SSLv2"  : CRITICAL if "CRITICAL" in dir() else HIGH,
    "SSLv3"  : HIGH,
    "TLSv1"  : MEDIUM,
    "TLSv1.1": MEDIUM,
}

try:
    from utils.severity import CRITICAL
except ImportError:
    CRITICAL = HIGH


def _get_cert_info(hostname, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {
                    "protocol": ssock.version(),
                    "cipher"  : ssock.cipher(),
                    "cert"    : ssock.getpeercert(),
                }
    except Exception as e:
        return {"error": str(e)}


def _check_weak_protocol(hostname, port, proto_const):
    """Try to connect using a specific legacy protocol version."""
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def run(base_url):
    print(f"{Fore.CYAN}[*] Checking TLS configuration...{Style.RESET_ALL}")
    findings = []

    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        findings.append(finding(
            title="Site Not Using HTTPS",
            severity=HIGH,
            description="The target URL uses HTTP, not HTTPS.",
            impact="All traffic is transmitted in plaintext. Credentials, session tokens, and data are exposed to interception.",
            remediation="Enforce HTTPS site-wide. Obtain a TLS certificate (Let's Encrypt is free) and redirect all HTTP to HTTPS.",
            evidence=f"URL scheme: {parsed.scheme}",
        ))
        print(f"  {badge('High')} Site not served over HTTPS")
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    info = _get_cert_info(hostname, port)
    if "error" in info:
        print(f"{Fore.YELLOW}[!] TLS check failed: {info['error']}{Style.RESET_ALL}")
        return findings

    proto = info.get("protocol", "")
    cipher_name = info.get("cipher", ("", "", ""))[0]

    print(f"  [i] Protocol : {proto}")
    print(f"  [i] Cipher   : {cipher_name}")

    # TLSv1.0 / TLSv1.1 — check what the server negotiated
    if proto in ("TLSv1", "TLSv1.1"):
        findings.append(finding(
            title=f"Weak TLS Protocol in Use: {proto}",
            severity=MEDIUM,
            description=f"The server negotiated {proto}, which is deprecated and insecure.",
            impact="Deprecated TLS versions are vulnerable to protocol downgrade attacks (POODLE, BEAST).",
            remediation="Configure the server to support TLS 1.2 minimum. Disable TLS 1.0 and 1.1 in server config.",
            evidence=f"Negotiated protocol: {proto}",
        ))
        print(f"  {badge('Medium')} Weak TLS protocol: {proto}")

    # Weak ciphers
    weak_cipher_keywords = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
    for kw in weak_cipher_keywords:
        if kw.upper() in cipher_name.upper():
            findings.append(finding(
                title=f"Weak Cipher Suite in Use: {cipher_name}",
                severity=HIGH,
                description=f"The server negotiated the weak cipher suite: {cipher_name}",
                impact="Weak ciphers can be broken, exposing encrypted traffic to decryption.",
                remediation="Disable weak cipher suites. Prefer ECDHE+AES256+GCM or CHACHA20-POLY1305.",
                evidence=f"Cipher: {cipher_name}",
            ))
            print(f"  {badge('High')} Weak cipher: {cipher_name}")
            break

    if not findings:
        print(f"{Fore.GREEN}[+] TLS configuration looks acceptable ({proto} / {cipher_name}){Style.RESET_ALL}")

    return findings
