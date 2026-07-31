# WPScan Vulnerability Database client.
# Free API key: https://wpscan.com/register
# Set WPSCAN_API_TOKEN env var or pass --api-token on the CLI.
# Without a token, CVE lookups return empty lists silently.

import os
from utils.http import get

API_BASE = "https://wpscan.com/api/v3"


def _token():
    return os.environ.get("WPSCAN_API_TOKEN", "")


def _auth():
    tok = _token()
    return {"Authorization": f"Token token={tok}"} if tok else {}


def plugin_vulns(slug, version=None):
    if not _token():
        return []
    resp = get(f"{API_BASE}/plugins/{slug}", headers=_auth())
    if not resp or resp.status_code != 200:
        return []
    return _parse(resp.json(), slug, version)


def theme_vulns(slug, version=None):
    if not _token():
        return []
    resp = get(f"{API_BASE}/themes/{slug}", headers=_auth())
    if not resp or resp.status_code != 200:
        return []
    return _parse(resp.json(), slug, version)


def wordpress_vulns(version):
    if not _token():
        return []
    key  = version.replace(".", "")
    resp = get(f"{API_BASE}/wordpresses/{key}", headers=_auth())
    if not resp or resp.status_code != 200:
        return []
    return _parse(resp.json(), version, version)


def _parse(data, key, installed_version):
    try:
        entries = data.get(key, {}).get("vulnerabilities", [])
    except AttributeError:
        return []

    results = []
    for entry in entries:
        fixed_in = entry.get("fixed_in")

        # Skip if already patched.
        if installed_version and fixed_in:
            try:
                from packaging.version import Version
                if Version(installed_version) >= Version(fixed_in):
                    continue
            except Exception:
                pass

        results.append({
            "title"    : entry.get("title", "Unknown"),
            "cvss"     : entry.get("cvss", {}).get("score"),
            "cve"      : entry.get("references", {}).get("cve", []),
            "fixed_in" : fixed_in,
            "url"      : entry.get("references", {}).get("url", []),
        })

    return results
