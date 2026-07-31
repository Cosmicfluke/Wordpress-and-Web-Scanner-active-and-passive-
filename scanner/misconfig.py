# Sensitive file and misconfiguration checks.
# Only flags a path as exposed if it returns real content — an empty
# 200 response (common for PHP files with no direct output) discloses
# nothing and shouldn't be reported as a finding.

from colorama import Fore, Style
from utils.http import get

# Paths that genuinely disclose something when accessible.
# xmlrpc.php, wp-cron.php, and wp-json/wp/v2/users are checked properly
# elsewhere (enum.py, bizlogic.py) with logic specific to what they expose —
# they don't belong here since a bare 200 on those paths means nothing on its own.
SENSITIVE_PATHS = [
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.php.save",
    ".wp-config.php.swp",
    "wp-config.txt",
    ".env",
    ".git/config",
    "wp-content/debug.log",
    "wp-content/uploads/wp-config.php",
    "readme.html",
    "license.txt",
    "wp-content/uploads/",
]

DIRECTORY_LISTING_HINTS = ["Index of /", "<title>Index of"]

# Minimum bytes required before we trust a 200 response as real disclosure.
# Below this, it's almost certainly a blank page from a PHP file with no
# direct output (e.g. version.php just defines variables, prints nothing).
MIN_CONTENT_LENGTH = 20


def check_path(base_url, path):
    url  = f"{base_url.rstrip('/')}/{path}"
    resp = get(url)

    if resp is None or resp.status_code != 200:
        return None

    # Empty or near-empty response — nothing was actually disclosed.
    if len(resp.text.strip()) < MIN_CONTENT_LENGTH:
        return None

    listing = any(hint in resp.text for hint in DIRECTORY_LISTING_HINTS)
    return {"path": path, "status": resp.status_code, "directory_listing": listing}


def run(base_url, paths=None):
    print(f"{Fore.CYAN}[*] Checking for exposed sensitive files...{Style.RESET_ALL}")
    findings = []

    for path in (paths or SENSITIVE_PATHS):
        result = check_path(base_url, path)
        if result:
            findings.append(result)
            tag = " [directory listing]" if result["directory_listing"] else ""
            print(f"{Fore.RED}[!] Exposed: /{path} (HTTP {result['status']}){tag}{Style.RESET_ALL}")

    if not findings:
        print(f"{Fore.GREEN}[+] No exposed sensitive files found{Style.RESET_ALL}")

    return findings
