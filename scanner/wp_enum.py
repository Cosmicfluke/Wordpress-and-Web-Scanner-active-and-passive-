# WordPress user enumeration and endpoint exposure checks.

import re
from colorama import Fore, Style
from utils.http import get, post


def _users_from_rest(base_url):
    users = []
    resp  = get(f"{base_url.rstrip('/')}/wp-json/wp/v2/users")
    if resp and resp.status_code == 200:
        try:
            for u in resp.json():
                users.append({"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")})
        except ValueError:
            pass
    return users


def _users_from_author_scan(base_url, max_id=10):
    # WordPress redirects ?author=N to /author/<slug>/ revealing usernames.
    users = []
    for uid in range(1, max_id + 1):
        resp = get(f"{base_url.rstrip('/')}/?author={uid}", allow_redirects=False)
        if not resp:
            continue
        m = re.search(r"/author/([^/]+)/?", resp.headers.get("Location", ""))
        if m:
            users.append({"id": uid, "slug": m.group(1)})
    return users


def _check_xmlrpc(base_url):
    url  = f"{base_url.rstrip('/')}/xmlrpc.php"
    body = "<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>"
    resp = post(url, data=body, headers={"Content-Type": "text/xml"})
    return bool(resp and resp.status_code == 200 and "<methodResponse>" in resp.text)


def run(base_url):
    results = {"users": [], "xmlrpc_enabled": False, "rest_api_exposed": False}

    print(f"{Fore.CYAN}[*] Enumerating users via REST API...{Style.RESET_ALL}")
    users = _users_from_rest(base_url)

    if not users:
        print(f"{Fore.YELLOW}[!] REST API blocked — trying author scan...{Style.RESET_ALL}")
        users = _users_from_author_scan(base_url)

    results["users"] = users
    if users:
        print(f"{Fore.GREEN}[+] Found {len(users)} user(s){Style.RESET_ALL}")
        for u in users:
            print(f"    - {u}")
    else:
        print(f"{Fore.YELLOW}[!] No users found{Style.RESET_ALL}")

    print(f"{Fore.CYAN}[*] Checking xmlrpc.php...{Style.RESET_ALL}")
    results["xmlrpc_enabled"] = _check_xmlrpc(base_url)
    if results["xmlrpc_enabled"]:
        print(f"{Fore.RED}[!] xmlrpc.php enabled — brute-force and SSRF pivot possible{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] xmlrpc.php not responding{Style.RESET_ALL}")

    resp = get(f"{base_url.rstrip('/')}/wp-json/")
    results["rest_api_exposed"] = bool(resp and resp.status_code == 200)
    if results["rest_api_exposed"]:
        print(f"{Fore.GREEN}[+] REST API reachable{Style.RESET_ALL}")

    return results
