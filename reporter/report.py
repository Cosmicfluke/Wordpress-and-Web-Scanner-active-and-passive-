# Terminal summary and JSON export.

import json
from colorama import Fore, Style
from utils.pathsafe import safe_output_path


def to_json(results, outfile):
    safe_path = safe_output_path(outfile)
    with open(safe_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"{Fore.GREEN}[+] JSON report written to {safe_path}{Style.RESET_ALL}")


def _collect_findings(results):
    keys = [
        "header_findings", "ssl_findings", "injection_findings",
        "traversal_findings", "idor_findings", "fileupload_findings",
        "authbypass_findings", "app_findings", "misconfigurations_findings",
        "infodisclosure_findings", "bizlogic_findings", "auth_findings",
        "waf_findings",
    ]
    return [f for k in keys for f in results.get(k, [])]


def summary(results):
    from collections import Counter

    print(f"\n{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")

    if results.get("aborted"):
        print(f"{Fore.RED}Scan aborted — target is not WordPress.{Style.RESET_ALL}")
        return

    recon   = results.get("recon", {})
    waf     = results.get("waf", {})
    users   = results.get("enumeration", {}).get("users", [])
    plugins = results.get("plugins", {})
    themes  = results.get("themes", {})
    core_v  = results.get("core_vulnerabilities", [])

    plugin_cves = sum(len(p.get("vulnerabilities", [])) for p in plugins.values())
    theme_cves  = sum(len(t.get("vulnerabilities", [])) for t in themes.values())

    all_findings = _collect_findings(results)
    sev_counts   = Counter(f.get("severity") for f in all_findings)

    if recon.get("version"):
        print(f"WordPress version : {recon['version']}")
    if waf.get("name"):
        print(f"WAF               : {waf['name']}")
    if users:
        print(f"Users found       : {len(users)}")
    if plugins:
        print(f"Plugins detected  : {len(plugins)}  ({plugin_cves} CVEs)")
    if themes:
        print(f"Themes detected   : {len(themes)}  ({theme_cves} CVEs)")
    if core_v:
        print(f"Core CVEs         : {len(core_v)}")

    print()
    colors = {
        "Critical": Fore.RED, "High": Fore.RED,
        "Medium": Fore.YELLOW, "Low": Fore.BLUE, "Info": Fore.CYAN,
    }
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = sev_counts.get(sev, 0)
        if count:
            print(f"  {colors[sev]}{sev:<10}{Style.RESET_ALL}: {count}")

    if results.get("enumeration", {}).get("xmlrpc_enabled"):
        print(f"\n{Fore.RED}xmlrpc.php: ENABLED{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")