# Core orchestrator.
#
# Runs checks in the right order depending on the selected mode:
#
#   web       — Layer 1 only: headers, TLS, injection, traversal, IDOR,
#               file upload, auth bypass
#
#   wordpress — Layer 1 + Layer 2: everything above plus WordPress-specific
#               recon, plugin/theme CVEs, user enum, misconfig, WAF detection
#
# Active checks (auth bypass attempts, injection, upload bypass) only run
# when --active is passed and the user confirms.

import time

from colorama import Fore, Style

from scanner import (
    headers,
    ssl as ssl_mod,
    injection,
    traversal,
    idor,
    fileupload,
    authbypass,
)

from utils.severity import finding as sev_finding, MEDIUM


def _section(title):
    print(f"\n{Fore.MAGENTA}[{title}]{Style.RESET_ALL}")


def _confirm_active():
    """Prompt the user before running active checks."""
    print(f"\n{Fore.YELLOW}{'=' * 60}")
    print(f"  [!] ACTIVE MODE")
    print(f"  Active checks will send probing requests including")
    print(f"  injection payloads, upload bypass attempts, and")
    print(f"  auth manipulation. Only continue if you have explicit")
    print(f"  written authorisation to test this target.")
    print(f"{'=' * 60}{Style.RESET_ALL}")

    try:
        answer = input("  Continue? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"

    return answer == "y"


def _run_layer1(base_url, html, options, results):
    """
    Layer 1: checks that apply to any web application.
    """
    active = options.get("active", False)
    cookie = options.get("cookie")

    _section("HTTP Security Headers / CORS / Cookies")
    results["header_findings"] = headers.run(base_url)

    _section("TLS / SSL")
    results["ssl_findings"] = ssl_mod.run(base_url)

    _section("Directory Traversal")
    results["traversal_findings"] = traversal.run(base_url)

    _section("IDOR")
    results["idor_findings"] = idor.run(base_url, cookie=cookie)

    _section("File Upload")
    results["fileupload_findings"] = fileupload.run(
        base_url,
        html   = html,
        cookie = cookie,
        active = active,
    )

    if active:
        _section("Injection (XSS, SQLi, SSRF)")
        results["injection_findings"] = injection.run(base_url)

        _section("Auth Bypass / Privilege Escalation")
        results["authbypass_findings"] = authbypass.run(base_url, cookie=cookie)
    else:
        results["injection_findings"]  = []
        results["authbypass_findings"] = []

    return results


def _run_layer2(base_url, options, results):
    """
    Layer 2: WordPress-specific checks.
    Runs on top of Layer 1 when --mode wordpress is used.
    """
    from scanner import (
        recon, wp_enum as enum_mod, plugins, themes,
        misconfig, appcheck, waf, infodisclosure,
        authcheck, bizlogic,
    )
    from utils import wpscan_db

    active = options.get("active", False)
    cookie = options.get("cookie")

    _section("WAF Detection")
    waf_result, waf_findings = waf.run(base_url)
    results["waf"]         = waf_result
    results["waf_findings"] = waf_findings

    if waf_result["detected"]:
        from utils import stealth
        stealth.enable_waf_evasion()

    _section("WordPress Recon + Fingerprinting")
    recon_result = recon.run(base_url)
    results["recon"] = recon_result

    if not recon_result["is_wordpress"]:
        print(f"{Fore.RED}[-] WordPress not detected — skipping WP-specific checks{Style.RESET_ALL}")
        return results

    html    = recon_result["html"]
    wp_ver  = recon_result["version"]

    # Pass the real HTML back up so Layer 1 checks can use it
    results["html"] = html

    _section("User Enumeration")
    enum_result = enum_mod.run(base_url)
    results["enumeration"] = enum_result

    _section("Plugin Detection + CVE Lookup")
    results["plugins"] = plugins.run(
        base_url,
        html         = html,
        wordlist     = options.get("plugin_wordlist"),
        active_probe = options.get("active_plugin_probe", False),
        waf_detected = waf_result["detected"],
    )

    _section("Theme Detection + CVE Lookup")
    results["themes"] = themes.run(base_url, html)

    _section("Misconfigurations + Sensitive Files")
    misc_raw = misconfig.run(base_url)
    results["misconfigurations"] = misc_raw

    misc_findings = []
    for m in misc_raw:
        tag = " [directory listing]" if m.get("directory_listing") else ""
        misc_findings.append(sev_finding(
            title       = f"Sensitive File Exposed: /{m['path']}{tag}",
            severity    = MEDIUM,
            description = f"/{m['path']} returned HTTP {m['status']}.",
            impact      = "May reveal credentials, configuration, or version details.",
            remediation = "Remove or restrict access to this file.",
            evidence    = f"HTTP {m['status']} at /{m['path']}",
        ))
    results["misconfigurations_findings"] = misc_findings

    _section("Application Checks")
    results["app_findings"] = appcheck.run(base_url, html, active=active)

    _section("Information Disclosure")
    results["infodisclosure_findings"] = infodisclosure.run(base_url)

    _section("Business Logic")
    results["bizlogic_findings"] = bizlogic.run(base_url, active=active)

    if wp_ver:
        core_vulns = wpscan_db.wordpress_vulns(wp_ver)
        results["core_vulnerabilities"] = core_vulns
        if core_vulns:
            print(f"\n{Fore.RED}[!] WordPress {wp_ver} has {len(core_vulns)} known CVEs{Style.RESET_ALL}")
    else:
        results["core_vulnerabilities"] = []

    if active:
        _section("WordPress Auth Checks")
        discovered_users = enum_result.get("users", [])
        results["auth_findings"] = authcheck.run(
            base_url,
            discovered_users = discovered_users,
        )
    else:
        results["auth_findings"] = []

    return results


def run_scan(base_url, options=None):
    options = options or {}
    mode    = options.get("mode", "web")
    active  = options.get("active", False)
    started = time.time()

    # Confirm active mode before doing anything
    if active and not options.get("active_confirmed"):
        if not _confirm_active():
            print(f"{Fore.YELLOW}[!] Active mode cancelled — running passive only{Style.RESET_ALL}")
            options["active"] = False
            active = False

    print(f"\n{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  LOTR  |  {base_url}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  Mode: {mode.upper()}  |  Active: {'YES' if active else 'NO'}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")

    results = {
        "target"      : base_url,
        "mode"        : mode,
        "active_mode" : active,
        "html"        : "",
    }

    # Layer 1 always runs
    results = _run_layer1(base_url, results.get("html", ""), options, results)

    # Layer 2 only for WordPress mode
    if mode == "wordpress":
        results = _run_layer2(base_url, options, results)

    elapsed = round(time.time() - started, 1)
    results["elapsed_seconds"] = elapsed

    print(f"\n{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}  Scan complete in {elapsed}s{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")

    return results
