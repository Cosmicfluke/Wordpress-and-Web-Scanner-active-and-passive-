# Markdown report generator.
# Output is structured to paste directly into a pentest report.
# Findings are sorted Critical -> High -> Medium -> Low -> Info.

from datetime import datetime
from collections import Counter
from utils.severity import SEVERITY_ORDER

SEVERITY_EMOJI = {
    "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵", "Info": "⚪",
}


def _sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99))


def _finding_block(f, index):
    sev   = f.get("severity", "Info")
    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    lines = [
        f"### {index}. {emoji} {f['title']}",
        "",
        f"| Field | Detail |",
        f"|---|---|",
        f"| **Severity** | {sev} |",
        f"| **Description** | {f.get('description', '').replace(chr(10), ' ')} |",
        f"| **Impact** | {f.get('impact', '').replace(chr(10), ' ')} |",
        f"| **Remediation** | {f.get('remediation', '').replace(chr(10), ' ')} |",
    ]
    evidence = f.get("evidence", "").strip()
    if evidence:
        lines += ["", "**Evidence:**", "```", evidence, "```"]
    lines.append("")
    return "\n".join(lines)


def _cve_block(vulns, source):
    if not vulns:
        return ""
    lines = [f"**Known CVEs ({source}):**\n"]
    for v in vulns:
        cvss  = f"CVSS: {v['cvss']}" if v.get("cvss") else ""
        cves  = ", ".join(v.get("cve") or []) or "No CVE assigned"
        fixed = f"Fixed in: {v['fixed_in']}" if v.get("fixed_in") else "No fix available"
        lines.append(f"- **{v['title']}** — {cves} {cvss} | {fixed}")
    return "\n".join(lines) + "\n"


def _collect_findings(results):
    keys = [
        "header_findings", "ssl_findings", "injection_findings",
        "traversal_findings", "idor_findings", "fileupload_findings",
        "authbypass_findings", "app_findings", "misconfigurations_findings",
        "infodisclosure_findings", "bizlogic_findings", "auth_findings",
        "waf_findings",
    ]
    return [f for k in keys for f in results.get(k, [])]


def generate(results, outfile):
    target  = results.get("target", "Unknown")
    elapsed = results.get("elapsed_seconds", 0)
    now     = datetime.now().strftime("%Y-%m-%d %H:%M")
    recon   = results.get("recon", {})
    wp_ver  = recon.get("version") or "Unknown"
    mode    = results.get("mode", "web").upper()

    all_findings = _collect_findings(results)
    sev_counts   = Counter(f.get("severity") for f in all_findings)
    plugins      = results.get("plugins", {})
    themes       = results.get("themes", {})
    core_vulns   = results.get("core_vulnerabilities", [])
    plugin_cves  = sum(len(p.get("vulnerabilities", [])) for p in plugins.values())
    theme_cves   = sum(len(t.get("vulnerabilities", [])) for t in themes.values())

    lines = [
        "# Security Assessment Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Target** | {target} |",
        f"| **Date** | {now} |",
        f"| **Mode** | {mode} |",
        f"| **WordPress** | {wp_ver} |",
        f"| **Duration** | {elapsed}s |",
        f"| **Tool** | LOTR |",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"This assessment identified **{len(all_findings)} findings**.",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| 🔴 Critical | {sev_counts.get('Critical', 0)} |",
        f"| 🟠 High | {sev_counts.get('High', 0)} |",
        f"| 🟡 Medium | {sev_counts.get('Medium', 0)} |",
        f"| 🔵 Low | {sev_counts.get('Low', 0)} |",
        f"| ⚪ Info | {sev_counts.get('Info', 0)} |",
        "",
    ]

    if core_vulns or plugin_cves or theme_cves:
        lines += [
            f"**WordPress Core CVEs:** {len(core_vulns)} | "
            f"**Plugin CVEs:** {plugin_cves} | "
            f"**Theme CVEs:** {theme_cves}",
            "",
        ]

    lines += ["---", "", "## Findings", ""]

    for i, f in enumerate(_sort_findings(all_findings), 1):
        lines.append(_finding_block(f, i))

    if core_vulns:
        lines += [
            "---", "",
            f"## WordPress Core Vulnerabilities (v{wp_ver})", "",
            "> CVE scores sourced from the WPScan Vulnerability Database.", "",
            _cve_block(core_vulns, f"WordPress {wp_ver}"), "",
        ]

    plugin_cve_lines = []
    for slug, data in plugins.items():
        vulns = data.get("vulnerabilities", [])
        if vulns:
            plugin_cve_lines += [f"#### {slug} (v{data.get('version') or 'unknown'})\n", _cve_block(vulns, slug)]

    if plugin_cve_lines:
        lines += ["---", "", "## Plugin Vulnerabilities", "", "> CVE scores from WPScan Vulnerability Database.", ""] + plugin_cve_lines

    theme_cve_lines = []
    for slug, data in themes.items():
        vulns = data.get("vulnerabilities", [])
        if vulns:
            theme_cve_lines += [f"#### {slug} (v{data.get('version') or 'unknown'})\n", _cve_block(vulns, slug)]

    if theme_cve_lines:
        lines += ["---", "", "## Theme Vulnerabilities", ""] + theme_cve_lines

    users = results.get("enumeration", {}).get("users", [])
    if users:
        lines += ["---", "", "## Enumeration", "", f"**Users:** {len(users)}", ""]
        for u in users:
            lines.append(f"- ID: {u.get('id')} | Name: {u.get('name') or u.get('slug')}")

    if plugins:
        lines += ["", f"**Plugins:** {len(plugins)}", ""]
        for slug, data in plugins.items():
            lines.append(f"- {slug} (v{data.get('version') or 'unknown'})")

    if themes:
        lines += ["", f"**Themes:** {len(themes)}", ""]
        for slug, data in themes.items():
            lines.append(f"- {slug} (v{data.get('version') or 'unknown'})")

    lines += [
        "", "---", "",
        "*Report generated by LOTR. CVE scores are sourced from the WPScan Vulnerability Database.*",
        "*All other severity ratings use a Critical/High/Medium/Low/Info tier system.*",
    ]

    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"\033[32m[+] Markdown report written to {outfile}\033[0m")
