# Severity tiers used across all modules.
# We don't generate synthetic CVSS scores — CVE-backed findings use
# official scores from WPScan DB, everything else uses these tiers.

CRITICAL = "Critical"
HIGH     = "High"
MEDIUM   = "Medium"
LOW      = "Low"
INFO     = "Info"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

SEVERITY_COLORS = {
    CRITICAL : "\033[91m",
    HIGH     : "\033[31m",
    MEDIUM   : "\033[33m",
    LOW      : "\033[34m",
    INFO     : "\033[36m",
}

RESET = "\033[0m"


def badge(severity):
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}[{severity.upper()}]{RESET}"


def finding(title, severity, description, impact, remediation, evidence=None):
    return {
        "title"       : title,
        "severity"    : severity,
        "description" : description,
        "impact"      : impact,
        "remediation" : remediation,
        "evidence"    : evidence or "",
    }
