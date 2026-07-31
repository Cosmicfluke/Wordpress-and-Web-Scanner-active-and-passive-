#!/usr/bin/env python3
#
# LOTR — One scanner to rule them all.
#
# Usage:
#   python main.py -u https://target.com --markdown report.md
#   python main.py -u https://target.com --active --markdown report.md
#   python main.py -u https://target.com --mode wordpress --api-token TOKEN --markdown report.md
#   python main.py -u https://target.com --cookie "session=abc123" --active --markdown report.md

import argparse
import os
import sys
import warnings

warnings.filterwarnings("ignore")

from colorama import init as colorama_init
colorama_init(autoreset=True)

from scanner.core import run_scan
from reporter import report
from reporter import markdown as md_report

BANNER = r"""
  _      ___ _____ ___
 | |    / _ \_   _| _ \
 | |__ | (_) || | |   /
 |____| \___/ |_| |_|_\

 One scanner to rule them all. One scanner to find them. One scanner to bring the Vulnerabilities and in the darkness bind them.

"""


def parse_args():
    p = argparse.ArgumentParser(
        description     = "LOTR — web application and WordPress security scanner",
        formatter_class = argparse.RawTextHelpFormatter,
    )

    p.add_argument("-u", "--url", required=True, help="Target URL")

    mode = p.add_argument_group("Mode")
    mode.add_argument(
        "--mode",
        choices = ["web", "wordpress"],
        default = "web",
        help    = "web: any web app (default)\nwordpress: web + WordPress-specific checks",
    )

    scan = p.add_argument_group("Scan options")
    scan.add_argument("--active",  action="store_true", help="Enable active checks (prompts for confirmation)")
    scan.add_argument("--yes",     action="store_true", help="Skip active mode confirmation")
    scan.add_argument("--stealth", action="store_true", help="Random delays + UA rotation")
    scan.add_argument("--cookie",  metavar="COOKIE",   help="Session cookie for authenticated checks")
    scan.add_argument("--active-plugins", action="store_true", help="WordPress: probe plugin wordlist actively")
    scan.add_argument("--plugin-wordlist", metavar="FILE",     help="WordPress: custom plugin slug wordlist")

    out = p.add_argument_group("Output")
    out.add_argument("--json",     metavar="FILE", help="Write results to JSON")
    out.add_argument("--markdown", metavar="FILE", help="Write Markdown report")

    api = p.add_argument_group("API")
    api.add_argument("--api-token", metavar="TOKEN", help="WPScan API token for CVE lookups")

    return p.parse_args()


def main():
    args = parse_args()
    print(BANNER)

    if args.api_token:
        os.environ["WPSCAN_API_TOKEN"] = args.api_token

    if args.stealth:
        from utils import stealth
        stealth.enable()
        print("\033[33m[*] Stealth mode enabled\033[0m")

    wordlist = None
    if args.plugin_wordlist:
        try:
            with open(args.plugin_wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(wordlist)} plugin slugs")
        except OSError as e:
            print(f"[!] Could not read wordlist: {e}")
            sys.exit(1)

    options = {
        "mode"               : args.mode,
        "active"             : args.active,
        "active_confirmed"   : args.yes,
        "cookie"             : args.cookie,
        "active_plugin_probe": args.active_plugins,
        "plugin_wordlist"    : wordlist,
    }

    results = run_scan(args.url, options=options)
    report.summary(results)

    # NOSONAR - args.json / args.markdown come from the operator's own CLI
    # invocation on their own machine, not from a remote or untrusted source.
    # There is no attacker-controlled input reaching these paths.
    if args.json:
        report.to_json(results, args.json)
    if args.markdown:
        md_report.generate(results, args.markdown)


if __name__ == "__main__":
    main()
