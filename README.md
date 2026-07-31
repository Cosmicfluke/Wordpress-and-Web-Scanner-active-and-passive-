# LOTR (One Scanner to Rule Them All)

Web application and WordPress security scanner for penetration testers.

## Setup

```bash
pip install -r requirements.txt
```

For CVE lookups, get a free WPScan API token at https://wpscan.com/register:

```bash
export WPSCAN_API_TOKEN=your_token_here
```

## Usage

```bash
# Any web app — passive
python main.py -u https://target.com --markdown report.md

# Any web app — active (will prompt for confirmation)
python main.py -u https://target.com --active --markdown report.md

# WordPress — passive with CVE lookups
python main.py -u https://target.com --mode wordpress --markdown report.md

# WordPress — full active scan with CVEs
python main.py -u https://target.com --mode wordpress \
  --active --api-token YOUR_TOKEN \
  --markdown report.md --json report.json

# Authenticated scan (pass your session cookie)
python main.py -u https://target.com \
  --cookie "session=abc123; csrf=xyz" \
  --active --markdown report.md

# WordPress with active plugin probing
python main.py -u https://target.com --mode wordpress \
  --active-plugins --markdown report.md

# Stealth mode (slower, quieter)
python main.py -u https://target.com --mode wordpress --stealth --markdown report.md
```

## Structure

```
main.py               CLI entrypoint

scanner/
  core.py             Orchestrator - mode-aware
  recon.py            WP detection + version fingerprint
  waf.py              WAF detection + evasion trigger
  enum.py             User enum, xmlrpc, REST API
  plugins.py          Plugin detection + CVE lookup (WAF-aware)
  themes.py           Theme detection + CVE lookup
  headers.py          Security headers, CORS, cookies
  ssl.py              TLS version + cipher checks
  misconfig.py        Sensitive file exposure
  appcheck.py         Debug mode, open registration, cron
  infodisclosure.py   Path errors, feeds, REST data leaks
  bizlogic.py         Uploads, git exposure, backup files
  authcheck.py        WP login protection (active)
  injection.py        XSS, SQLi, SSRF, open redirect (active)
  traversal.py        Directory traversal (any web app)
  idor.py             IDOR - numeric, UUID, param fuzzing (any web app)
  fileupload.py       Upload endpoint discovery + bypass (any web app)
  authbypass.py       Auth logic flaws, JWT none, mass assignment (any web app)

reporter/
  report.py           Colour terminal summary + JSON export
  markdown.py         Pentest-ready Markdown report

utils/
  http.py             Shared GET/POST wrapper
  severity.py         Finding structure + severity tiers
  stealth.py          UA rotation, jitter, cover requests
  wpscan_db.py        WPScan Vulnerability Database client
  gowitness.py        Optional screenshot helper
```

## Notes

- Active mode (`--active`) prompts for confirmation before firing. Use `--yes` to skip in scripts.
- `--cookie` enables authenticated checks for IDOR, auth bypass, and upload tests.
- CVE scores in reports are official figures from WPScan DB. All other severities use Critical/High/Medium/Low/Info tiers.
- Only use against targets you have explicit written authorisation to test.
