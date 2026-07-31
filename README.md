# LOTR: One Scanner to Rule Them All

A security scanner for web applications and WordPress, built for penetration testers.

Runs a full set of checks against any web app (headers, TLS, IDOR, directory traversal,
file upload, auth bypass, injection), and adds a deep WordPress-specific layer on top
when you need it (plugin/theme CVEs, user enumeration, xmlrpc abuse, WAF-aware scanning).

Every finding comes with severity, impact, and a fix, not just a raw alert. Output goes
to the terminal in colour, or to a clean JSON / Markdown report you can drop straight
into a client deliverable.

---

## Table of contents

- [What it checks](#what-it-checks)
- [Setup](#setup)
- [Usage](#usage)
  - [Any web app](#any-web-app)
  - [WordPress](#wordpress)
  - [Authenticated scans](#authenticated-scans)
  - [WPScan CVE lookups](#wpscan-cve-lookups)
  - [Stealth / WAF evasion](#stealth--waf-evasion)
- [Flag reference](#flag-reference)
- [Project structure](#project-structure)
- [Sample output](#sample-output)
- [Notes and limitations](#notes-and-limitations)
- [Legal](#legal)

---

## What it checks

**Runs on any web app** (no `--mode` flag needed):

| Check | What it does |
|---|---|
| Security headers | HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, CORS, cookie flags |
| TLS / SSL | Protocol version, weak ciphers, HTTPS enforcement |
| Directory traversal | Fuzzes path-like parameters and URL segments for `../` style traversal |
| IDOR | Numeric ID fuzzing, UUID substitution, common ID parameter names |
| File upload | Discovers upload endpoints, attempts MIME spoofing, double extension, null byte, and polyglot bypasses (active mode only) |
| Auth bypass | Forced browsing, HTTP method switching, role parameter manipulation, JWT none-algorithm attack |
| Injection | Reflected XSS, SQL injection error detection, SSRF via common vectors, open redirect (active mode only) |

**Adds on top with `--mode wordpress`:**

| Check | What it does |
|---|---|
| Recon | Confirms WordPress, fingerprints the core version |
| WAF detection | Identifies Cloudflare, Sucuri, Wordfence, Akamai, Imperva, ModSecurity, SiteLock, and adjusts plugin probing accordingly |
| User enumeration | REST API user list, author archive scanning, xmlrpc and REST API exposure checks |
| Plugin / theme detection | Passive and active detection, cross-referenced against the WPScan Vulnerability Database |
| Misconfigurations | Exposed backup files, `.git` directories, `wp-config.php` variants |
| Application checks | Debug mode leakage, open registration, feed and sitemap disclosure |
| Business logic | `wp-cron.php` exposure, uploads directory listing, backup archive discovery |
| Auth checks (active) | Login lockout / rate limiting, CAPTCHA presence, default credential testing, xmlrpc multicall batching |

---

## Setup

```bash
git clone https://github.com/Cosmicfluke/Wordpress-and-Web-Scanner-active-and-passive-.git
cd Wordpress-and-Web-Scanner-active-and-passive-
pip install -r requirements.txt
```

Requires Python 3.9+.

---

## Usage

### Any web app

Passive scan, writes a Markdown report:

```bash
python main.py -u https://target.com --markdown report.md
```

Active scan (adds injection, upload bypass, auth manipulation, prompts for confirmation first):

```bash
python main.py -u https://target.com --active --markdown report.md
```

### WordPress

Everything above plus the full WordPress-specific layer:

```bash
python main.py -u https://target.com --mode wordpress --markdown report.md
```

Full active WordPress scan:

```bash
python main.py -u https://target.com --mode wordpress --active --markdown report.md
```

### Authenticated scans

Pass a session cookie to unlock checks that need a logged-in context (IDOR across accounts,
privilege escalation, authenticated upload testing):

```bash
python main.py -u https://target.com --cookie "session=abc123; csrf=xyz" --active --markdown report.md
```

### WPScan CVE lookups

Plugin, theme, and core CVE data comes from the WPScan Vulnerability Database. Get a free
token at [wpscan.com/register](https://wpscan.com/register), then either:

```bash
python main.py -u https://target.com --mode wordpress --api-token YOUR_TOKEN --markdown report.md
```

or set it once as an environment variable:

```bash
export WPSCAN_API_TOKEN=your_token_here          # Linux / macOS
$env:WPSCAN_API_TOKEN = "your_token_here"        # Windows PowerShell
```

Without a token, plugin and theme detection still runs, it just won't have CVE data attached.
The free tier has a daily request limit, check WPScan's site for the current cap.

### Stealth / WAF evasion

Randomises request timing and rotates user-agents. WAF evasion mode (cover requests,
shuffled probe order) enables automatically when a firewall is detected, `--stealth`
adds the same behaviour on top for the rest of the scan:

```bash
python main.py -u https://target.com --mode wordpress --stealth --markdown report.md
```

---

## Flag reference

| Flag | Description |
|---|---|
| `-u, --url` | Target URL (required) |
| `--mode` | `web` (default) or `wordpress` |
| `--active` | Enable active checks, prompts for confirmation |
| `--yes` | Skip the active mode confirmation prompt (for scripting) |
| `--stealth` | Random delays + user-agent rotation |
| `--cookie` | Session cookie string for authenticated checks |
| `--active-plugins` | WordPress: actively probe a plugin wordlist |
| `--plugin-wordlist` | WordPress: path to a custom plugin slug wordlist |
| `--json` | Write full results to a JSON file |
| `--markdown` | Write a pentest-ready Markdown report |
| `--api-token` | WPScan API token for CVE lookups |

---

## Project structure

```
main.py                CLI entrypoint

scanner/
  core.py               Orchestrator, mode-aware
  recon.py              WordPress detection + version fingerprint      (WordPress)
  waf.py                WAF detection + evasion trigger                (WordPress)
  wp_enum.py            User enum, xmlrpc, REST API                    (WordPress)
  plugins.py            Plugin detection + CVE lookup, WAF-aware       (WordPress)
  themes.py             Theme detection + CVE lookup                  (WordPress)
  headers.py            Security headers, CORS, cookies                (any web app)
  ssl.py                TLS version + cipher checks                    (any web app)
  misconfig.py          Sensitive file exposure                       (WordPress)
  appcheck.py           Debug mode, open registration, cron            (WordPress)
  infodisclosure.py     Path errors, feeds, REST data leaks            (WordPress)
  bizlogic.py           Uploads, git exposure, backup files            (WordPress)
  authcheck.py          Login protection, active                      (WordPress)
  injection.py          XSS, SQLi, SSRF, open redirect, active         (any web app)
  traversal.py          Directory traversal                            (any web app)
  idor.py               IDOR, numeric / UUID / param fuzzing           (any web app)
  fileupload.py         Upload endpoint discovery + bypass             (any web app)
  authbypass.py         Auth logic flaws, JWT none, mass assignment    (any web app)

reporter/
  report.py             Colour terminal summary + JSON export
  markdown.py           Pentest-ready Markdown report

utils/
  http.py               Shared GET/POST wrapper, central SSL config
  severity.py            Finding structure + severity tiers
  stealth.py             UA rotation, jitter, cover requests
  wpscan_db.py           WPScan Vulnerability Database client
  gowitness.py           Optional screenshot helper
```

---

## Sample output

Terminal (colour-coded by severity):

```
[HTTP Security Headers / CORS / Cookies]
[*] Checking HTTP security headers, CORS, cookies...
  [HIGH] Missing HTTP Strict Transport Security (HSTS)
  [HIGH] Missing Content Security Policy (CSP)
  [MEDIUM] Missing X-Frame-Options Header

[WAF Detection]
[*] Checking for WAF / firewall...
[!] WAF detected: Cloudflare (confidence: high)
    Enabling WAF evasion mode
```

Markdown report findings are structured with severity, description, impact, remediation,
and evidence for each issue, sorted Critical to Info, ready to paste into a client report.

---

## Notes and limitations

- CVE scores in reports come directly from the WPScan Vulnerability Database. Every other
  severity rating uses a Critical / High / Medium / Low / Info tier system, no synthetic
  CVSS scores are generated.
- SSL/TLS certificate verification is intentionally disabled throughout (`utils/http.py`,
  `VERIFY_SSL`). Pentest targets frequently run self-signed or otherwise untrusted certs,
  this is expected behaviour for the tool's use case, not an oversight.
- Behind a WAF like Cloudflare, plugin/theme detection and version fingerprinting can come
  back incomplete if the WAF strips identifying content. Running from the origin server
  directly, or with `--active-plugins`, generally gives more complete results.
- Automated findings should be manually verified before going into a report. This tool
  reduces the grunt work, it doesn't replace judgement.

---

## Legal

Only run this against targets you have explicit written authorisation to test. Active mode
prompts for confirmation before firing, but that confirmation is not a substitute for having
actual permission from the target's owner.
