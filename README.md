LOTR: One Scanner to Rule Them All
A security scanner for web applications and WordPress, built for penetration testers.

It runs a full set of checks against any web app, including headers, TLS, IDOR, directory traversal, file upload, authentication bypass and injection. When scanning WordPress, it adds a deeper layer that covers plugin and theme CVEs, user enumeration, xmlrpc abuse and WAF‑aware probing.

Every finding includes a severity rating, impact and recommended fix. Results can be shown in the terminal with color coding or exported as JSON or Markdown for client reporting.

Table of contents
What it checks

Setup

Usage

Any web app

WordPress

Authenticated scans

WPScan CVE lookups

Stealth and WAF evasion

Flag reference

Project structure

Sample output

Notes and limitations

Legal

What it checks
Works on any web app
Check	Description
Security headers	HSTS, CSP, X‑Frame‑Options, Referrer‑Policy, Permissions‑Policy, CORS, cookie flags
TLS and SSL	Protocol version, weak ciphers, HTTPS enforcement
Directory traversal	Fuzzes parameters and URL segments for traversal patterns
IDOR	Numeric ID fuzzing, UUID substitution, common ID parameter names
File upload	Finds upload endpoints and tests MIME spoofing, double extensions, null bytes and polyglot bypasses
Authentication bypass	Forced browsing, HTTP method switching, role manipulation, JWT none‑algorithm checks
Injection	Reflected XSS, SQL error detection, SSRF through common vectors, open redirect


Adds more checks with the WordPress mode
Check	Description
Recon	Confirms WordPress and fingerprints the core version
WAF detection	Identifies Cloudflare, Sucuri, Wordfence, Akamai, Imperva, ModSecurity and SiteLock, then adjusts probing
User enumeration	REST API user list, author archives, xmlrpc and REST exposure
Plugin and theme detection	Passive and active detection with WPScan CVE lookups
Misconfigurations	Exposed backups, git directories, wp‑config variants
Application checks	Debug mode, open registration, feed and sitemap exposure
Business logic	wp‑cron exposure, uploads directory listing, backup archive discovery
Authentication checks	Login lockout, CAPTCHA, default credentials, xmlrpc multicall batching


Setup
bash
git clone https://github.com/Cosmicfluke/Wordpress-and-Web-Scanner-active-and-passive-.git
cd Wordpress-and-Web-Scanner-active-and-passive-
pip install -r requirements.txt
Requires Python 3.9 or newer.

Usage
Any web app
Passive scan with Markdown output:

bash
python main.py -u https://target.com --markdown report.md
Active scan with injection, upload bypass and authentication manipulation:

bash
python main.py -u https://target.com --active --markdown report.md
WordPress
Passive WordPress scan:

bash
python main.py -u https://target.com --mode wordpress --markdown report.md
Full active WordPress scan:

bash
python main.py -u https://target.com --mode wordpress --active --markdown report.md
Authenticated scans
Provide a session cookie to unlock checks that require a logged‑in context:

bash
python main.py -u https://target.com --cookie "session=abc123; csrf=xyz" --active --markdown report.md
WPScan CVE lookups
Get a free token at wpscan.com/register, then run:

bash
python main.py -u https://target.com --mode wordpress --api-token YOUR_TOKEN --markdown report.md
Or set it as an environment variable:

bash
export WPSCAN_API_TOKEN=your_token_here
Without a token, plugin and theme detection still works but CVE data will not be included.

Stealth and WAF evasion
Randomizes timing and rotates user agents. If a WAF is detected, evasion mode activates automatically. You can also enable it manually:

bash
python main.py -u https://target.com --mode wordpress --stealth --markdown report.md
Flag reference
Flag	Description
-u, --url	Target URL
--mode	web or wordpress
--active	Enable active checks
--yes	Skip active mode confirmation
--stealth	Random delays and user‑agent rotation
--cookie	Session cookie string
--active-plugins	Actively probe plugin wordlist
--plugin-wordlist	Custom plugin slug wordlist
--json	Export results to JSON
--markdown	Export results to Markdown
--api-token	WPScan API token


Project structure
Code
main.py                CLI entrypoint

scanner/
  core.py              Orchestrator
  recon.py             WordPress detection and version fingerprint
  waf.py               WAF detection and evasion
  wp_enum.py           User enumeration and API exposure
  plugins.py           Plugin detection and CVE lookup
  themes.py            Theme detection and CVE lookup
  headers.py           Security headers and cookies
  ssl.py               TLS checks
  misconfig.py         Sensitive file exposure
  appcheck.py          Debug mode and registration checks
  infodisclosure.py    Path errors and REST leaks
  bizlogic.py          Uploads, git exposure, backups
  authcheck.py         Login protection checks
  injection.py         XSS, SQLi, SSRF and redirects
  traversal.py         Directory traversal
  idor.py              IDOR fuzzing
  fileupload.py        Upload discovery and bypass testing
  authbypass.py        Authentication logic flaws

reporter/
  report.py            Terminal summary and JSON export
  markdown.py          Markdown report generator

utils/
  http.py              Shared HTTP wrapper
  severity.py          Severity tiers
  stealth.py           User‑agent rotation and jitter
  wpscan_db.py         WPScan client
  gowitness.py         Screenshot helper
Sample output
Code
[HTTP Security Headers / CORS / Cookies]
[*] Checking HTTP security headers, CORS, cookies...
  [HIGH] Missing HTTP Strict Transport Security
  [HIGH] Missing Content Security Policy
  [MEDIUM] Missing X‑Frame‑Options

[WAF Detection]
[*] Checking for WAF or firewall...
[!] WAF detected: Cloudflare (confidence: high)
    Enabling WAF evasion mode
Markdown reports include severity, description, impact, remediation and evidence for each finding.

Notes and limitations
CVE scores come directly from the WPScan database. Other severities use a simple tier system.

SSL certificate verification is disabled intentionally because pentest targets often use self‑signed certificates.

WAFs can block plugin and theme fingerprinting. Running from the origin or using active plugin probing usually helps.

Automated findings should always be manually verified before being included in a report.

Legal
Only scan systems you have explicit permission to test. Active mode asks for confirmation, but that confirmation does not replace proper authorisation.

Table of contents
What it checks

Setup

Usage

Any web app

WordPress

Authenticated scans

WPScan CVE lookups

Stealth and WAF evasion

Flag reference

Project structure

Sample output

Notes and limitations

Legal

What it checks
Works on any web app
Check	Description
Security headers	HSTS, CSP, X‑Frame‑Options, Referrer‑Policy, Permissions‑Policy, CORS, cookie flags
TLS and SSL	Protocol version, weak ciphers, HTTPS enforcement
Directory traversal	Fuzzes parameters and URL segments for traversal patterns
IDOR	Numeric ID fuzzing, UUID substitution, common ID parameter names
File upload	Finds upload endpoints and tests MIME spoofing, double extensions, null bytes and polyglot bypasses
Authentication bypass	Forced browsing, HTTP method switching, role manipulation, JWT none‑algorithm checks
Injection	Reflected XSS, SQL error detection, SSRF through common vectors, open redirect


Adds more checks with the WordPress mode
Check	Description
Recon	Confirms WordPress and fingerprints the core version
WAF detection	Identifies Cloudflare, Sucuri, Wordfence, Akamai, Imperva, ModSecurity and SiteLock, then adjusts probing
User enumeration	REST API user list, author archives, xmlrpc and REST exposure
Plugin and theme detection	Passive and active detection with WPScan CVE lookups
Misconfigurations	Exposed backups, git directories, wp‑config variants
Application checks	Debug mode, open registration, feed and sitemap exposure
Business logic	wp‑cron exposure, uploads directory listing, backup archive discovery
Authentication checks	Login lockout, CAPTCHA, default credentials, xmlrpc multicall batching


Setup
bash
git clone https://github.com/Cosmicfluke/Wordpress-and-Web-Scanner-active-and-passive-.git
cd Wordpress-and-Web-Scanner-active-and-passive-
pip install -r requirements.txt
Requires Python 3.9 or newer.

Usage
Any web app
Passive scan with Markdown output:

bash
python main.py -u https://target.com --markdown report.md
Active scan with injection, upload bypass and authentication manipulation:

bash
python main.py -u https://target.com --active --markdown report.md
WordPress
Passive WordPress scan:

bash
python main.py -u https://target.com --mode wordpress --markdown report.md
Full active WordPress scan:

bash
python main.py -u https://target.com --mode wordpress --active --markdown report.md
Authenticated scans
Provide a session cookie to unlock checks that require a logged‑in context:

bash
python main.py -u https://target.com --cookie "session=abc123; csrf=xyz" --active --markdown report.md
WPScan CVE lookups
Get a free token at wpscan.com/register, then run:

bash
python main.py -u https://target.com --mode wordpress --api-token YOUR_TOKEN --markdown report.md
Or set it as an environment variable:

bash
export WPSCAN_API_TOKEN=your_token_here
Without a token, plugin and theme detection still works but CVE data will not be included.

Stealth and WAF evasion
Randomizes timing and rotates user agents. If a WAF is detected, evasion mode activates automatically. You can also enable it manually:

bash
python main.py -u https://target.com --mode wordpress --stealth --markdown report.md
Flag reference
Flag	Description
-u, --url	Target URL
--mode	web or wordpress
--active	Enable active checks
--yes	Skip active mode confirmation
--stealth	Random delays and user‑agent rotation
--cookie	Session cookie string
--active-plugins	Actively probe plugin wordlist
--plugin-wordlist	Custom plugin slug wordlist
--json	Export results to JSON
--markdown	Export results to Markdown
--api-token	WPScan API token


Project structure
Code
main.py                CLI entrypoint

scanner/
  core.py              Orchestrator
  recon.py             WordPress detection and version fingerprint
  waf.py               WAF detection and evasion
  wp_enum.py           User enumeration and API exposure
  plugins.py           Plugin detection and CVE lookup
  themes.py            Theme detection and CVE lookup
  headers.py           Security headers and cookies
  ssl.py               TLS checks
  misconfig.py         Sensitive file exposure
  appcheck.py          Debug mode and registration checks
  infodisclosure.py    Path errors and REST leaks
  bizlogic.py          Uploads, git exposure, backups
  authcheck.py         Login protection checks
  injection.py         XSS, SQLi, SSRF and redirects
  traversal.py         Directory traversal
  idor.py              IDOR fuzzing
  fileupload.py        Upload discovery and bypass testing
  authbypass.py        Authentication logic flaws

reporter/
  report.py            Terminal summary and JSON export
  markdown.py          Markdown report generator

utils/
  http.py              Shared HTTP wrapper
  severity.py          Severity tiers
  stealth.py           User‑agent rotation and jitter
  wpscan_db.py         WPScan client
  gowitness.py         Screenshot helper
Sample output
Code
[HTTP Security Headers / CORS / Cookies]
[*] Checking HTTP security headers, CORS, cookies...
  [HIGH] Missing HTTP Strict Transport Security
  [HIGH] Missing Content Security Policy
  [MEDIUM] Missing X‑Frame‑Options

[WAF Detection]
[*] Checking for WAF or firewall...
[!] WAF detected: Cloudflare (confidence: high)
    Enabling WAF evasion mode
Markdown reports include severity, description, impact, remediation and evidence for each finding.

Notes and limitations
CVE scores come directly from the WPScan database. Other severities use a simple tier system.

SSL certificate verification is disabled intentionally because pentest targets often use self‑signed certificates.

WAFs can block plugin and theme fingerprinting. Running from the origin or using active plugin probing usually helps.

Automated findings should always be manually verified before being included in a report.

Legal
Only scan systems you have explicit permission to test. Active mode asks for confirmation, but that confirmation does not replace proper authorisation.
