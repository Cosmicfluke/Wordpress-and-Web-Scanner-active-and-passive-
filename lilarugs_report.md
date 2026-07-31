# Security Assessment Report

| | |
|---|---|
| **Target** | https://lilarugs.com.au |
| **Date** | 2026-07-31 13:21 |
| **Mode** | WORDPRESS |
| **WordPress** | Unknown |
| **Duration** | 209.8s |
| **Tool** | LOTR |

---

## Executive Summary

This assessment identified **16 findings**.

| Severity | Count |
|---|---|
| 🔴 Critical | 0 |
| 🟠 High | 3 |
| 🟡 Medium | 5 |
| 🔵 Low | 5 |
| ⚪ Info | 3 |

---

## Findings

### 1. 🟠 Missing HTTP Strict Transport Security (HSTS)

| Field | Detail |
|---|---|
| **Severity** | High |
| **Description** | The Strict-Transport-Security header is not set. Browsers will not enforce HTTPS connections. |
| **Impact** | Users may be downgraded to HTTP connections, enabling MitM attacks and cookie theft. |
| **Remediation** | Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload |

**Evidence:**
```
Header absent from response
```

### 2. 🟠 Missing Content Security Policy (CSP)

| Field | Detail |
|---|---|
| **Severity** | High |
| **Description** | No Content-Security-Policy header is present. |
| **Impact** | XSS attacks have no browser-level mitigation. Inline scripts and external resources load without restriction. |
| **Remediation** | Define a strict CSP. Start with: Content-Security-Policy: default-src 'self' |

**Evidence:**
```
Header absent from response
```

### 3. 🟠 No Login Brute-Force Protection Detected

| Field | Detail |
|---|---|
| **Severity** | High |
| **Description** | After 6 failed login attempts, the WordPress login page did not block or throttle requests. |
| **Impact** | An attacker can brute-force login credentials without being locked out. Combined with a known username, this is a direct path to account takeover. |
| **Remediation** | Install a login protection plugin (Wordfence, Limit Login Attempts Reloaded, or similar). Enable lockout after 5 failed attempts. |

**Evidence:**
```
6 consecutive failed logins returned no lockout response
```

### 4. 🟡 Missing X-Frame-Options Header

| Field | Detail |
|---|---|
| **Severity** | Medium |
| **Description** | X-Frame-Options is not set and frame-ancestors is absent from CSP. |
| **Impact** | The site may be embedded in iframes, enabling clickjacking attacks. |
| **Remediation** | Add: X-Frame-Options: SAMEORIGIN or use CSP frame-ancestors 'self' |

**Evidence:**
```
Header absent from response
```

### 5. 🟡 Open Redirect via redirect_to Parameter

| Field | Detail |
|---|---|
| **Severity** | Medium |
| **Description** | The redirect_to parameter accepts arbitrary external URLs without validation. |
| **Impact** | Phishing attacks using legitimate-looking WordPress URLs that redirect to attacker-controlled sites. |
| **Remediation** | Validate redirect_to against a whitelist of allowed internal paths. Reject any value containing an external domain. |

**Evidence:**
```
Redirect to: https://lilarugs.com.au/?redirect_to=https%3A%2F%2Fevil.example.com
```

### 6. 🟡 Sensitive File Exposed: /readme.html

| Field | Detail |
|---|---|
| **Severity** | Medium |
| **Description** | /readme.html returned HTTP 200. |
| **Impact** | May reveal credentials, configuration, or version details. |
| **Remediation** | Remove or restrict access to this file. |

**Evidence:**
```
HTTP 200 at /readme.html
```

### 7. 🟡 Sensitive File Exposed: /license.txt

| Field | Detail |
|---|---|
| **Severity** | Medium |
| **Description** | /license.txt returned HTTP 200. |
| **Impact** | May reveal credentials, configuration, or version details. |
| **Remediation** | Remove or restrict access to this file. |

**Evidence:**
```
HTTP 200 at /license.txt
```

### 8. 🟡 xmlrpc.php system.multicall Batches Multiple Auth Attempts

| Field | Detail |
|---|---|
| **Severity** | Medium |
| **Description** | Sending 3 distinct login attempts wrapped in a single system.multicall request returned 3 individually processed results, confirming the server processes each attempt separately within one HTTP request. |
| **Impact** | An attacker can test hundreds of password guesses in a single HTTP request via multicall, bypassing IP-based or per-request rate limiting that only counts requests, not attempts within a request. |
| **Remediation** | Disable xmlrpc.php entirely if not needed. If required, restrict access to trusted IPs and disable system.multicall specifically via a plugin such as Disable XML-RPC. |

**Evidence:**
```
3 attempts sent, 3 individual results returned
```

### 9. 🔵 Missing Referrer-Policy Header

| Field | Detail |
|---|---|
| **Severity** | Low |
| **Description** | Referrer-Policy is not configured. |
| **Impact** | Full URLs including query strings may be sent in the Referer header to third-party sites, leaking session tokens or sensitive parameters. |
| **Remediation** | Add: Referrer-Policy: strict-origin-when-cross-origin |

**Evidence:**
```
Header absent from response
```

### 10. 🔵 Missing Permissions-Policy Header

| Field | Detail |
|---|---|
| **Severity** | Low |
| **Description** | Permissions-Policy (formerly Feature-Policy) is not set. |
| **Impact** | Browser features like camera, microphone, and geolocation are not restricted for embedded scripts. |
| **Remediation** | Add: Permissions-Policy: geolocation=(), microphone=(), camera=() |

**Evidence:**
```
Header absent from response
```

### 11. 🔵 Server Information Disclosure via Server Header

| Field | Detail |
|---|---|
| **Severity** | Low |
| **Description** | The response includes the Server header revealing server software details. |
| **Impact** | Attackers can fingerprint server software and target known vulnerabilities for that version. |
| **Remediation** | Remove or genericise the Server header at the web server configuration level. |

**Evidence:**
```
Server: cloudflare
```

### 12. 🔵 File Upload Endpoint(s) Discovered

| Field | Detail |
|---|---|
| **Severity** | Low |
| **Description** | Found 2 upload endpoint(s): https://lilarugs.com.au/wp-json/wp/v2/media, https://lilarugs.com.au/wp-admin/async-upload.php |
| **Impact** | Upload endpoints are high-risk surfaces and should be reviewed for bypass techniques. |
| **Remediation** | Validate file types by magic bytes, not extension or MIME header. Store uploads outside the web root. |

**Evidence:**
```
https://lilarugs.com.au/wp-json/wp/v2/media
https://lilarugs.com.au/wp-admin/async-upload.php
```

### 13. 🔵 No CAPTCHA on Login Page

| Field | Detail |
|---|---|
| **Severity** | Low |
| **Description** | No CAPTCHA or bot-detection challenge was found on the WordPress login page. |
| **Impact** | Automated login attempts are not challenged, making brute-force attacks easier. |
| **Remediation** | Add CAPTCHA to the login page using a plugin such as Google reCAPTCHA or hCaptcha. |

**Evidence:**
```
No CAPTCHA pattern detected in wp-login.php HTML
```

### 14. ⚪ XML Sitemap Publicly Accessible

| Field | Detail |
|---|---|
| **Severity** | Info |
| **Description** | An XML sitemap was found at /sitemap.xml. |
| **Impact** | Enumerates all public URLs, posts, categories, and pages. Useful for attacker reconnaissance. |
| **Remediation** | Restrict sitemap access if the site is not intended to be indexed, or review what the sitemap exposes. |

**Evidence:**
```
Sitemap found: https://lilarugs.com.au/sitemap.xml
```

### 15. ⚪ wp-cron.php Externally Accessible (Default Behaviour)

| Field | Detail |
|---|---|
| **Severity** | Info |
| **Description** | wp-cron.php responds to external requests, which is standard WordPress behaviour unless DISABLE_WP_CRON is set. |
| **Impact** | Low — theoretical resource exhaustion via repeated triggering, but requires significant automated abuse to matter in practice. |
| **Remediation** | Optional hardening: set DISABLE_WP_CRON in wp-config.php and use a real system cron job instead. |

**Evidence:**
```
wp-cron.php returned HTTP 200
```

### 16. ⚪ WAF Detected: Cloudflare

| Field | Detail |
|---|---|
| **Severity** | Info |
| **Description** | Cloudflare firewall detected (confidence: high). |
| **Impact** | Active scanning may be blocked or return false negatives. |
| **Remediation** | For tester: use --stealth. For client: verify WAF rules are correctly configured. |

**Evidence:**
```
WAF: Cloudflare | Confidence: high
```


---

*Report generated by LOTR. CVE scores are sourced from the WPScan Vulnerability Database.*
*All other severity ratings use a Critical/High/Medium/Low/Info tier system.*