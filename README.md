# Automated Web Security Auditor (Headers & CORS)

An automated vulnerability auditing tool written in Python that assesses web applications for defensive HTTP security headers and Cross-Origin Resource Sharing (CORS) misconfigurations according to OWASP standards. 

*Developed as a project submission for the IBM SkillsBuild Program.*

## 📌 Features
- **Defensive HTTP Header Compliance:** Checks for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- **Information Disclosure Detection:** Scans for server technology stack leaks (`Server`, `X-Powered-By`) that aid attackers in reconnaissance.
- **CORS Misconfiguration Probing:** Tests origin reflection behavior with untrusted external domains and `null` origins to detect unauthorized data sharing.
- **Reporting:** Provides a colorized terminal interface for quick triage and a structured JSON export for further analysis.

## ⚙️ Requirements
- Python 3.8 or higher
- Dependencies: `requests`, `colorama`

## 🛠️ Setup & Installation
Install the required third-party libraries using pip:
```bash
pip install -r requirements.txt
```

## Sample Output
[*] Dispatching requests to [https://example.com](https://example.com)...

============================================================================
 AUTOMATED WEB SECURITY AUDITOR REPORT
 Target URL: [https://example.com](https://example.com)
============================================================================

[FAIL] [Header Audit] Missing Header: Strict-Transport-Security
       Severity   : High
       Details    : Protects against SSL-stripping and downgrade attacks by enforcing HTTPS.
       Fix        : Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.
----------------------------------------------------------------------------
[FAIL] [Header Audit] Missing Header: Content-Security-Policy
       Severity   : High
       Details    : Restricts resource origins to mitigate Cross-Site Scripting (XSS) and injection attacks.
       Fix        : Define a robust policy: Content-Security-Policy: default-src 'self'; frame-ancestors 'none';
----------------------------------------------------------------------------
[WARN] [Header Audit] Information Disclosure: Server
       Severity   : Low
       Details    : Exposes technical stack banner: 'cloudflare'
       Fix        : Disable or mask the 'Server' header in your web server config.
----------------------------------------------------------------------------
[PASS] [CORS Audit] CORS Enforcement
       Severity   : Info
       Details    : Target did not reflect arbitrary or null origins.
----------------------------------------------------------------------------

[✔] Audit results successfully saved to: scan_results.json
