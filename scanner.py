#!/usr/bin/env python3
"""
Automated Web Security Auditor (Headers & CORS)
Analyzes target web servers for defensive HTTP headers and CORS misconfigurations.
"""

import argparse
import json
import sys
import requests
from colorama import Fore, Style, init

init(autoreset=True)

SECURE_HEADERS_POLICY = {
    "Strict-Transport-Security": {
        "severity": "High",
        "desc": "Protects against SSL-stripping and downgrade attacks by enforcing HTTPS.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
    },
    "Content-Security-Policy": {
        "severity": "High",
        "desc": "Restricts resource origins to mitigate Cross-Site Scripting (XSS) and injection attacks.",
        "fix": "Define a robust policy: Content-Security-Policy: default-src 'self'; frame-ancestors 'none';"
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "desc": "Mitigates Clickjacking by controlling whether the site can be rendered in a frame/iframe.",
        "fix": "Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "desc": "Prevents MIME-type sniffing vulnerabilities in browsers.",
        "fix": "Set 'X-Content-Type-Options: nosniff'."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "desc": "Protects sensitive URL query parameters from cross-origin leakage.",
        "fix": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "desc": "Restricts access to browser APIs (camera, microphone, geolocation).",
        "fix": "Define allowed features: Permissions-Policy: geolocation=(), camera=(), microphone=()."
    }
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]


def normalize_target_url(raw_url: str) -> str:
    if not raw_url.startswith(("http://", "https://")):
        return f"https://{raw_url}"
    return raw_url


def audit_security_headers(response_headers: dict) -> list:
    findings = []
    normalized_headers = {k.lower(): v for k, v in response_headers.items()}

    for header_name, meta in SECURE_HEADERS_POLICY.items():
        lowered = header_name.lower()
        if lowered not in normalized_headers:
            findings.append({
                "module": "Header Audit",
                "finding": f"Missing Header: {header_name}",
                "severity": meta["severity"],
                "status": "FAIL",
                "details": meta["desc"],
                "recommendation": meta["fix"]
            })
        else:
            findings.append({
                "module": "Header Audit",
                "finding": f"Header Present: {header_name}",
                "severity": "Info",
                "status": "PASS",
                "details": f"Configured value: {normalized_headers[lowered]}",
                "recommendation": "Security control active."
            })

    for leak in INFO_LEAK_HEADERS:
        if leak.lower() in normalized_headers:
            findings.append({
                "module": "Header Audit",
                "finding": f"Information Disclosure: {leak}",
                "severity": "Low",
                "status": "WARN",
                "details": f"Exposes technical stack banner: '{normalized_headers[leak.lower()]}'",
                "recommendation": f"Disable or mask the '{leak}' header in your web server config."
            })

    return findings


def audit_cors_configuration(target_url: str, timeout: int = 8) -> list:
    findings = []
    probes = [
        ("https://attacker-origin.com", "Arbitrary External Domain"),
        ("null", "Null Origin (sandboxed iframe)")
    ]

    base_headers = {"User-Agent": "SecurityAuditorBot/1.0"}

    for origin_val, origin_type in probes:
        probe_headers = base_headers.copy()
        probe_headers["Origin"] = origin_val

        try:
            resp = requests.get(target_url, headers=probe_headers, timeout=timeout, allow_redirects=True)
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")

            if acao:
                if acao == origin_val and acac and acac.lower() == "true":
                    findings.append({
                        "module": "CORS Audit",
                        "finding": f"Critical Origin Reflection ({origin_type})",
                        "severity": "High",
                        "status": "FAIL",
                        "details": f"Target dynamically reflects '{origin_val}' with 'Access-Control-Allow-Credentials: true'.",
                        "recommendation": "Validate Origin against an explicit server-side whitelist before reflecting."
                    })
                elif acao == "null":
                    findings.append({
                        "module": "CORS Audit",
                        "finding": "Insecure Null Origin Trusted",
                        "severity": "Medium",
                        "status": "WARN",
                        "details": "Server trusts 'null' origin, enabling attacks through sandboxed iframes.",
                        "recommendation": "Remove 'null' from permitted origins."
                    })
                elif acao == "*" and acac and acac.lower() == "true":
                    findings.append({
                        "module": "CORS Audit",
                        "finding": "Invalid CORS Combination (Wildcard + Credentials)",
                        "severity": "High",
                        "status": "FAIL",
                        "details": "Server attempts wildcard origin '*' alongside credentials.",
                        "recommendation": "Specify allowed origins explicitly."
                    })
                elif acao == origin_val:
                    findings.append({
                        "module": "CORS Audit",
                        "finding": f"Permissive Origin Reflection ({origin_type})",
                        "severity": "Low",
                        "status": "WARN",
                        "details": f"Server reflected '{origin_val}' without credentials.",
                        "recommendation": "Ensure public APIs only expose unauthenticated read-only resources."
                    })
        except requests.RequestException as exc:
            findings.append({
                "module": "CORS Audit",
                "finding": f"Probe Connection Error ({origin_type})",
                "severity": "Info",
                "status": "ERROR",
                "details": str(exc),
                "recommendation": "Verify network connectivity to the target."
            })

    if not findings:
        findings.append({
            "module": "CORS Audit",
            "finding": "CORS Enforcement",
            "severity": "Info",
            "status": "PASS",
            "details": "Target did not reflect arbitrary or null origins.",
            "recommendation": "No action needed."
        })

    return findings


def render_terminal_report(target_url: str, findings: list):
    print("\n" + "=" * 76)
    print(f"{Fore.CYAN}{Style.BRIGHT} AUTOMATED WEB SECURITY AUDITOR REPORT{Style.RESET_ALL}")
    print(f" Target URL: {Fore.YELLOW}{target_url}{Style.RESET_ALL}")
    print("=" * 76 + "\n")

    severities = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.BLUE, "Info": Fore.WHITE}
    status_tags = {
        "PASS": f"{Fore.GREEN}[PASS]{Style.RESET_ALL}",
        "FAIL": f"{Fore.RED}[FAIL]{Style.RESET_ALL}",
        "WARN": f"{Fore.YELLOW}[WARN]{Style.RESET_ALL}",
        "ERROR": f"{Fore.MAGENTA}[ERR]{Style.RESET_ALL}"
    }

    for item in findings:
        sev_color = severities.get(item["severity"], Fore.WHITE)
        symbol = status_tags.get(item["status"], "[INFO]")
        print(f"{symbol} [{item['module']}] {Style.BRIGHT}{item['finding']}{Style.RESET_ALL}")
        print(f"       Severity   : {sev_color}{item['severity']}{Style.RESET_ALL}")
        print(f"       Details    : {item['details']}")
        if item["status"] in ["FAIL", "WARN"]:
            print(f"       Fix        : {Fore.CYAN}{item['recommendation']}{Style.RESET_ALL}")
        print("-" * 76)


def export_json_report(findings: list, filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
    print(f"\n{Fore.GREEN}[✔] Audit results successfully saved to: {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Web Security Auditor - Audits HTTP security headers and CORS configurations."
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Optional output JSON report filename")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="Timeout in seconds")
    args = parser.parse_args()

    target = normalize_target_url(args.url)
    print(f"[*] Dispatching requests to {target}...")

    try:
        resp = requests.get(target, timeout=args.timeout, headers={"User-Agent": "SecurityAuditorBot/1.0"})
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Failed to connect to target: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    header_results = audit_security_headers(resp.headers)
    cors_results = audit_cors_configuration(target, timeout=args.timeout)
    total_findings = header_results + cors_results

    render_terminal_report(target, total_findings)

    if args.output:
        export_json_report(total_findings, args.output)


if __name__ == "__main__":
    main()