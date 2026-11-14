# HelixAudit Tiers A / B / C

## Tier A (automated core) — implemented
Subdomain, DNS email, ports, live probe (httpx or Python), WAF, TLS, HTTPS redirect, tech, cookies, crawl, sitemap, paths, baseline, secrets, headers/OWASP, active, injection probes, nuclei (if binary), auth deep (optional), report + matrix.

## Tier B (extended surface) — implemented
Controlled dir brute, Swagger/OpenAPI, JS endpoint + cloud bucket URLs, upload form surface.

## Tier C (manual expert) — checklist in report
Business logic, complex IDOR/roles, chained exploits, SSO edge cases, upload→RCE chains, rate-limit/OTP, phishing, internal pivot — **not auto-exploited**.

## Render build
```
pip install -r requirements.txt && bash scripts/install_tools.sh
```
