# Burp Suite integration

HelixAudit does **not** embed Burp Suite (PortSwigger desktop product).

## What you get
1. `GET /api/v1/scans/{id}/burp` — JSON package: URLs, scope hosts, issues, instructions
2. `GET /api/v1/scans/{id}/burp/urls.txt` — plain URL list for paste into Burp
3. `POST /api/v1/scans/{id}/burp/push` — optional push if `BURP_API_URL` is set

## Manual workflow
1. Run HelixAudit scan
2. Open **Burp Export** or download `urls.txt`
3. Burp → Target → Scope → add hosts
4. Paste URLs into site map / spider / scanner (authorized only)

## Optional REST API
Run Burp with a REST API extension, then set:
```
BURP_API_URL=http://127.0.0.1:8090
BURP_API_KEY=
```
API paths differ by extension; push is best-effort.

## Legal
Only use Burp Scanner on systems you are authorized to test.
