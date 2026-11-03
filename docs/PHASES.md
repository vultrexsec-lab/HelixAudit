# HelixAudit

## v1.0.0-rc1

### Implemented
- Multi-user register/login (JWT)
- Scheduled scans (interval-based, in-process worker)
- Background scan execution
- SQLi/XSS *detection probes* (not full exploit engine)
- PDF reports (reportlab)
- HTML + JSON export
- Authenticated scanning foundation
- Dashboard UI with projects/history
- Finding lifecycle

### Honest limitations
- Not SQLMap/Burp-level exploitation
- Scheduler is in-process (not distributed Celery/Redis)
- Screenshots not included (Playwright too heavy for free tier)
- Auth on API is optional for scan routes (backward compatible)
