# HelixAudit Professional Roadmap Status (v1.3.0)

## Tier 1
- [x] Finding quality: secret masking, dedupe
- [x] Risk score on findings (`extra_data.risk_score`)
- [x] Executive summary finding + PDF section
- [x] SSL/TLS basic checks (pipeline)
- [x] API endpoint discovery (pipeline)
- [partial] Authenticated scan (foundation exists; continue deepening)
- [partial] Binary tools reliability (install script; depends on host)

## Tier 2
- [x] Scan comparison API: `GET /api/v1/scans/compare?scan_a=&scan_b=`
- [x] Retest API: `POST /api/v1/findings/{id}/retest`
- [partial] White-label PDF (structure ready; branding fields next)
- [partial] Alerts (schedules exist; email/Slack next)

## Tier 3
- [x] API discovery tool
- [x] SSL checks
- [partial] Authz/IDOR surface (path-level only for now)
- [ ] Broader CVE correlation engine

## Tier 4
- [partial] Multi-user auth + schedules
- [partial] Programs/multi-target via projects
- [ ] Full RBAC client portal
- [ ] Jira/Slack integrations

## Explicitly NOT in scope as "unrestricted auto-exploit"
HelixAudit focuses on authorized assessment, detection, reporting, and workflow —
not an autonomous exploitation framework.
