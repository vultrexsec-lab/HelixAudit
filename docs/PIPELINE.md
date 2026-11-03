# HelixAudit Tool Pipeline

## Logic
1. Tools run **in order** (order field).
2. Each tool receives full **PipelineContext** (domains, urls, ports, pages, findings…).
3. Tool enriches context → next tool gets richer data.
4. Failures are logged; chain continues.
5. Final context → DB assets/findings → HTML/PDF/JSON report.

## Current chain
1. subdomain_enum
2. port_scan
3. tech_detect
4. crawler
5. secrets_scan
6. owasp_surface
7. active_checks
8. injection_detect
(+ optional authenticated stage)

## Adding a new open-source tool
1. Create `backend/app/pipeline/tools/my_tool.py` implementing `BaseTool`.
2. Register in `default_tool_chain()` in `engine.py`.
3. Read prior context (`ctx.urls`, `ctx.domains`…), write findings via `ctx.add_finding(...)`.

This scales from 8 tools toward dozens without rewriting the core.
