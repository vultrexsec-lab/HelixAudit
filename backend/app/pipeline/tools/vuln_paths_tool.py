"""Expanded sensitive / VAPT common path checks."""

import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext

PATHS = [
    ("/.env", "high"),
    ("/.git/HEAD", "high"),
    ("/backup.zip", "high"),
    ("/db.sql", "high"),
    ("/phpinfo.php", "medium"),
    ("/server-status", "medium"),
    ("/actuator", "medium"),
    ("/actuator/env", "high"),
    ("/swagger-ui.html", "medium"),
    ("/swagger/index.html", "medium"),
    ("/api-docs", "medium"),
    ("/graphql", "medium"),
    ("/debug", "medium"),
    ("/console", "medium"),
    ("/admin", "medium"),
    ("/administrator", "medium"),
    ("/wp-login.php", "info"),
    ("/wp-json/", "info"),
    ("/.well-known/security.txt", "info"),
    ("/config.json", "medium"),
    ("/package.json", "low"),
]


class VulnPathsTool(BaseTool):
    name = "vuln_paths"
    description = "Common sensitive path enumeration"
    order = 43

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers = {"User-Agent": "HelixAudit-Pipeline/1.6"}
        hits = 0
        async with httpx.AsyncClient(follow_redirects=False, timeout=6.0, verify=False, headers=headers) as client:
            for path, sev in PATHS:
                url = origin + path
                try:
                    r = await client.get(url)
                    if r.status_code in (200, 401, 403) and len(r.content) > 0:
                        hits += 1
                        ctx.merge_urls([url])
                        ctx.add_finding(
                            title=f"Path responds [{r.status_code}]: {path}",
                            severity=sev if r.status_code == 200 else "low",
                            category="VAPT-Vulnerability Assessment",
                            evidence=f"status={r.status_code} length={len(r.content)}",
                            location=url,
                            remediation="Restrict or remove sensitive/debug endpoints from public access.",
                            source_tool=self.name,
                        )
                except Exception:
                    continue
        ctx.log_tool(self.name, "ok", f"hits={hits}")
        return ctx
