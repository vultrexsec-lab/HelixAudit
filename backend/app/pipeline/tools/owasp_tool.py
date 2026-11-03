from .base import BaseTool
from ..context import PipelineContext
from ...scanners.owasp_checks import run_full_owasp_checks
import httpx


class OwaspTool(BaseTool):
    name = "owasp_surface"
    description = "OWASP surface checks using prior crawl data"
    order = 60

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        url = ctx.urls[0] if ctx.urls else ctx.target
        headers = {"User-Agent": "HelixAudit-Pipeline/1.1"}
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers) as client:
            # body from first page if any
            body = ""
            if ctx.pages:
                body = str(ctx.pages[0].get("title") or "")
            findings = await run_full_owasp_checks(
                client, url, ctx.headers, body, ctx.paths
            )
            for f in findings:
                ctx.add_finding(
                    title=f.get("title", "OWASP finding"),
                    severity=f.get("severity", "info"),
                    category=f.get("category", "OWASP"),
                    evidence=f.get("evidence", ""),
                    location=f.get("location") or url,
                    remediation=f.get("remediation", ""),
                    source_tool=self.name,
                )
        return ctx
