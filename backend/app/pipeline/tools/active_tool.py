from .base import BaseTool
from ..context import PipelineContext
from ...scanners.active_checks import run_active_checks
import httpx


class ActiveTool(BaseTool):
    name = "active_checks"
    description = "CORS, methods, sensitive files"
    order = 70

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        url = ctx.urls[0] if ctx.urls else ctx.target
        headers = {"User-Agent": "HelixAudit-Pipeline/1.1"}
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers) as client:
            findings = await run_active_checks(client, url)
            for f in findings:
                ctx.add_finding(
                    title=f.get("title", "Active check"),
                    severity=f.get("severity", "info"),
                    category=f.get("category", "Active"),
                    evidence=f.get("evidence", ""),
                    location=f.get("location") or url,
                    remediation=f.get("remediation", ""),
                    source_tool=self.name,
                )
        return ctx
