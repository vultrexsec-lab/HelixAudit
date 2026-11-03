from .base import BaseTool
from ..context import PipelineContext
from ...scanners.injection import run_injection_detection
import httpx


class InjectionTool(BaseTool):
    name = "injection_detect"
    description = "SQLi/XSS detection probes (uses discovered URLs)"
    order = 80

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        # Feed richer URL list from previous tools
        targets = ctx.urls[:5] if ctx.urls else [ctx.target]
        headers = {"User-Agent": "HelixAudit-Pipeline/1.1"}
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers) as client:
            for url in targets:
                findings = await run_injection_detection(client, url)
                for f in findings:
                    ctx.add_finding(
                        title=f.get("title", "Injection"),
                        severity=f.get("severity", "medium"),
                        category=f.get("category", "Injection"),
                        evidence=f.get("evidence", ""),
                        location=f.get("location") or url,
                        remediation=f.get("remediation", ""),
                        source_tool=self.name,
                    )
        return ctx
