from .base import BaseTool
from ..context import PipelineContext
from ...scanners.crawler import fetch_and_analyze
from ...scanners.secrets import find_secrets_in_text
import httpx


class SecretsTool(BaseTool):
    name = "secrets_scan"
    description = "Secrets & sensitive data detection"
    order = 50

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        urls = (ctx.urls[:8] if ctx.urls else [ctx.target])
        headers = {"User-Agent": "HelixAudit-Pipeline/1.1"}
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers) as client:
            for url in urls:
                data = await fetch_and_analyze(client, url)
                if not data:
                    continue
                if data.get("headers") and not ctx.headers:
                    ctx.headers.update({k.lower(): v for k, v in data["headers"].items()})
                secrets = find_secrets_in_text(data.get("text") or "", source=url)
                ctx.secrets_raw.extend(secrets)
                for sec in secrets:
                    sev = "critical" if sec.get("confidence", 0) >= 0.8 else "high"
                    ctx.add_finding(
                        title=f"Potential {sec['type']} found",
                        severity=sev,
                        category="Sensitive Data Exposure",
                        evidence=f"{sec.get('evidence')} @ {sec.get('source')}",
                        location=url,
                        remediation="Rotate and remove exposed secrets.",
                        source_tool=self.name,
                    )
        return ctx
