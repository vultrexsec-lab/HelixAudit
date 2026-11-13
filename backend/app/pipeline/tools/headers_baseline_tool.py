"""Extra baseline: robots.txt / security.txt presence (Phase C small tool)."""

from urllib.parse import urlparse
import httpx
from .base import BaseTool
from ..context import PipelineContext


class HeadersBaselineTool(BaseTool):
    name = "baseline_files"
    description = "robots.txt and security.txt baseline"
    order = 42

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers = {"User-Agent": "HelixAudit-Pipeline/1.5"}
        paths = ["/robots.txt", "/.well-known/security.txt", "/security.txt"]
        async with httpx.AsyncClient(follow_redirects=True, timeout=8.0, verify=False, headers=headers) as client:
            for path in paths:
                url = origin + path
                try:
                    r = await client.get(url)
                    if r.status_code == 200 and len(r.content) > 0:
                        ctx.merge_urls([str(r.url)])
                        sev = "info"
                        title = f"Found {path}"
                        if "security.txt" in path:
                            title = "security.txt present"
                        ctx.add_finding(
                            title=title,
                            severity=sev,
                            category="Baseline",
                            evidence=(r.text or "")[:400],
                            location=str(r.url),
                            remediation="Keep security.txt current with contact and policy links.",
                            source_tool=self.name,
                        )
                    elif "security.txt" in path and r.status_code == 404:
                        ctx.add_finding(
                            title="security.txt not found",
                            severity="low",
                            category="Baseline",
                            evidence=f"status={r.status_code}",
                            location=url,
                            remediation="Add /.well-known/security.txt for coordinated disclosure contact.",
                            source_tool=self.name,
                        )
                except Exception:
                    continue
        ctx.log_tool(self.name, "ok", "baseline checked")
        return ctx
