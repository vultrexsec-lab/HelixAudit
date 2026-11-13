"""robots.txt and security.txt baseline — only real text files, not SPA HTML."""

from urllib.parse import urlparse
import httpx
from .base import BaseTool
from ..context import PipelineContext


def _is_html(text: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    low = (text or "")[:500].lower()
    return "<html" in low or "<!doctype html" in low


class HeadersBaselineTool(BaseTool):
    name = "baseline_files"
    description = "robots.txt and security.txt baseline"
    order = 42

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers = {"User-Agent": "HelixAudit-Pipeline/1.6.2"}
        paths = ["/robots.txt", "/.well-known/security.txt", "/security.txt"]
        async with httpx.AsyncClient(follow_redirects=True, timeout=8.0, verify=False, headers=headers) as client:
            for path in paths:
                url = origin + path
                try:
                    r = await client.get(url)
                    text = r.text or ""
                    ct = r.headers.get("content-type", "")
                    if r.status_code != 200 or len(r.content) == 0:
                        if "security.txt" in path and r.status_code == 404:
                            ctx.add_finding(
                                title="security.txt not found",
                                severity="low",
                                category="Baseline",
                                evidence=f"status={r.status_code}",
                                location=url,
                                remediation="Add /.well-known/security.txt for coordinated disclosure contact.",
                                source_tool=self.name,
                            )
                        continue
                    if _is_html(text, ct):
                        # SPA soft-404 — do not report as security.txt/robots present
                        continue
                    ctx.merge_urls([str(r.url)])
                    title = "security.txt present" if "security.txt" in path else f"Found {path}"
                    ctx.add_finding(
                        title=title,
                        severity="info",
                        category="Baseline",
                        evidence=text[:400],
                        location=str(r.url),
                        remediation="Keep security.txt current with contact and policy links.",
                        source_tool=self.name,
                    )
                except Exception:
                    continue
        ctx.log_tool(self.name, "ok", "baseline checked")
        return ctx
