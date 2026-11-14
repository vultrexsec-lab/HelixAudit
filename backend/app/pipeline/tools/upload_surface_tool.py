"""Detect file upload forms (surface only)."""

import re
import httpx
from urllib.parse import urljoin, urlparse
from .base import BaseTool
from ..context import PipelineContext


class UploadSurfaceTool(BaseTool):
    name = "upload_surface"
    description = "File upload form surface detection"
    order = 48

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
            for url in list(dict.fromkeys((ctx.urls or [origin])[:8])):
                try:
                    r = await client.get(url)
                    html = r.text or ""
                except Exception:
                    continue
                if re.search(r'(?i)enctype\s*=\s*["\']multipart/form-data["\']', html) or re.search(
                    r'(?i)<input[^>]+type=["\']file["\']', html
                ):
                    found.append(str(r.url))
        if found:
            ctx.add_finding(
                title=f"File upload form surface ({len(found)})",
                severity="medium",
                category="VAPT-Vulnerability Assessment",
                evidence=", ".join(found[:10]),
                location=origin,
                remediation="Restrict upload types, size, auth; store outside webroot; scan content.",
                source_tool=self.name,
            )
        else:
            ctx.add_finding(
                title="No file upload forms detected on crawled pages",
                severity="info",
                category="VAPT-Vulnerability Assessment",
                evidence="No multipart/file inputs in sampled pages",
                location=origin,
                remediation="Retest authenticated areas where uploads may exist.",
                source_tool=self.name,
            )
        ctx.log_tool(self.name, "ok", f"upload_forms={len(found)}")
        return ctx
