"""OpenAPI / Swagger surface discovery."""

import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext

PATHS = [
    "/swagger-ui.html", "/swagger/index.html", "/swagger/", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/openapi.json", "/openapi.yaml",
    "/api/swagger.json", "/api/openapi.json",
]


class SwaggerTool(BaseTool):
    name = "swagger_enum"
    description = "Swagger/OpenAPI discovery"
    order = 46

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        found = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=8.0, verify=False) as client:
            for path in PATHS:
                url = origin + path
                try:
                    r = await client.get(url)
                    if r.status_code != 200 or len(r.content) < 20:
                        continue
                    text = (r.text or "")[:500].lower()
                    ct = (r.headers.get("content-type") or "").lower()
                    if "html" in ct and "swagger" not in text and "openapi" not in text:
                        continue
                    if any(x in text for x in ("swagger", "openapi", "paths", "api-docs")) or "json" in ct or "yaml" in ct:
                        found.append(url)
                        ctx.merge_urls([url])
                        ctx.add_finding(
                            title=f"Swagger/OpenAPI surface: {path}",
                            severity="medium",
                            category="VAPT-Enumeration",
                            evidence=f"status={r.status_code} ct={ct} preview={(r.text or '')[:120]}",
                            location=url,
                            remediation="Restrict API docs in production or require authentication.",
                            source_tool=self.name,
                        )
                except Exception:
                    continue
        ctx.artifacts["swagger"] = found
        ctx.log_tool(self.name, "ok", f"found={len(found)}")
        return ctx
