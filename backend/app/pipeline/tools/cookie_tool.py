"""Cookie security flags (Secure, HttpOnly, SameSite)."""

import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext


class CookieTool(BaseTool):
    name = "cookie_flags"
    description = "Cookie Secure/HttpOnly/SameSite checks"
    order = 36

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        url = ctx.urls[0] if ctx.urls else ctx.target
        if not url.startswith("http"):
            url = "https://" + url
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
                r = await client.get(url)
            raw = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
            if not raw:
                # httpx may expose set-cookie differently
                sc = r.headers.get("set-cookie")
                raw = [sc] if sc else []
            if not raw:
                ctx.add_finding(
                    title="No Set-Cookie headers on landing page",
                    severity="info",
                    category="VAPT-Configuration",
                    evidence="No cookies observed on initial response",
                    location=url,
                    remediation="Review session cookies on auth responses during authenticated testing.",
                    source_tool=self.name,
                )
                ctx.log_tool(self.name, "ok", "no cookies")
                return ctx
            for c in raw[:15]:
                cl = c.lower()
                issues = []
                if "secure" not in cl and url.startswith("https"):
                    issues.append("Missing Secure")
                if "httponly" not in cl:
                    issues.append("Missing HttpOnly")
                if "samesite" not in cl:
                    issues.append("Missing SameSite")
                name = c.split("=")[0][:40]
                if issues:
                    ctx.add_finding(
                        title=f"Cookie flags weak: {name}",
                        severity="medium" if "Secure" in str(issues) or "HttpOnly" in str(issues) else "low",
                        category="A02:2025 - Security Misconfiguration",
                        evidence=c[:300],
                        location=url,
                        remediation="; ".join(issues) + ". Set Secure; HttpOnly; SameSite=Lax or Strict.",
                        source_tool=self.name,
                    )
            ctx.log_tool(self.name, "ok", f"cookies={len(raw)}")
        except Exception as e:
            ctx.log_tool(self.name, "error", str(e)[:200])
        return ctx
