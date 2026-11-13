"""Discover API-like endpoints; filter SPA soft-404 responses."""

import hashlib
import re
from urllib.parse import urljoin, urlparse
from .base import BaseTool
from ..context import PipelineContext
import httpx

API_PATH_RE = re.compile(r"(?i)(\/api\/[a-z0-9_\-\/{}]+|\/v[12]\/[a-z0-9_\-\/]+|\/graphql)")
JS_URL_RE = re.compile(r"""(?i)https?://[^\s"'<>]+|/[^"'\\s]{3,}\.(?:js)(?:\?[^\s"'<>]*)?""")


def _h(content: bytes) -> str:
    return hashlib.sha256(content[:8000]).hexdigest()


class ApiDiscoverTool(BaseTool):
    name = "api_discover"
    description = "API path hints from pages and linked scripts"
    order = 45

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        found = set()
        base = ctx.urls[0] if ctx.urls else ctx.target
        parsed = urlparse(base if "://" in base else f"https://{base}")
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for u in ctx.urls + [p.get("url") for p in ctx.paths if p.get("url")]:
            if not u:
                continue
            for m in API_PATH_RE.findall(u):
                found.add(urljoin(origin, m) if m.startswith("/") else m)

        headers = {"User-Agent": "HelixAudit-Pipeline/1.6.2"}
        baseline = set()
        async with httpx.AsyncClient(follow_redirects=True, timeout=8.0, verify=False, headers=headers) as client:
            try:
                home = await client.get(origin + "/")
                baseline.add(_h(home.content))
            except Exception:
                pass
            try:
                rnd = await client.get(origin + "/helixaudit-not-exist-api-4242")
                if rnd.status_code == 200:
                    baseline.add(_h(rnd.content))
            except Exception:
                pass

            for url in list(dict.fromkeys(ctx.urls[:5] or [base])):
                try:
                    r = await client.get(url)
                    text = r.text or ""
                except Exception:
                    continue
                for m in API_PATH_RE.findall(text):
                    found.add(urljoin(str(r.url), m) if m.startswith("/") else m)
                for js in JS_URL_RE.findall(text)[:3]:
                    js_url = urljoin(str(r.url), js)
                    try:
                        jr = await client.get(js_url)
                        for m in API_PATH_RE.findall(jr.text or ""):
                            found.add(urljoin(origin, m) if m.startswith("/") else m)
                    except Exception:
                        continue

            apis = sorted(found)[:40]
            ctx.artifacts["api_endpoints"] = apis
            ctx.merge_urls(apis)
            if apis:
                ctx.add_finding(
                    title=f"API endpoint candidates discovered ({len(apis)})",
                    severity="info",
                    category="API Discovery",
                    evidence=", ".join(apis[:20]),
                    location=origin,
                    remediation="Review auth on API routes; ensure none are publicly exposing sensitive data.",
                    source_tool=self.name,
                )
                for a in apis[:10]:
                    try:
                        r = await client.get(a, follow_redirects=False)
                        if r.status_code != 200 or len(r.content) == 0:
                            continue
                        # soft-404 / same as homepage shell
                        if _h(r.content) in baseline and len(r.content) > 500:
                            continue
                        ct = (r.headers.get("content-type") or "").lower()
                        text = ""
                        try:
                            text = r.content.decode("utf-8", errors="ignore")[:500].lower()
                        except Exception:
                            pass
                        # HTML shell is not an API response
                        if "text/html" in ct or "<html" in text:
                            continue
                        ctx.add_finding(
                            title=f"API candidate responds 200: {a}",
                            severity="medium",
                            category="A01:2025 - Broken Access Control (Surface)",
                            evidence=f"status={r.status_code} length={len(r.content)} content-type={ct}",
                            location=a,
                            remediation="Confirm authentication/authorization required for this API.",
                            source_tool=self.name,
                        )
                    except Exception:
                        continue
        ctx.log_tool(self.name, "ok", f"apis={len(found)}")
        return ctx
