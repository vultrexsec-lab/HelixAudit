"""Live host probe — ProjectDiscovery httpx if present, else pure Python fallback."""

import asyncio
import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext
from ..binary import find_binary


class LiveProbeTool(BaseTool):
    name = "httpx_probe"
    description = "Live host probe (httpx binary or Python fallback)"
    order = 25

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        # Prefer existing httpx tool binary path via import of logic; fallback here
        binary = find_binary("httpx")
        hosts = list(dict.fromkeys(ctx.domains or []))
        if not hosts:
            h = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}").hostname
            hosts = [h] if h else []
        hosts = [h for h in hosts if h][:40]

        if binary:
            # delegate to subprocess similar to httpx_tool
            import json, subprocess

            def _run():
                return subprocess.run(
                    [binary, "-silent", "-status-code", "-title", "-json", "-timeout", "10"],
                    input="\n".join(hosts), capture_output=True, text=True, timeout=60,
                )

            try:
                proc = await asyncio.to_thread(_run)
                live = 0
                for line in (proc.stdout or "").splitlines():
                    try:
                        obj = json.loads(line.strip())
                    except Exception:
                        continue
                    url = obj.get("url") or obj.get("input")
                    if url:
                        live += 1
                        ctx.merge_urls([url])
                ctx.add_finding(
                    title=f"Live host probe: {live}/{len(hosts)} hosts responded",
                    severity="info",
                    category="VAPT-Recon",
                    evidence=f"method=httpx_binary hosts={len(hosts)} live={live}",
                    location=ctx.target,
                    remediation="Focus testing on live hosts.",
                    source_tool=self.name,
                )
                ctx.log_tool(self.name, "ok", f"binary live={live}")
                return ctx
            except Exception as e:
                ctx.log_tool(self.name, "error", f"binary failed: {e}")

        # Python fallback
        live = []
        headers = {"User-Agent": "HelixAudit-LiveProbe/1.8"}
        async with httpx.AsyncClient(follow_redirects=True, timeout=8.0, verify=False, headers=headers) as client:
            for host in hosts:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}/"
                    try:
                        r = await client.get(url)
                        live.append({"url": str(r.url), "status": r.status_code, "length": len(r.content)})
                        ctx.merge_urls([str(r.url)])
                        break
                    except Exception:
                        continue
        ctx.artifacts["live_hosts"] = live
        ctx.add_finding(
            title=f"Live host probe (Python): {len(live)}/{len(hosts)} hosts responded",
            severity="info",
            category="VAPT-Recon",
            evidence=str(live)[:500],
            location=ctx.target,
            remediation="Focus testing on live hosts.",
            source_tool=self.name,
        )
        ctx.log_tool(self.name, "ok", f"python_fallback live={len(live)}")
        return ctx
