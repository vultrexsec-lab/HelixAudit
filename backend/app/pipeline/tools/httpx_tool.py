import asyncio
import json
import subprocess
from .base import BaseTool
from ..context import PipelineContext
from ..binary import find_binary


class HttpxTool(BaseTool):
    name = "httpx_probe"
    description = "ProjectDiscovery httpx — probe live hosts/URLs"
    order = 25

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        binary = find_binary("httpx")
        if not binary:
            ctx.log_tool(self.name, "skipped", "httpx binary not found")
            return ctx

        hosts = list(dict.fromkeys(ctx.domains or []))
        if not hosts:
            from urllib.parse import urlparse
            h = urlparse(ctx.target if "://" in ctx.target else f"http://{ctx.target}").netloc or ctx.target
            hosts = [h.split(":")[0]]

        # limit
        hosts = hosts[:40]
        input_data = "\n".join(hosts)

        def _run():
            return subprocess.run(
                [binary, "-silent", "-status-code", "-title", "-tech-detect", "-json", "-timeout", "10"],
                input=input_data, capture_output=True, text=True, timeout=180,
            )

        proc = await asyncio.to_thread(_run)
        live = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                ctx.merge_urls([line])
                continue
            url = obj.get("url") or obj.get("input")
            if url:
                live.append(obj)
                ctx.merge_urls([url])
            techs = obj.get("tech") or obj.get("technologies") or []
            if isinstance(techs, list):
                ctx.technologies = sorted(set(ctx.technologies + techs))
            sc = obj.get("status_code") or obj.get("status-code")
            if sc and int(sc) >= 500:
                ctx.add_finding(
                    title=f"HTTP {sc} on {url}",
                    severity="low",
                    category="Availability",
                    evidence=str(obj)[:400],
                    location=url or "",
                    remediation="Investigate server errors on live hosts.",
                    source_tool=self.name,
                )

        ctx.artifacts["httpx_live"] = live
        ctx.add_finding(
            title=f"httpx probed {len(hosts)} hosts, {len(live)} responses parsed",
            severity="info",
            category="Recon",
            evidence=f"hosts={len(hosts)} live_json={len(live)}",
            location=ctx.target,
            remediation="Focus testing on live hosts only.",
            source_tool=self.name,
        )
        return ctx
