import asyncio
import subprocess
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext
from ..binary import find_binary


class SubfinderTool(BaseTool):
    name = "subfinder"
    description = "ProjectDiscovery subfinder — passive subdomain discovery"
    order = 8  # before basic subdomain enum

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        binary = find_binary("subfinder")
        if not binary:
            ctx.log_tool(self.name, "skipped", "subfinder binary not found")
            return ctx

        host = urlparse(ctx.target if "://" in ctx.target else f"http://{ctx.target}").netloc or ctx.target
        host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]

        def _run():
            return subprocess.run(
                [binary, "-d", host, "-silent", "-timeout", "30"],
                capture_output=True, text=True, timeout=120,
            )

        proc = await asyncio.to_thread(_run)
        subs = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
        ctx.domains = sorted(set(ctx.domains + subs + [host]))
        ctx.merge_urls([f"https://{s}" for s in subs])
        ctx.artifacts["subfinder"] = subs
        if subs:
            ctx.add_finding(
                title=f"Subfinder found {len(subs)} subdomain(s)",
                severity="info",
                category="Recon",
                evidence=", ".join(subs[:30]),
                location=host,
                remediation="Review exposed subdomains; remove unused hosts.",
                source_tool=self.name,
            )
        return ctx
