from .base import BaseTool
from ..context import PipelineContext
from ...scanners.portscan import run_nmap_scan
from urllib.parse import urlparse


class PortTool(BaseTool):
    name = "port_scan"
    description = "Port & service scan"
    order = 20

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        host = urlparse(ctx.target if "://" in ctx.target else f"http://{ctx.target}").netloc or ctx.target
        host = host.split(":")[0].split("/")[0]
        ports = run_nmap_scan(host)
        ctx.ports.extend(ports)
        for p in ports:
            if p.get("ip"):
                if p["ip"] not in ctx.ips:
                    ctx.ips.append(p["ip"])
            if p.get("port") in [21, 22, 23, 3389, 5900, 3306, 445]:
                ctx.add_finding(
                    title=f"Open port {p['port']} ({p.get('service', '?')})",
                    severity="medium" if p["port"] in [21, 23, 3389, 445] else "info",
                    category="Open Port",
                    evidence=str(p),
                    location=f"{p.get('ip', host)}:{p['port']}",
                    remediation="Restrict public access if not required.",
                    source_tool=self.name,
                )
        ctx.artifacts["ports"] = ports
        return ctx
