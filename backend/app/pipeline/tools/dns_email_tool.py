"""DNS / email security baseline (SPF, DMARC, MX)."""

import socket
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext

try:
    import dns.resolver  # type: ignore
    HAS_DNS = True
except Exception:
    HAS_DNS = False


class DnsEmailTool(BaseTool):
    name = "dns_email_security"
    description = "MX/SPF/DMARC DNS security checks"
    order = 12
    vapt_phase = "Reconnaissance"

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        host = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}").hostname or ctx.target
        host = host.replace("www.", "")
        if not HAS_DNS:
            # minimal fallback without dnspython
            try:
                socket.gethostbyname(host)
                ctx.add_finding(
                    title=f"DNS resolves for {host}",
                    severity="info",
                    category="VAPT-Recon",
                    evidence="A record resolution OK (dnspython not installed for SPF/DMARC)",
                    location=host,
                    remediation="Install dnspython on server for full SPF/DMARC checks.",
                    source_tool=self.name,
                )
            except Exception as e:
                ctx.add_finding(
                    title=f"DNS resolution failed for {host}",
                    severity="medium",
                    category="VAPT-Recon",
                    evidence=str(e)[:200],
                    location=host,
                    remediation="Verify DNS configuration.",
                    source_tool=self.name,
                )
            ctx.log_tool(self.name, "ok", "basic dns")
            return ctx

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5

        def txt(name):
            try:
                ans = resolver.resolve(name, "TXT")
                return [b"".join(r.strings).decode(errors="ignore") if hasattr(r, "strings") else str(r) for r in ans]
            except Exception:
                return []

        try:
            mx = []
            try:
                mx = [str(r.exchange).rstrip(".") for r in resolver.resolve(host, "MX")]
            except Exception:
                pass
            spf = [t for t in txt(host) if "v=spf1" in t.lower()]
            dmarc = txt(f"_dmarc.{host}")
            ctx.artifacts["dns"] = {"mx": mx, "spf": spf, "dmarc": dmarc}

            if not mx:
                ctx.add_finding(
                    title="No MX records found",
                    severity="info",
                    category="VAPT-Recon",
                    evidence=f"host={host}",
                    location=host,
                    remediation="Expected if domain does not receive email.",
                    source_tool=self.name,
                )
            if not spf:
                ctx.add_finding(
                    title="SPF record missing",
                    severity="medium",
                    category="VAPT-Email Security",
                    evidence=f"No v=spf1 TXT on {host}",
                    location=host,
                    remediation="Publish an SPF TXT record to reduce spoofing.",
                    source_tool=self.name,
                )
            else:
                ctx.add_finding(
                    title="SPF record present",
                    severity="info",
                    category="VAPT-Email Security",
                    evidence="; ".join(spf)[:400],
                    location=host,
                    remediation="Review SPF for ~all/+all weaknesses.",
                    source_tool=self.name,
                )
            if not dmarc:
                ctx.add_finding(
                    title="DMARC record missing",
                    severity="medium",
                    category="VAPT-Email Security",
                    evidence=f"_dmarc.{host} has no TXT",
                    location=host,
                    remediation="Publish DMARC policy (p=quarantine/reject as appropriate).",
                    source_tool=self.name,
                )
            else:
                ctx.add_finding(
                    title="DMARC record present",
                    severity="info",
                    category="VAPT-Email Security",
                    evidence="; ".join(dmarc)[:400],
                    location=f"_dmarc.{host}",
                    remediation="Ensure policy is enforced (not only none) when ready.",
                    source_tool=self.name,
                )
            ctx.log_tool(self.name, "ok", "dns email checked")
        except Exception as e:
            ctx.log_tool(self.name, "error", str(e)[:200])
        return ctx
