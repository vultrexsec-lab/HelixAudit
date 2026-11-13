"""Basic TLS/SSL surface checks using stdlib."""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext


class SslTool(BaseTool):
    name = "ssl_check"
    description = "TLS certificate and HTTPS basic checks"
    order = 28

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        host = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}").hostname
        if not host:
            ctx.log_tool(self.name, "skipped", "no host")
            return ctx
        try:
            ctx_ssl = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
            not_after = cert.get("notAfter")
            # e.g. 'Jun  1 12:00:00 2027 GMT'
            days_left = None
            if not_after:
                try:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                except Exception:
                    pass
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            ctx.artifacts["ssl"] = {
                "version": version,
                "not_after": not_after,
                "days_left": days_left,
                "subject": subject,
                "issuer": issuer,
            }
            if days_left is not None and days_left < 30:
                ctx.add_finding(
                    title=f"TLS certificate expires in {days_left} days",
                    severity="high" if days_left < 7 else "medium",
                    category="A02:2025 - Security Misconfiguration",
                    evidence=f"notAfter={not_after} issuer={issuer}",
                    location=f"https://{host}",
                    remediation="Renew certificate before expiry.",
                    source_tool=self.name,
                )
            if version and version in ("TLSv1", "TLSv1.1", "SSLv3"):
                ctx.add_finding(
                    title=f"Weak TLS protocol in use: {version}",
                    severity="medium",
                    category="A02:2025 - Security Misconfiguration",
                    evidence=f"protocol={version}",
                    location=f"https://{host}",
                    remediation="Disable TLS 1.0/1.1; require TLS 1.2+.",
                    source_tool=self.name,
                )
            ctx.add_finding(
                title=f"TLS OK ({version})",
                severity="info",
                category="SSL/TLS",
                evidence=f"version={version} days_left={days_left} subject={subject}",
                location=f"https://{host}",
                remediation="Keep certificates monitored and auto-renewed.",
                source_tool=self.name,
            )
            ctx.log_tool(self.name, "ok", f"version={version}")
        except Exception as e:
            ctx.log_tool(self.name, "error", str(e)[:200])
            ctx.add_finding(
                title="TLS/HTTPS check failed",
                severity="medium",
                category="SSL/TLS",
                evidence=str(e)[:300],
                location=f"https://{host}",
                remediation="Verify HTTPS is correctly configured and reachable.",
                source_tool=self.name,
            )
        return ctx
