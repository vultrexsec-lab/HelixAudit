import asyncio
import json
import subprocess
import tempfile
import os
from .base import BaseTool
from ..context import PipelineContext
from ..binary import find_binary


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "ProjectDiscovery nuclei — template-based vulnerability scan"
    order = 85

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        binary = find_binary("nuclei")
        if not binary:
            ctx.log_tool(self.name, "skipped", "nuclei binary not found — run scripts/install_tools.sh")
            return ctx

        urls = list(dict.fromkeys(ctx.urls[:15] if ctx.urls else [ctx.target]))
        if not urls:
            urls = [ctx.target]

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            list_path = f.name

        try:
            def _run():
                cmd = [
                    binary,
                    "-l", list_path,
                    "-severity", "critical,high,medium",
                    "-silent",
                    "-jsonl",
                    "-timeout", "5",
                    "-retries", "0",
                    "-rate-limit", "40",
                    "-c", "10",
                    "-max-host-error", "3",
                ]
                return subprocess.run(
                    cmd, capture_output=True, text=True, timeout=90  # hard cap 90s
                )

            try:
                proc = await asyncio.to_thread(_run)
            except subprocess.TimeoutExpired:
                ctx.log_tool(self.name, "error", "nuclei timed out after 90s")
                ctx.add_finding(
                    title="Nuclei scan timed out",
                    severity="info",
                    category="Nuclei",
                    evidence="Process exceeded 90s limit",
                    location=ctx.target,
                    remediation="Retry with fewer targets or install templates on server.",
                    source_tool=self.name,
                )
                return ctx
            except Exception as e:
                ctx.log_tool(self.name, "error", str(e)[:200])
                return ctx

            hits = 0
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                hits += 1
                info = obj.get("info") or {}
                name = info.get("name") or obj.get("template-id") or "Nuclei match"
                sev = (info.get("severity") or "medium").lower()
                matched = obj.get("matched-at") or obj.get("host") or ctx.target
                ctx.add_finding(
                    title=f"[Nuclei] {name}",
                    severity=sev if sev in ["critical", "high", "medium", "low", "info"] else "medium",
                    category="Nuclei Template",
                    evidence=str(obj)[:800],
                    location=str(matched)[:500],
                    remediation=(info.get("description") or "Review nuclei finding.")[:500],
                    source_tool=self.name,
                )

            ctx.artifacts["nuclei_hits"] = hits
            if hits == 0:
                ctx.add_finding(
                    title="Nuclei completed — no critical/high/medium matches",
                    severity="info",
                    category="Nuclei",
                    evidence=f"targets={len(urls)}",
                    location=ctx.target,
                    remediation="Expand templates or review manually.",
                    source_tool=self.name,
                )
            ctx.log_tool(self.name, "ok", f"hits={hits}")
        finally:
            try:
                os.unlink(list_path)
            except Exception:
                pass
        return ctx
