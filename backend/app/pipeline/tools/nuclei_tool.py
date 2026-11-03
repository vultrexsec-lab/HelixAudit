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
            ctx.log_tool(self.name, "skipped", "nuclei binary not found")
            return ctx

        urls = list(dict.fromkeys(ctx.urls[:25] if ctx.urls else [ctx.target]))
        if not urls:
            urls = [ctx.target]

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            list_path = f.name

        try:
            def _run():
                # Focus on higher signal; keep runtime bounded
                cmd = [
                    binary,
                    "-l", list_path,
                    "-severity", "critical,high,medium",
                    "-silent",
                    "-jsonl",
                    "-timeout", "7",
                    "-retries", "1",
                    "-rate-limit", "50",
                    "-c", "15",
                ]
                return subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            proc = await asyncio.to_thread(_run)
            hits = []
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                hits.append(obj)
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
                    remediation=(info.get("description") or "Review nuclei finding and vendor guidance.")[:500],
                    source_tool=self.name,
                )

            ctx.artifacts["nuclei_hits"] = len(hits)
            if not hits:
                ctx.add_finding(
                    title="Nuclei scan completed — no critical/high/medium template matches",
                    severity="info",
                    category="Nuclei",
                    evidence=f"targets={len(urls)} stderr={(proc.stderr or '')[:200]}",
                    location=ctx.target,
                    remediation="Continue manual review; expand templates if needed.",
                    source_tool=self.name,
                )
        finally:
            try:
                os.unlink(list_path)
            except Exception:
                pass
        return ctx
