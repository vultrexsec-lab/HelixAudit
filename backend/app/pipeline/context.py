"""
Shared context passed between pipeline tools.
Each tool reads from context, writes new data back.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime


@dataclass
class PipelineFinding:
    title: str
    severity: str = "info"
    category: str = "general"
    evidence: str = ""
    location: str = ""
    remediation: str = ""
    source_tool: str = ""


@dataclass
class PipelineContext:
    target: str
    config: Dict[str, Any] = field(default_factory=dict)
    # Accumulated intelligence
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    pages: List[Dict[str, Any]] = field(default_factory=list)
    paths: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    secrets_raw: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[PipelineFinding] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)  # free-form per-tool output
    tool_logs: List[Dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def add_finding(self, **kwargs):
        self.findings.append(PipelineFinding(**kwargs))

    def log_tool(self, name: str, status: str, message: str = "", extra: Optional[dict] = None):
        self.tool_logs.append({
            "tool": name,
            "status": status,
            "message": message,
            "extra": extra or {},
            "ts": datetime.utcnow().isoformat(),
        })

    def merge_urls(self, new_urls: List[str]):
        seen = set(self.urls)
        for u in new_urls:
            if u and u not in seen:
                seen.add(u)
                self.urls.append(u)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "domains": self.domains,
            "ports_count": len(self.ports),
            "urls_count": len(self.urls),
            "technologies": self.technologies,
            "findings_count": len(self.findings),
            "tools_run": len(self.tool_logs),
            "tool_logs": self.tool_logs,
        }
