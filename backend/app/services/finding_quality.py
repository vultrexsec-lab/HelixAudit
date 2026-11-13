"""Finding quality: mask secrets, dedupe, risk score."""

import re
from typing import List, Dict, Any, Tuple

SECRET_VALUE = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|xsrf-token|csrf)\s*[=:]\s*)([^\s&;\"']{6,})"
)
JWT_LIKE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
LONG_TOKEN = re.compile(r"\b[a-zA-Z0-9_\-+/=]{32,}\b")


def mask_secrets(text: str | None) -> str:
    if not text:
        return ""
    out = SECRET_VALUE.sub(r"\1***REDACTED***", text)
    out = JWT_LIKE.sub("***JWT_REDACTED***", out)
    return out


def normalize_title(title: str) -> str:
    t = (title or "").lower().strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"https?://\S+", "", t)
    return t[:120]


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge near-duplicate findings by normalized title + location host/path."""
    seen: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for f in findings:
        loc = (f.get("location") or "")[:80]
        key = normalize_title(f.get("title") or "") + "|" + loc.split("?")[0]
        if key in seen:
            # keep higher severity
            prev = seen[key]
            if _sev_rank(f.get("severity")) < _sev_rank(prev.get("severity")):
                seen[key] = f
            continue
        seen[key] = f
        order.append(key)
    return [seen[k] for k in order]


def _sev_rank(s: str | None) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get((s or "info").lower(), 5)


def risk_score(severity: str | None, category: str | None = None, location: str | None = None) -> int:
    """0-100 style score for prioritization."""
    base = {"critical": 90, "high": 70, "medium": 45, "low": 25, "info": 10}.get((severity or "info").lower(), 10)
    cat = (category or "").lower()
    loc = (location or "").lower()
    if "injection" in cat or "nuclei" in cat:
        base = min(100, base + 8)
    if "admin" in loc or "api" in loc:
        base = min(100, base + 5)
    if "misconfiguration" in cat:
        base = min(100, base + 2)
    return base


def build_executive_summary(
    target: str,
    findings: List[Dict[str, Any]],
    asset_count: int,
) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        if s in counts:
            counts[s] += 1
    top = sorted(findings, key=lambda x: risk_score(x.get("severity"), x.get("category"), x.get("location")), reverse=True)[:5]
    lines = [
        f"Target: {target}",
        f"Overall findings: {len(findings)} (Critical {counts['critical']}, High {counts['high']}, "
        f"Medium {counts['medium']}, Low {counts['low']}, Info {counts['info']}). Assets observed: {asset_count}.",
    ]
    if counts["critical"] or counts["high"]:
        lines.append("Priority: Address Critical/High issues before production exposure increases.")
    else:
        lines.append("Priority: No critical/high issues detected by automated surface analysis; continue hardening and authenticated review.")
    if top:
        lines.append("Top items:")
        for i, f in enumerate(top, 1):
            lines.append(f"  {i}. [{(f.get('severity') or '').upper()}] {f.get('title')}")
    lines.append(
        "This automated assessment supports expert review. Manual verification and authorized authenticated testing remain essential."
    )
    return "\n".join(lines)
