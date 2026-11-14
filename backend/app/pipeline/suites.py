"""
HelixAudit scan suites (Top Suite profiles).

suite id is stored on scan.config["suite"] and optionally scan.scan_type.
"""

from typing import Any, Dict, List, Optional

# tool.name values from pipeline tools
SUITES: Dict[str, Dict[str, Any]] = {
    "quick": {
        "name": "Quick Surface",
        "description": "Fast recon + headers/TLS — minutes, low noise",
        "tools": [
            "subdomain_enum", "dns_email_security", "port_scan", "httpx_probe",
            "waf_detect", "ssl_check", "https_redirect", "tech_detect",
            "baseline_files", "owasp_surface", "vapt_summary",
        ],
        "nuclei_severity": "critical,high",
        "nuclei_tags": "helixaudit",
        "nuclei_use_default": False,
        "nuclei_enabled": False,
    },
    "standard": {
        "name": "Standard VAPT-Assist",
        "description": "Balanced Tier A coverage (default)",
        "tools": None,  # all tools
        "exclude_tools": ["dir_brute"],  # slightly lighter
        "nuclei_severity": "critical,high,medium",
        "nuclei_tags": "helixaudit,cve,exposure,misconfig",
        "nuclei_exclude_tags": "dos,fuzz,intrusive",
        "nuclei_use_default": True,
        "nuclei_enabled": True,
    },
    "full": {
        "name": "Full Suite (Top)",
        "description": "All automated Tier A+B modules + nuclei top tags",
        "tools": None,  # everything registered
        "exclude_tools": [],
        "nuclei_severity": "critical,high,medium,low",
        "nuclei_tags": "cve,exposure,misconfig,vuln,helixaudit,config,swagger",
        "nuclei_exclude_tags": "dos,fuzz",
        "nuclei_use_default": True,
        "nuclei_enabled": True,
    },
    "owasp": {
        "name": "OWASP Top 10 Focus",
        "description": "Headers, access paths, injection probes, secrets, auth surface",
        "tools": [
            "httpx_probe", "ssl_check", "https_redirect", "tech_detect", "cookie_flags",
            "crawler", "api_discover", "vuln_paths", "secrets_scan", "owasp_surface",
            "active_checks", "injection_detect", "nuclei", "vapt_summary", "tier_c_manual",
        ],
        "nuclei_severity": "critical,high,medium",
        "nuclei_tags": "owasp,cve,injection,xss,sqli,misconfig,exposure,helixaudit",
        "nuclei_exclude_tags": "dos,fuzz",
        "nuclei_use_default": True,
        "nuclei_enabled": True,
    },
    "nuclei_top": {
        "name": "Nuclei Top Templates",
        "description": "Recon + nuclei CVEs/exposures/misconfig suite",
        "tools": [
            "subdomain_enum", "httpx_probe", "tech_detect", "ssl_check",
            "crawler", "api_discover", "nuclei", "vapt_summary",
        ],
        "nuclei_severity": "critical,high,medium",
        "nuclei_tags": "cve,exposure,misconfig,rce,lfi,sqli,xss,vuln",
        "nuclei_exclude_tags": "dos,fuzz,intrusive",
        "nuclei_use_default": True,
        "nuclei_enabled": True,
    },
}

DEFAULT_SUITE = "standard"


def list_suites() -> List[Dict[str, Any]]:
    out = []
    for sid, s in SUITES.items():
        out.append({
            "id": sid,
            "name": s["name"],
            "description": s["description"],
            "nuclei_enabled": s.get("nuclei_enabled", True),
            "nuclei_tags": s.get("nuclei_tags"),
            "nuclei_severity": s.get("nuclei_severity"),
        })
    return out


def resolve_suite(suite_id: Optional[str]) -> Dict[str, Any]:
    sid = (suite_id or DEFAULT_SUITE).strip().lower()
    if sid not in SUITES:
        sid = DEFAULT_SUITE
    return {"id": sid, **SUITES[sid]}


def apply_suite_to_config(config: Optional[dict], suite_id: Optional[str]) -> dict:
    cfg = dict(config or {})
    suite = resolve_suite(suite_id or cfg.get("suite"))
    cfg["suite"] = suite["id"]
    if suite.get("nuclei_enabled") is False:
        cfg["nuclei_enabled"] = False
    else:
        cfg["nuclei_enabled"] = True
    for k in ("nuclei_severity", "nuclei_tags", "nuclei_exclude_tags", "nuclei_use_default"):
        if k in suite and suite[k] is not None:
            # scan-level explicit override wins if already set
            if k not in cfg:
                cfg[k] = suite[k]
    return cfg


def filter_tools(tools: list, suite_id: Optional[str]) -> list:
    suite = resolve_suite(suite_id)
    allow = suite.get("tools")
    exclude = set(suite.get("exclude_tools") or [])
    if not suite.get("nuclei_enabled", True):
        exclude.add("nuclei")
    if allow is None:
        return [t for t in tools if t.name not in exclude]
    allow_set = set(allow)
    return [t for t in tools if t.name in allow_set and t.name not in exclude]
