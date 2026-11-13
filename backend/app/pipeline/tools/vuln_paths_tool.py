"""Sensitive path checks with soft-404 / baseline fingerprint filtering."""

import hashlib
import httpx
from urllib.parse import urlparse
from .base import BaseTool
from ..context import PipelineContext

PATHS = [
    ("/.env", "high"),
    ("/.git/HEAD", "high"),
    ("/backup.zip", "high"),
    ("/db.sql", "high"),
    ("/phpinfo.php", "medium"),
    ("/server-status", "medium"),
    ("/actuator", "medium"),
    ("/actuator/env", "high"),
    ("/swagger-ui.html", "medium"),
    ("/swagger/index.html", "medium"),
    ("/api-docs", "medium"),
    ("/graphql", "medium"),
    ("/debug", "medium"),
    ("/console", "medium"),
    ("/admin", "medium"),
    ("/administrator", "medium"),
    ("/wp-login.php", "info"),
    ("/wp-json/", "info"),
    ("/.well-known/security.txt", "info"),
    ("/config.json", "medium"),
    ("/package.json", "low"),
]

# Content signals that suggest a real sensitive file (not SPA shell)
GIT_HEAD_SIG = ("ref: refs/", "ref:refs/")
ENV_SIG = ("APP_KEY=", "DB_PASSWORD=", "DATABASE_URL=", "AWS_SECRET", "SECRET_KEY=")
SQL_SIG = ("CREATE TABLE", "INSERT INTO", "PostgreSQL", "MySQL dump")
ZIP_SIG = (b"PK\x03\x04",)


def _body_hash(content: bytes) -> str:
    return hashlib.sha256(content[:8000]).hexdigest()


def _looks_like_real_hit(path: str, status: int, content: bytes, text: str) -> tuple[bool, str]:
    """Return (is_real, reason). Soft-404 / generic pages return False."""
    if status == 403:
        # Forbidden on sensitive path can be notable but not "exposed file"
        return True, "403_forbidden"
    if status != 200:
        return False, "non_200"

    low = (text or "")[:4000].lower()
    # HTML app shell is not a leaked .env / .git / sql
    if path in ("/.env", "/.git/HEAD", "/db.sql", "/backup.zip", "/actuator/env"):
        if "<html" in low and "create table" not in low and "ref: refs" not in low and "app_key=" not in low:
            # likely SPA/soft-404 unless binary zip
            if path == "/backup.zip" and content[:4] == b"PK\x03\x04":
                return True, "zip_magic"
            if path == "/.git/HEAD" and any(s in (text or "") for s in GIT_HEAD_SIG):
                return True, "git_head_content"
            if path == "/.env" and any(s.lower() in low for s in ENV_SIG):
                return True, "env_content"
            if path == "/db.sql" and any(s.lower() in low for s in SQL_SIG):
                return True, "sql_content"
            if path == "/actuator/env" and ("propertySources" in text or "systemProperties" in text):
                return True, "actuator_env_json"
            return False, "soft404_html_shell"

    if path.endswith(".php") and "phpinfo()" in low:
        return True, "phpinfo"
    if "swagger" in path and ("swagger" in low or "openapi" in low):
        return True, "swagger_ui"
    if path == "/graphql" and status == 200:
        return True, "graphql_endpoint"

    # Generic 200 on admin/login: possible real page
    if path in ("/admin", "/administrator", "/wp-login.php", "/login"):
        if 'type="password"' in low or "login" in low or "wordpress" in low:
            return True, "login_form"
        if "<html" in low:
            return True, "html_200_unverified"

    return True, "status_200"


class VulnPathsTool(BaseTool):
    name = "vuln_paths"
    description = "Sensitive path checks with soft-404 filtering"
    order = 43

    async def run(self, ctx: PipelineContext) -> PipelineContext:
        parsed = urlparse(ctx.target if "://" in ctx.target else f"https://{ctx.target}")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        headers = {"User-Agent": "HelixAudit-Pipeline/1.6.1"}
        hits = 0
        soft404 = 0

        async with httpx.AsyncClient(follow_redirects=False, timeout=8.0, verify=False, headers=headers) as client:
            # Baseline: random path + homepage fingerprint for soft-404 detection
            baseline_hashes = set()
            try:
                home = await client.get(origin + "/")
                baseline_hashes.add(_body_hash(home.content))
            except Exception:
                pass
            try:
                rnd = await client.get(origin + "/helixaudit-not-exist-424242/")
                if rnd.status_code == 200:
                    baseline_hashes.add(_body_hash(rnd.content))
            except Exception:
                pass

            for path, sev in PATHS:
                url = origin + path
                try:
                    r = await client.get(url)
                    content = r.content or b""
                    text = ""
                    try:
                        text = content.decode("utf-8", errors="ignore")
                    except Exception:
                        text = ""

                    # Soft-404: same body as baseline random/home page
                    h = _body_hash(content)
                    if r.status_code == 200 and h in baseline_hashes and len(content) > 500:
                        soft404 += 1
                        continue

                    real, reason = _looks_like_real_hit(path, r.status_code, content, text)
                    if not real:
                        soft404 += 1
                        continue

                    if r.status_code not in (200, 401, 403):
                        continue

                    hits += 1
                    ctx.merge_urls([url])

                    # Severity calibration
                    severity = sev
                    if r.status_code == 403:
                        severity = "low" if path in ("/.env", "/.git/HEAD", "/db.sql", "/backup.zip") else "info"
                        title = f"Path forbidden [{r.status_code}]: {path}"
                    elif reason in ("soft404_html_shell",):
                        continue
                    elif reason in ("html_200_unverified",):
                        severity = "info"
                        title = f"Path returns 200 (needs manual verify): {path}"
                    elif reason in ("git_head_content", "env_content", "sql_content", "zip_magic", "actuator_env_json"):
                        severity = "high"
                        title = f"Likely sensitive exposure [{r.status_code}]: {path}"
                    else:
                        title = f"Path responds [{r.status_code}]: {path}"

                    ctx.add_finding(
                        title=title,
                        severity=severity,
                        category="VAPT-Vulnerability Assessment",
                        evidence=f"status={r.status_code} length={len(content)} validate={reason}",
                        location=url,
                        remediation="Confirm manually. Restrict or remove sensitive/debug endpoints from public access.",
                        source_tool=self.name,
                    )
                except Exception:
                    continue

        ctx.artifacts["vuln_paths"] = {"hits": hits, "soft404_filtered": soft404}
        ctx.log_tool(self.name, "ok", f"hits={hits} soft404_filtered={soft404}")
        return ctx
