"""Shared soft-404 / SPA shell detection for path findings."""

import hashlib
from typing import Optional


def body_hash(content: bytes) -> str:
    return hashlib.sha256((content or b"")[:8000]).hexdigest()


def is_html_shell(content: bytes, content_type: str = "", text: Optional[str] = None) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    if text is None:
        try:
            text = (content or b"").decode("utf-8", errors="ignore")
        except Exception:
            text = ""
    low = (text or "")[:800].lower()
    return "<!doctype html" in low or "<html" in low


def is_soft404(
    content: bytes,
    content_type: str = "",
    baseline_hashes: Optional[set] = None,
    text: Optional[str] = None,
) -> bool:
    """
    True if response looks like SPA/app shell soft-404 rather than a real file.
    """
    if not content:
        return True
    if baseline_hashes and body_hash(content) in baseline_hashes and len(content) > 400:
        return True
    # HTML for paths that should be text/binary is soft-404
    if is_html_shell(content, content_type, text):
        return True
    return False


def real_sensitive_content(path: str, content: bytes, text: str = "") -> bool:
    """True only if body matches expected sensitive file content."""
    p = (path or "").lower()
    t = text or ""
    try:
        t = t or content.decode("utf-8", errors="ignore")
    except Exception:
        t = ""
    low = t[:5000].lower()

    if ".env" in p and any(x in low for x in ("app_key=", "db_password=", "database_url=", "secret_key=")):
        return True
    if "git/head" in p and ("ref: refs/" in t or "ref:refs/" in t):
        return True
    if "git/config" in p and "[core]" in low:
        return True
    if p.endswith(".sql") and any(x in low for x in ("create table", "insert into", "mysql dump")):
        return True
    if "phpinfo" in p and "phpinfo()" in low:
        return True
    if "actuator" in p and ("propertysources" in low or "systemproperties" in low):
        return True
    if content[:4] == b"PK\x03\x04":
        return True
    return False
