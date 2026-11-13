"""Email notifications for scan completion (Phase B)."""

import os
import smtplib
from email.message import EmailMessage
from typing import Optional


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def email_configured() -> bool:
    return bool(_env("SMTP_HOST") and _env("SMTP_FROM") and _env("NOTIFY_EMAIL_TO"))


def send_scan_complete_email(
    to_email: Optional[str],
    project_name: str,
    scan_id: int,
    target: str,
    status: str,
    counts: dict,
    report_hint: str = "",
) -> dict:
    """
    Send scan completion email if SMTP env is configured.
    Env:
      SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD
      SMTP_FROM, NOTIFY_EMAIL_TO (default recipient)
      SMTP_TLS (default true)
    """
    if not email_configured() and not to_email:
        return {"sent": False, "reason": "email not configured"}

    host = _env("SMTP_HOST")
    port = int(_env("SMTP_PORT", "587") or "587")
    user = _env("SMTP_USER")
    password = _env("SMTP_PASSWORD")
    from_addr = _env("SMTP_FROM")
    to_addr = (to_email or _env("NOTIFY_EMAIL_TO")).strip()
    use_tls = _env("SMTP_TLS", "true").lower() in ("1", "true", "yes")

    if not host or not from_addr or not to_addr:
        return {"sent": False, "reason": "missing SMTP_HOST/SMTP_FROM/recipient"}

    subj = f"[HelixAudit] Scan #{scan_id} {status}: {target}"
    body = (
        f"Project: {project_name}\n"
        f"Scan ID: {scan_id}\n"
        f"Target: {target}\n"
        f"Status: {status}\n\n"
        f"Summary:\n"
        f"  Critical: {counts.get('critical', 0)}\n"
        f"  High: {counts.get('high', 0)}\n"
        f"  Medium: {counts.get('medium', 0)}\n"
        f"  Low: {counts.get('low', 0)}\n"
        f"  Info: {counts.get('info', 0)}\n\n"
        f"{report_hint}\n"
        f"— HelixAudit (authorized assessments only)\n"
    )

    msg = EmailMessage()
    msg["Subject"] = subj
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            if use_tls:
                smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return {"sent": True, "to": to_addr}
    except Exception as e:
        return {"sent": False, "reason": str(e)[:300]}
