"""
HelixAudit Scan Service - Full pipeline with auth + active checks
"""

from datetime import datetime
from sqlalchemy.orm import Session
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..scanners.subdomain import enumerate_subdomains
from ..scanners.portscan import run_nmap_scan
from ..scanners.techdetect import detect_technologies
from ..scanners.crawler import crawl_site, directory_discovery, fetch_and_analyze
from ..scanners.secrets import find_secrets_in_text
from ..scanners.owasp_checks import run_full_owasp_checks
from ..scanners.active_checks import run_active_checks
from ..scanners.auth_scan import attempt_form_login, authenticated_crawl
from urllib.parse import urlparse
import httpx


def _sev(s: str) -> str:
    return {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
    }.get((s or "info").lower(), Severity.INFO.value)


async def run_discovery_scan(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    try:
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.progress = 2
        scan.error_message = None
        db.commit()

        target = scan.target.strip()
        config = scan.config or {}
        discovered_paths = []
        main_headers = {}
        main_body = ""
        pages = []

        # 1. Subdomains
        scan.progress = 6
        db.commit()
        try:
            for sub in await enumerate_subdomains(target):
                db.add(Asset(scan_id=scan.id, asset_type="subdomain", value=sub,
                             extra_data={"source": "enumeration"}))
            db.commit()
        except Exception as e:
            print("Subdomain error:", e)

        # 2. Ports
        scan.progress = 12
        db.commit()
        host = urlparse(target if "://" in target else f"http://{target}").netloc or target
        host = host.split(":")[0].split("/")[0]
        try:
            for p in run_nmap_scan(host):
                db.add(Asset(scan_id=scan.id, asset_type="port",
                             value=f"{p.get('ip', host)}:{p['port']}", extra_data=p))
                if p["port"] in [21, 22, 23, 3389, 5900, 3306, 445]:
                    sev = Severity.MEDIUM.value if p["port"] in [21, 23, 3389, 445] else Severity.INFO.value
                    db.add(Finding(
                        scan_id=scan.id,
                        title=f"Open Port: {p['port']} ({p.get('service', '?')})",
                        description=f"Method: {p.get('method')} | {p.get('banner', '')}",
                        severity=sev, category="Open Port",
                        evidence=str(p), location=f"{p.get('ip', host)}:{p['port']}",
                        remediation="Restrict public access if not required."
                    ))
            db.commit()
        except Exception as e:
            print("Port error:", e)

        # 3. Tech
        scan.progress = 18
        db.commit()
        try:
            tech = await detect_technologies(target)
            db.add(Asset(scan_id=scan.id, asset_type="technology",
                         value=tech.get("final_url") or target, extra_data=tech))
            if tech.get("technologies"):
                db.add(Finding(
                    scan_id=scan.id, title="Technologies Detected",
                    description=", ".join(tech["technologies"]),
                    severity=Severity.INFO.value, category="Technology Fingerprint",
                    evidence=str(tech.get("server")), location=tech.get("final_url") or target,
                    remediation="Keep software updated."
                ))
            db.commit()
        except Exception as e:
            print("Tech error:", e)

        # 4. Crawl
        scan.progress = 28
        db.commit()
        try:
            pages = await crawl_site(target, max_pages=20, max_depth=2)
            for page in pages:
                if page.get("error"):
                    continue
                db.add(Asset(scan_id=scan.id, asset_type="page", value=page.get("url"),
                             extra_data={"status_code": page.get("status_code"),
                                         "title": page.get("title"),
                                         "has_forms": page.get("has_forms")}))
            db.commit()
        except Exception as e:
            print("Crawl error:", e)

        # 5. Directory discovery
        scan.progress = 38
        db.commit()
        try:
            discovered_paths = await directory_discovery(target)
            for d in discovered_paths:
                db.add(Asset(scan_id=scan.id, asset_type="path", value=d.get("url"), extra_data=d))
            db.commit()
        except Exception as e:
            print("Dir error:", e)

        headers_ua = {"User-Agent": "HelixAudit/0.9 (Authorized Security Scanner)"}

        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers_ua) as client:
            # 6. Secrets
            scan.progress = 48
            db.commit()
            urls = [target] + [p.get("url") for p in pages[:7] if p.get("url")]
            for i, url in enumerate(dict.fromkeys(urls)):
                try:
                    data = await fetch_and_analyze(client, url)
                    if not data:
                        continue
                    if i == 0:
                        main_headers = data.get("headers") or {}
                        main_body = data.get("text") or ""
                    for sec in find_secrets_in_text(data.get("text") or "", source=url):
                        sev = Severity.CRITICAL.value if sec.get("confidence", 0) >= 0.8 else Severity.HIGH.value
                        db.add(Finding(
                            scan_id=scan.id,
                            title=f"Potential {sec['type']} Found",
                            description=f"Possible secret detected (confidence {sec.get('confidence')})",
                            severity=sev, category="Sensitive Data Exposure",
                            evidence=f"{sec['evidence']}\nSource: {sec['source']}",
                            location=url,
                            remediation="Rotate/remove the secret immediately."
                        ))
                    db.commit()
                except Exception as e:
                    print("Secrets error:", e)

            # 7. OWASP surface
            scan.progress = 60
            db.commit()
            try:
                owasp = await run_full_owasp_checks(
                    client=client, url=target, headers=main_headers,
                    body=main_body, discovered_paths=discovered_paths
                )
                for f in owasp:
                    db.add(Finding(
                        scan_id=scan.id, title=f["title"], description=f.get("title"),
                        severity=_sev(f.get("severity")), category=f.get("category", "OWASP Check"),
                        evidence=f.get("evidence"), location=f.get("location") or target,
                        remediation=f.get("remediation")
                    ))
                db.commit()
            except Exception as e:
                print("OWASP error:", e)

            # 8. Deeper active checks
            scan.progress = 72
            db.commit()
            try:
                active = await run_active_checks(client, target)
                for f in active:
                    db.add(Finding(
                        scan_id=scan.id, title=f["title"], description=f.get("title"),
                        severity=_sev(f.get("severity")), category=f.get("category", "Active Check"),
                        evidence=f.get("evidence"), location=f.get("location") or target,
                        remediation=f.get("remediation")
                    ))
                db.commit()
            except Exception as e:
                print("Active checks error:", e)

        # 9. Authenticated scanning (if credentials provided)
        scan.progress = 82
        db.commit()
        username = config.get("username")
        password = config.get("password")
        login_url = config.get("login_url")

        if username and password:
            try:
                auth_client, auth_info = await attempt_form_login(
                    target, username, password, login_url
                )
                db.add(Finding(
                    scan_id=scan.id,
                    title="Authenticated scan attempted",
                    description=auth_info.get("message", ""),
                    severity=Severity.INFO.value,
                    category="Authenticated Scanning",
                    evidence=str(auth_info),
                    location=auth_info.get("login_url") or target,
                    remediation="Review authenticated exposure if login succeeded."
                ))
                if auth_client:
                    try:
                        if auth_info.get("success"):
                            auth_pages = await authenticated_crawl(auth_client, target)
                            for ap in auth_pages:
                                db.add(Asset(
                                    scan_id=scan.id,
                                    asset_type="auth_page",
                                    value=ap.get("url"),
                                    extra_data=ap
                                ))
                                if ap.get("status_code") == 200 and any(
                                    x in (ap.get("url") or "").lower()
                                    for x in ["admin", "dashboard", "settings", "account"]
                                ):
                                    db.add(Finding(
                                        scan_id=scan.id,
                                        title=f"Authenticated page accessible: {ap.get('url')}",
                                        description=f"Status {ap.get('status_code')} after login",
                                        severity=Severity.INFO.value,
                                        category="Authenticated Scanning",
                                        evidence=str(ap),
                                        location=ap.get("url"),
                                        remediation="Verify authorization controls on authenticated resources."
                                    ))
                        await auth_client.aclose()
                    except Exception as e:
                        print("Auth crawl error:", e)
                        try:
                            await auth_client.aclose()
                        except Exception:
                            pass
                db.commit()
            except Exception as e:
                print("Auth scan error:", e)

        # Clear password from stored config after run (best effort)
        try:
            if scan.config and "password" in (scan.config or {}):
                new_cfg = dict(scan.config)
                new_cfg["password"] = "***cleared***"
                scan.config = new_cfg
        except Exception:
            pass

        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.error_message = str(e)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
