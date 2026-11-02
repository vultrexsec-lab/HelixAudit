"""
Scan orchestration service
Phase 1 + Phase 2 (Discovery + Deep Crawling)
"""

import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..scanners.subdomain import enumerate_subdomains
from ..scanners.portscan import run_nmap_scan
from ..scanners.techdetect import detect_technologies
from ..scanners.crawler import crawl_site, directory_discovery
from urllib.parse import urlparse


async def run_discovery_scan(db: Session, scan_id: int):
    """
    Combined Phase 1 + Phase 2 scan:
    1. Subdomain enumeration
    2. Port scanning (Nmap → TCP fallback)
    3. Technology detection
    4. Deep crawling (pages + links)
    5. Directory / interesting path discovery
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    try:
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.progress = 5
        scan.error_message = None
        db.commit()

        target = scan.target.strip()

        # ===== 1. Subdomain Enumeration =====
        scan.progress = 8
        db.commit()
        try:
            subdomains = await enumerate_subdomains(target)
            for sub in subdomains:
                db.add(Asset(scan_id=scan.id, asset_type="subdomain", value=sub,
                             extra_data={"source": "enumeration"}))
            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Subdomain error: {e}")

        scan.progress = 20
        db.commit()

        # ===== 2. Port Scanning =====
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = (parsed.netloc or parsed.path).split(":")[0].split("/")[0]

        try:
            ports_data = run_nmap_scan(host)
            for p in ports_data:
                db.add(Asset(scan_id=scan.id, asset_type="port",
                             value=f"{p.get('ip', host)}:{p['port']}", extra_data=p))

                notable = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP",
                           5900: "VNC", 3306: "MySQL", 445: "SMB"}
                if p["port"] in notable:
                    sev = Severity.MEDIUM.value if p["port"] in [21, 23, 3389, 445] else Severity.INFO.value
                    db.add(Finding(
                        scan_id=scan.id,
                        title=f"Open Port: {p['port']}/{p.get('protocol','tcp')} ({p.get('service','unknown')})",
                        description=f"Port {p['port']} open. Service: {p.get('service')} {p.get('banner','')}. Method: {p.get('method')}",
                        severity=sev,
                        category="Open Port",
                        evidence=str(p),
                        location=f"{p.get('ip', host)}:{p['port']}",
                        remediation="Verify if this port should be public. Restrict via firewall if not needed."
                    ))
            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Port scan error: {e}")

        scan.progress = 35
        db.commit()

        # ===== 3. Technology Detection =====
        try:
            tech = await detect_technologies(target)
            db.add(Asset(scan_id=scan.id, asset_type="technology",
                         value=tech.get("final_url") or target, extra_data=tech))

            techs = tech.get("technologies") or []
            if techs:
                db.add(Finding(
                    scan_id=scan.id,
                    title="Technologies Detected",
                    description=f"Detected: {', '.join(techs)}",
                    severity=Severity.INFO.value,
                    category="Technology Fingerprint",
                    evidence=f"Server: {tech.get('server')} | Status: {tech.get('status_code')} | Title: {tech.get('title')}",
                    location=tech.get("final_url") or target,
                    remediation="Keep all software updated. Minimize version disclosure."
                ))
            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Tech detect error: {e}")

        scan.progress = 50
        db.commit()

        # ===== 4. Deep Crawling (Phase 2) =====
        try:
            pages = await crawl_site(target, max_pages=20, max_depth=2)
            for page in pages:
                if page.get("error"):
                    continue
                db.add(Asset(
                    scan_id=scan.id,
                    asset_type="page",
                    value=page.get("url"),
                    extra_data={
                        "status_code": page.get("status_code"),
                        "title": page.get("title"),
                        "content_type": page.get("content_type"),
                        "has_forms": page.get("has_forms"),
                        "interesting": page.get("interesting"),
                        "links_count": len(page.get("links", []))
                    }
                ))
                if page.get("interesting"):
                    db.add(Finding(
                        scan_id=scan.id,
                        title=f"Interesting Page Found: {page.get('url')}",
                        description=f"Status: {page.get('status_code')} | Title: {page.get('title')} | Forms: {page.get('has_forms')}",
                        severity=Severity.INFO.value,
                        category="Content Discovery",
                        evidence=str(page.get("url")),
                        location=page.get("url"),
                        remediation="Review this page for sensitive functionality or information disclosure."
                    ))
            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Crawler error: {e}")

        scan.progress = 75
        db.commit()

        # ===== 5. Directory / Path Discovery (Phase 2) =====
        try:
            dirs = await directory_discovery(target)
            for d in dirs:
                db.add(Asset(
                    scan_id=scan.id,
                    asset_type="path",
                    value=d.get("url"),
                    extra_data=d
                ))
                if d.get("interesting") or d.get("status_code") in [200, 403, 401]:
                    sev = Severity.MEDIUM.value if d.get("path") in [".env", ".git/HEAD", "backup", "phpinfo.php"] else Severity.INFO.value
                    db.add(Finding(
                        scan_id=scan.id,
                        title=f"Interesting Path: /{d.get('path')} (Status {d.get('status_code')})",
                        description=f"Path responded with {d.get('status_code')}. Length: {d.get('content_length')}",
                        severity=sev,
                        category="Content Discovery",
                        evidence=str(d),
                        location=d.get("url"),
                        remediation="Review whether this path should be publicly accessible. Remove or protect sensitive paths."
                    ))
            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Directory discovery error: {e}")

        # ===== Finished =====
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.error_message = str(e)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
