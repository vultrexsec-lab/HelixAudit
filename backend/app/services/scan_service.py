"""
HelixAudit Scan Service
Phase 1 + 2 + 3 (Discovery + Crawling + Secrets/Deep Analysis)
"""

import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..scanners.subdomain import enumerate_subdomains
from ..scanners.portscan import run_nmap_scan
from ..scanners.techdetect import detect_technologies
from ..scanners.crawler import crawl_site, directory_discovery, fetch_and_analyze
from ..scanners.secrets import find_secrets_in_text, analyze_security_headers
from urllib.parse import urlparse
import httpx


async def run_discovery_scan(db: Session, scan_id: int):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    try:
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.progress = 3
        scan.error_message = None
        db.commit()

        target = scan.target.strip()

        # 1. Subdomains
        scan.progress = 8
        db.commit()
        try:
            subdomains = await enumerate_subdomains(target)
            for sub in subdomains:
                db.add(Asset(scan_id=scan.id, asset_type="subdomain", value=sub,
                             extra_data={"source": "enumeration"}))
            db.commit()
        except Exception as e:
            print(f"Subdomain error: {e}")

        # 2. Ports
        scan.progress = 18
        db.commit()
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = (parsed.netloc or parsed.path).split(":")[0].split("/")[0]
        try:
            ports_data = run_nmap_scan(host)
            for p in ports_data:
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
            print(f"Port error: {e}")

        # 3. Tech detect
        scan.progress = 28
        db.commit()
        tech = {}
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
            print(f"Tech error: {e}")

        # 4. Crawling
        scan.progress = 40
        db.commit()
        pages = []
        try:
            pages = await crawl_site(target, max_pages=18, max_depth=2)
            for page in pages:
                if page.get("error"):
                    continue
                db.add(Asset(scan_id=scan.id, asset_type="page", value=page.get("url"),
                             extra_data={"status_code": page.get("status_code"),
                                         "title": page.get("title"),
                                         "has_forms": page.get("has_forms"),
                                         "interesting": page.get("interesting")}))
                if page.get("interesting"):
                    db.add(Finding(
                        scan_id=scan.id,
                        title=f"Interesting Page: {page.get('url')}",
                        description=f"Status {page.get('status_code')} | Forms: {page.get('has_forms')}",
                        severity=Severity.INFO.value, category="Content Discovery",
                        evidence=page.get("url"), location=page.get("url"),
                        remediation="Review for sensitive content."
                    ))
            db.commit()
        except Exception as e:
            print(f"Crawl error: {e}")

        # 5. Directory discovery
        scan.progress = 55
        db.commit()
        try:
            dirs = await directory_discovery(target)
            for d in dirs:
                db.add(Asset(scan_id=scan.id, asset_type="path", value=d.get("url"), extra_data=d))
                if d.get("interesting") or d.get("status_code") in [200, 401, 403]:
                    sev = Severity.HIGH.value if d.get("path") in [".env", ".git/HEAD"] else (
                        Severity.MEDIUM.value if d.get("status_code") in [200, 403] else Severity.INFO.value)
                    db.add(Finding(
                        scan_id=scan.id,
                        title=f"Interesting Path: /{d.get('path')} [{d.get('status_code')}]",
                        description=f"Length: {d.get('content_length')}",
                        severity=sev, category="Content Discovery",
                        evidence=str(d), location=d.get("url"),
                        remediation="Protect or remove sensitive paths."
                    ))
            db.commit()
        except Exception as e:
            print(f"Dir discovery error: {e}")

        # ===== PHASE 3: Secrets + Headers Analysis =====
        scan.progress = 70
        db.commit()

        # Analyze main page + a few crawled pages for secrets
        urls_to_analyze = [target]
        for p in pages[:8]:
            if p.get("url") and p.get("url") not in urls_to_analyze:
                urls_to_analyze.append(p.get("url"))

        headers = {
            "User-Agent": "HelixAudit/0.3 (Authorized Security Scanner)"
        }

        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers) as client:
            for url in urls_to_analyze:
                try:
                    data = await fetch_and_analyze(client, url)
                    if not data or not data.get("text"):
                        continue

                    # Secrets detection
                    secrets = find_secrets_in_text(data["text"], source=url)
                    for sec in secrets:
                        sev = Severity.CRITICAL.value if sec["confidence"] >= 0.8 else Severity.HIGH.value
                        db.add(Finding(
                            scan_id=scan.id,
                            title=f"Potential {sec['type']} Found",
                            description=f"A possible {sec['type']} was detected in the page content. Confidence: {sec['confidence']}",
                            severity=sev,
                            category="Sensitive Data Exposure",
                            evidence=f"Match: {sec['evidence']}\nSource: {sec['source']}",
                            location=url,
                            remediation="Immediately remove or rotate the exposed secret. Never hardcode credentials in client-side code or public files."
                        ))

                    # Security headers (only on main page)
                    if url == target or url == urls_to_analyze[0]:
                        header_issues = analyze_security_headers(data.get("headers", {}))
                        for issue in header_issues:
                            db.add(Finding(
                                scan_id=scan.id,
                                title=issue["title"],
                                description="Security header check failed.",
                                severity=issue["severity"],
                                category=issue["category"],
                                evidence=str(data.get("headers", {}))[:500],
                                location=url,
                                remediation=issue["remediation"]
                            ))

                    db.commit()
                except Exception as e:
                    print(f"Analysis error on {url}: {e}")

        # Done
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.error_message = str(e)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
