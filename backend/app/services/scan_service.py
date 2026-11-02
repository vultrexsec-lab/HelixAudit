"""
HelixAudit Scan Service
Phases 1–4: Discovery + Crawling + Secrets + OWASP surface checks
"""

import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..scanners.subdomain import enumerate_subdomains
from ..scanners.portscan import run_nmap_scan
from ..scanners.techdetect import detect_technologies
from ..scanners.crawler import crawl_site, directory_discovery, fetch_and_analyze
from ..scanners.secrets import find_secrets_in_text
from ..scanners.owasp_checks import run_owasp_surface_checks
from urllib.parse import urlparse
import httpx


def _sev(s: str) -> str:
    s = (s or "info").lower()
    mapping = {
        "critical": Severity.CRITICAL.value,
        "high": Severity.HIGH.value,
        "medium": Severity.MEDIUM.value,
        "low": Severity.LOW.value,
        "info": Severity.INFO.value,
    }
    return mapping.get(s, Severity.INFO.value)


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
        discovered_paths = []
        main_headers = {}
        main_body = ""

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
        scan.progress = 16
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
        scan.progress = 24
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
                    remediation="Keep software updated and minimize version disclosure."
                ))
            db.commit()
        except Exception as e:
            print(f"Tech error: {e}")

        # 4. Crawling
        scan.progress = 38
        db.commit()
        pages = []
        try:
            pages = await crawl_site(target, max_pages=18, max_depth=2)
            for page in pages:
                if page.get("error"):
                    continue
                db.add(Asset(scan_id=scan.id, asset_type="page", value=page.get("url"),
                             extra_data={
                                 "status_code": page.get("status_code"),
                                 "title": page.get("title"),
                                 "has_forms": page.get("has_forms"),
                                 "interesting": page.get("interesting")
                             }))
            db.commit()
        except Exception as e:
            print(f"Crawl error: {e}")

        # 5. Directory discovery
        scan.progress = 52
        db.commit()
        try:
            dirs = await directory_discovery(target)
            discovered_paths = dirs
            for d in dirs:
                db.add(Asset(scan_id=scan.id, asset_type="path", value=d.get("url"), extra_data=d))
            db.commit()
        except Exception as e:
            print(f"Dir discovery error: {e}")

        # 6. Secrets + content analysis
        scan.progress = 68
        db.commit()
        urls_to_analyze = [target]
        for p in pages[:6]:
            u = p.get("url")
            if u and u not in urls_to_analyze:
                urls_to_analyze.append(u)

        headers = {"User-Agent": "HelixAudit/0.4 (Authorized Security Scanner)"}
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0, verify=False, headers=headers) as client:
            for i, url in enumerate(urls_to_analyze):
                try:
                    data = await fetch_and_analyze(client, url)
                    if not data:
                        continue
                    if i == 0:
                        main_headers = data.get("headers") or {}
                        main_body = data.get("text") or ""

                    # Secrets
                    secrets = find_secrets_in_text(data.get("text") or "", source=url)
                    for sec in secrets:
                        sev = Severity.CRITICAL.value if sec.get("confidence", 0) >= 0.8 else Severity.HIGH.value
                        db.add(Finding(
                            scan_id=scan.id,
                            title=f"Potential {sec['type']} Found",
                            description=f"Possible {sec['type']} detected. Confidence: {sec.get('confidence')}",
                            severity=sev,
                            category="A04:2025 Cryptographic Failures / Sensitive Data Exposure",
                            evidence=f"Match: {sec['evidence']}\nSource: {sec['source']}",
                            location=url,
                            remediation="Remove or rotate the exposed secret immediately. Never hardcode credentials."
                        ))
                    db.commit()
                except Exception as e:
                    print(f"Analysis error on {url}: {e}")

        # 7. Phase 4 – OWASP surface checks
        scan.progress = 85
        db.commit()
        try:
            owasp_findings = run_owasp_surface_checks(
                url=target,
                headers=main_headers,
                body=main_body,
                discovered_paths=discovered_paths
            )
            for f in owasp_findings:
                db.add(Finding(
                    scan_id=scan.id,
                    title=f["title"],
                    description=f.get("title"),
                    severity=_sev(f.get("severity")),
                    category=f.get("category", "OWASP Check"),
                    evidence=f.get("evidence"),
                    location=f.get("location") or target,
                    remediation=f.get("remediation")
                ))
            db.commit()
        except Exception as e:
            print(f"OWASP checks error: {e}")

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
