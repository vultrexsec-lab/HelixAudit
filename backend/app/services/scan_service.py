"""
Scan orchestration service - Phase 1 (improved for Render)
"""

import asyncio
from datetime import datetime
from sqlalchemy.orm import Session
from ..models.models import Scan, Asset, Finding, ScanStatus, Severity
from ..scanners.subdomain import enumerate_subdomains
from ..scanners.portscan import run_nmap_scan
from ..scanners.techdetect import detect_technologies
from urllib.parse import urlparse


async def run_discovery_scan(db: Session, scan_id: int):
    """
    Phase 1 Discovery scan (Render-friendly version):
    1. Subdomain enumeration
    2. Port scanning (Nmap → TCP fallback)
    3. Technology detection
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

        # ---------- 1. Subdomain Enumeration ----------
        scan.progress = 10
        db.commit()

        try:
            subdomains = await enumerate_subdomains(target)
            for sub in subdomains:
                asset = Asset(
                    scan_id=scan.id,
                    asset_type="subdomain",
                    value=sub,
                    extra_data={"source": "enumeration"}
                )
                db.add(asset)
            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Subdomain enum error: {e}")

        scan.progress = 35
        db.commit()

        # ---------- 2. Port Scanning ----------
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.netloc or parsed.path
        host = host.split(":")[0].split("/")[0]

        try:
            ports_data = run_nmap_scan(host)

            for p in ports_data:
                asset = Asset(
                    scan_id=scan.id,
                    asset_type="port",
                    value=f"{p.get('ip', host)}:{p['port']}",
                    extra_data=p
                )
                db.add(asset)

                # Create finding for notable open ports
                notable_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP",
                                 5900: "VNC", 3306: "MySQL", 445: "SMB", 27017: "MongoDB"}
                if p["port"] in notable_ports:
                    sev = Severity.MEDIUM.value if p["port"] in [21, 23, 3389, 445] else Severity.INFO.value
                    finding = Finding(
                        scan_id=scan.id,
                        title=f"Open Port: {p['port']}/{p.get('protocol', 'tcp')} ({p.get('service', 'unknown')})",
                        description=f"Port {p['port']} is open. Service: {p.get('service')} {p.get('banner', '')}. Detection method: {p.get('method', 'unknown')}",
                        severity=sev,
                        category="Open Port",
                        evidence=str(p),
                        location=f"{p.get('ip', host)}:{p['port']}",
                        remediation="Verify if this port needs to be publicly accessible. Restrict via firewall if not required."
                    )
                    db.add(finding)

            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Port scan error: {e}")

        scan.progress = 65
        db.commit()

        # ---------- 3. Technology Detection ----------
        try:
            tech = await detect_technologies(target)

            asset = Asset(
                scan_id=scan.id,
                asset_type="technology",
                value=tech.get("final_url") or tech.get("url") or target,
                extra_data=tech
            )
            db.add(asset)

            techs = tech.get("technologies") or []
            if techs:
                finding = Finding(
                    scan_id=scan.id,
                    title="Technologies Detected",
                    description=f"Detected: {', '.join(techs)}",
                    severity=Severity.INFO.value,
                    category="Technology Fingerprint",
                    evidence=f"Server: {tech.get('server')} | Status: {tech.get('status_code')} | Title: {tech.get('title')}",
                    location=tech.get("final_url") or target,
                    remediation="Keep all detected software and frameworks updated. Avoid unnecessary version disclosure."
                )
                db.add(finding)
            elif tech.get("error"):
                # Still record that we tried
                finding = Finding(
                    scan_id=scan.id,
                    title="Technology Detection Partial Failure",
                    description=f"Could not fully fingerprint the target. Error: {tech.get('error')}",
                    severity=Severity.INFO.value,
                    category="Scan Info",
                    evidence=str(tech),
                    location=target,
                    remediation="Target may be blocking scanners or have network restrictions."
                )
                db.add(finding)

            db.commit()
        except Exception as e:
            print(f"[Scan {scan_id}] Tech detect error: {e}")

        # ---------- Done ----------
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.error_message = str(e)[:500]
        scan.completed_at = datetime.utcnow()
        db.commit()
