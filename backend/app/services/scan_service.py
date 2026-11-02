"""
Scan orchestration service for Phase 1
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
    Run Phase 1 Discovery scan:
    1. Subdomain enumeration
    2. Port scanning on main target
    3. Basic technology detection
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
    
    try:
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        scan.progress = 5
        db.commit()
        
        target = scan.target
        
        # 1. Subdomain Enumeration
        scan.progress = 15
        db.commit()
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
        
        scan.progress = 40
        db.commit()
        
        # 2. Port Scanning (main domain/IP)
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.netloc or parsed.path
        host = host.split(":")[0]
        
        ports_data = run_nmap_scan(host)
        
        for p in ports_data:
            asset = Asset(
                scan_id=scan.id,
                asset_type="port",
                value=f"{p['ip']}:{p['port']}",
                extra_data=p
            )
            db.add(asset)
            
            # Create informational finding for interesting open ports
            if p["port"] in [21, 22, 23, 3389, 5900, 3306, 445]:
                finding = Finding(
                    scan_id=scan.id,
                    title=f"Open Port Detected: {p['port']}/{p['protocol']} ({p['service']})",
                    description=f"Port {p['port']} is open running {p['service']} {p.get('banner', '')}",
                    severity=Severity.INFO.value if p["port"] not in [21, 23, 3389] else Severity.MEDIUM.value,
                    category="Open Port",
                    evidence=str(p),
                    location=f"{p['ip']}:{p['port']}",
                    remediation="Review if this port needs to be publicly exposed. Restrict access if possible."
                )
                db.add(finding)
        db.commit()
        
        scan.progress = 70
        db.commit()
        
        # 3. Technology Detection
        tech = await detect_technologies(target)
        
        asset = Asset(
            scan_id=scan.id,
            asset_type="technology",
            value=tech.get("url", target),
            extra_data=tech
        )
        db.add(asset)
        
        if tech.get("technologies"):
            finding = Finding(
                scan_id=scan.id,
                title="Technologies Detected",
                description=f"Detected technologies: {', '.join(tech['technologies'])}",
                severity=Severity.INFO.value,
                category="Technology Fingerprint",
                evidence=str(tech.get("headers", {})),
                location=tech.get("url"),
                remediation="Keep all software updated. Remove unnecessary technology disclosure if possible."
            )
            db.add(finding)
        
        db.commit()
        
        # Done
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 100
        scan.completed_at = datetime.utcnow()
        db.commit()
        
    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
