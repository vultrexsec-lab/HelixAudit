"""
Port & Service Scanning using Nmap for HelixAudit Phase 1
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import tempfile
import os


def run_nmap_scan(target: str, ports: str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443") -> List[Dict[str, Any]]:
    """
    Run a basic Nmap scan and return structured results.
    Only runs against targets that are in scope (caller responsibility).
    """
    results = []
    
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_file = tmp.name
    
    try:
        cmd = [
            "nmap",
            "-sV",               # Service version detection
            "-T4",               # Faster timing
            "--open",            # Only open ports
            "-p", ports,
            "-oX", xml_file,
            target
        ]
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if os.path.exists(xml_file):
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall("host"):
                addr = host.find("address")
                ip = addr.get("addr") if addr is not None else target
                
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                    
                for port in ports_elem.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        protocol = port.get("protocol", "tcp")
                        
                        service = port.find("service")
                        service_name = service.get("name", "unknown") if service is not None else "unknown"
                        product = service.get("product", "") if service is not None else ""
                        version = service.get("version", "") if service is not None else ""
                        
                        results.append({
                            "ip": ip,
                            "port": int(port_id),
                            "protocol": protocol,
                            "service": service_name,
                            "product": product,
                            "version": version,
                            "banner": f"{product} {version}".strip()
                        })
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print(f"Nmap error: {e}")
    finally:
        if os.path.exists(xml_file):
            os.unlink(xml_file)
    
    return results
