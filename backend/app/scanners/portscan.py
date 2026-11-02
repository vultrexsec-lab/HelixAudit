"""
Port & Service Scanning for HelixAudit
- Tries Nmap first
- Falls back to pure Python TCP connect scan if Nmap fails (Render-friendly)
"""

import subprocess
import socket
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
import tempfile
import os
import concurrent.futures


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8888
]


def _tcp_connect_scan(host: str, ports: List[int] = None, timeout: float = 1.5) -> List[Dict[str, Any]]:
    """Pure Python TCP connect scan - works on most PaaS including Render."""
    if ports is None:
        ports = COMMON_PORTS

    results = []

    def check_port(port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = socket.getservbyport(port, "tcp") if port <= 1024 else "unknown"
                    return {
                        "ip": host,
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "product": "",
                        "version": "",
                        "banner": "",
                        "method": "tcp-connect"
                    }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    return sorted(results, key=lambda x: x["port"])


def run_nmap_scan(target: str, ports: str = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443") -> List[Dict[str, Any]]:
    """
    Try Nmap first. If it fails (common on Render free tier), 
    automatically fall back to pure Python TCP connect scan.
    """
    results = []
    nmap_success = False

    # --- Try Nmap ---
    xml_file = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_file = tmp.name

        cmd = [
            "nmap", "-sV", "-T4", "--open",
            "-p", ports,
            "-oX", xml_file,
            target
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        if os.path.exists(xml_file) and os.path.getsize(xml_file) > 100:
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
                            "banner": f"{product} {version}".strip(),
                            "method": "nmap"
                        })
            nmap_success = len(results) > 0 or True  # Considered attempted
    except Exception as e:
        print(f"[PortScan] Nmap failed: {e}")
    finally:
        if xml_file and os.path.exists(xml_file):
            try:
                os.unlink(xml_file)
            except Exception:
                pass

    # --- Fallback to pure Python if Nmap gave nothing useful ---
    if not results:
        print(f"[PortScan] Falling back to TCP connect scan for {target}")
        try:
            # Clean host
            host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            results = _tcp_connect_scan(host)
        except Exception as e:
            print(f"[PortScan] TCP fallback also failed: {e}")

    return results
