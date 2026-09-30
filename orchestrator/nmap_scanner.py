import subprocess
import json
import xml.etree.ElementTree as ET
from pathlib import Path


NMAP_TIMEOUT_SECONDS = 180


def run_nmap(target_host: str, output_file: str | Path = None) -> dict:
    """
    Run Nmap in defensive discovery and service audit mode against an authorized target.
    
    Args:
        target_host: Hostname or IP address to scan.
        output_file: Optional path to save XML/JSON output.
        
    Returns:
        Structured dictionary containing scan summary, hosts, and discovered services.
    """
    target_host = str(target_host).strip()
    if not target_host:
        raise ValueError("Target host/IP cannot be empty.")

    xml_output_path = Path(output_file) if output_file else Path("nmap_scan_output.xml")
    xml_output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "nmap",
        "-sV",             # Service and version detection
        "--top-ports", "100",  # Top 100 common ports for fast, safe auditing
        "-T3",             # Normal timing
        "-Pn",             # Treat all hosts as online (avoid host discovery ping drops)
        "-oX", str(xml_output_path),
        target_host
    ]

    print(f"[*] Running Nmap service scan on target: {target_host}...")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NMAP_TIMEOUT_SECONDS
        )
    except subprocess.TimeoutExpired:
        print(f"[-] Nmap timed out after {NMAP_TIMEOUT_SECONDS} seconds.")
        return {"error": f"Nmap timed out after {NMAP_TIMEOUT_SECONDS} seconds.", "findings": []}
    except FileNotFoundError:
        print("[-] Nmap executable was not found on PATH.")
        return {"error": "Nmap not installed or not in PATH", "findings": []}

    if result.returncode != 0 and not xml_output_path.exists():
        print(f"[-] Nmap exited with code {result.returncode}: {result.stderr}")
        return {"error": result.stderr, "findings": []}

    parsed_result = parse_nmap_xml(xml_output_path, target_host)
    return parsed_result


def parse_nmap_xml(xml_path: Path, target_host: str) -> dict:
    """
    Parse Nmap XML output into a standardized list of security audit findings.
    """
    if not xml_path.exists():
        return {"target": target_host, "findings": []}

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return {"target": target_host, "error": f"Failed to parse XML: {e}", "findings": []}

    findings = []
    
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addresses = [addr.get("addr") for addr in host.findall("address")]
        host_addr = addresses[0] if addresses else target_host

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            port_id = port.get("portid")
            protocol = port.get("protocol")
            
            state_elem = port.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"
            
            if state != "open":
                continue

            service_elem = port.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            extra_info = service_elem.get("extrainfo", "") if service_elem is not None else ""

            full_service = f"{product} {version} {extra_info}".strip() or service_name

            # Evaluate severity heuristic based on exposed service
            severity = "LOW"
            if port_id in ["21", "23"]:  # Telnet / Plaintext FTP
                severity = "HIGH"
                title = f"Insecure plaintext service exposed ({service_name.upper()} on port {port_id})"
                remedy = f"Disable {service_name.upper()} and migrate to encrypted alternatives (e.g., SSH/SFTP)."
            elif port_id in ["3389", "5900", "445"]:  # RDP, VNC, SMB
                severity = "HIGH"
                title = f"High-risk remote administration or file sharing port exposed ({service_name.upper()} on port {port_id})"
                remedy = "Restrict access via VPN, firewall, or network segmentation. Disable if not required."
            elif port_id in ["80", "8080"]:
                severity = "MEDIUM"
                title = f"Unencrypted HTTP port exposed (port {port_id})"
                remedy = "Enforce HTTPS redirect (port 443) and enable HSTS."
            else:
                title = f"Exposed open port {port_id}/{protocol} running {service_name}"
                remedy = f"Verify whether port {port_id} needs to be accessible. Restrict exposure using firewall rules if internal only."

            finding = {
                "id": f"NMAP-{len(findings) + 1:03d}",
                "scanner": "nmap",
                "type": "Network Service Exposure",
                "title": title,
                "severity": severity,
                "file": f"{host_addr}:{port_id}",
                "line_start": int(port_id),
                "line_end": int(port_id),
                "description": f"Host {host_addr} is exposing {service_name} on {protocol} port {port_id}. Service details: {full_service}",
                "evidence": [
                    f"Host: {host_addr}",
                    f"Port: {port_id}/{protocol}",
                    f"State: {state}",
                    f"Service: {service_name}",
                    f"Version Info: {full_service}"
                ],
                "remediation_plan": {
                    "status": "requires_review",
                    "action": "restrict_network_access",
                    "recommended_fix": remedy,
                    "requires_patch_validation": False
                }
            }
            findings.append(finding)

    return {
        "target": target_host,
        "scanned_ports_count": len(findings),
        "findings": findings
    }
