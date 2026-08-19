import argparse
import concurrent.futures
import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime
import psutil


class SystemMonitor:
    """Handles system resource sampling and threshold checking."""

    def __init__(self, cpu_thresh=80.0, ram_thresh=80.0, disk_thresh=90.0):
        self.cpu_thresh = cpu_thresh
        self.ram_thresh = ram_thresh
        self.disk_thresh = disk_thresh

    def collect_metrics(self):
        cpu_usage = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        status = "OPTIMAL"
        alerts = []

        if cpu_usage > self.cpu_thresh:
            status = "WARNING"
            alerts.append(f"High CPU Utilization: {cpu_usage}%")
        if ram.percent > self.ram_thresh:
            status = "WARNING"
            alerts.append(f"High RAM Utilization: {ram.percent}%")
        if disk.percent > self.disk_thresh:
            status = "CRITICAL"
            alerts.append(f"High Disk Utilization: {disk.percent}%")

        return {
            "timestamp": datetime.now().isoformat(),
            "cpu_percent": cpu_usage,
            "ram_percent": ram.percent,
            "ram_used_gb": round(ram.used / (1024**3), 2),
            "ram_total_gb": round(ram.total / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024**3), 2),
            "system_status": status,
            "alerts": alerts
        }


class NetworkScanner:
    """Handles network diagnostics, multi-threaded port scanning, and host sweeps."""

    def __init__(self, target_host="127.0.0.1", timeout=0.8):
        self.target_host = target_host
        self.timeout = timeout

    def check_latency(self, host="8.8.8.8", port=53):
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((host, port))
            sock.close()
            latency = round((time.time() - start) * 1000, 2)
            return {"target": host, "status": "REACHABLE", "latency_ms": latency}
        except Exception:
            return {"target": host, "status": "UNREACHABLE", "latency_ms": None}

    def scan_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None

    def multi_threaded_port_scan(self, host, ports, max_threads=50):
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res is not None:
                    open_ports.append(res)
        return sorted(open_ports)

    def discover_local_subnet_hosts(self, max_threads=50):
        """Derives local IP, constructs /24 subnet, and sweeps active hosts."""
        discovered_hosts = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"

        if local_ip == "127.0.0.1":
            return [local_ip]

        subnet_base = ".".join(local_ip.split(".")[:-1])
        target_ips = [f"{subnet_base}.{i}" for i in range(1, 255)]

        def probe_host(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                res = sock.connect_ex((ip, 80))
                sock.close()
                if res == 0:
                    return ip
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = executor.map(probe_host, target_ips)
            for res in results:
                if res:
                    discovered_hosts.append(res)

        if local_ip not in discovered_hosts:
            discovered_hosts.append(local_ip)

        return sorted(discovered_hosts)


class SecurityAuditor:
    """Evaluates risk levels and security posture for open ports."""

    RISK_REGISTRY = {
        21: {"service": "FTP", "risk": "HIGH", "desc": "Unencrypted file transfer. Exposure of credentials."},
        22: {"service": "SSH", "risk": "MEDIUM", "desc": "Remote administrative access. Ensure strong keys/MFA."},
        23: {"service": "TELNET", "risk": "CRITICAL", "desc": "Cleartext transmission of administrative commands."},
        25: {"service": "SMTP", "risk": "LOW", "desc": "Mail transfer service. Check for open relay configuration."},
        80: {"service": "HTTP", "risk": "MEDIUM", "desc": "Unencrypted web service. Enforce HTTPS redirect."},
        110: {"service": "POP3", "risk": "HIGH", "desc": "Unencrypted mail retrieval protocol."},
        135: {"service": "RPC", "risk": "HIGH", "desc": "Microsoft RPC Endpoint Mapper. High attack surface."},
        139: {"service": "NetBIOS", "risk": "HIGH", "desc": "Legacy NetBIOS Session Service."},
        443: {"service": "HTTPS", "risk": "INFO", "desc": "Encrypted web communication standard."},
        445: {"service": "SMB", "risk": "CRITICAL", "desc": "Server Message Block. Target for lateral movement & ransomware."},
        3389: {"service": "RDP", "risk": "HIGH", "desc": "Remote Desktop Protocol. Vulnerable to brute-force attacks."}
    }

    def audit_open_ports(self, open_ports):
        findings = []
        for port in open_ports:
            info = self.RISK_REGISTRY.get(port, {
                "service": "UNKNOWN",
                "risk": "LOW",
                "desc": "Unrecognized or custom service listening."
            })
            findings.append({
                "port": port,
                "service": info["service"],
                "risk_level": info["risk"],
                "description": info["desc"]
            })
        return findings


class ReportEngine:
    """Generates SIEM JSON payload, HTML dashboard, and SHA-256 cryptographic hash."""

    def __init__(self, data):
        self.data = data

    def generate_json(self, filename="security_audit.json"):
        with open(filename, "w") as f:
            json.dump(self.data, f, indent=4)
        return filename

    def generate_html(self, filename="security_audit.html"):
        findings_rows = ""
        for item in self.data["security_findings"]:
            badge_class = item["risk_level"].lower()
            findings_rows += f"""
            <tr>
                <td><strong>{item['port']}</strong></td>
                <td>{item['service']}</td>
                <td><span class="badge {badge_class}">{item['risk_level']}</span></td>
                <td>{item['description']}</td>
            </tr>
            """

        if not findings_rows:
            findings_rows = "<tr><td colspan='4' style='text-align:center;'>No open ports detected in scanned range.</td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Security & Network Audit</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 20px; border-radius: 8px; border-left: 6px solid #3b82f6; margin-bottom: 20px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #334155; }}
        .card h3 {{ margin-top: 0; font-size: 0.9rem; color: #94a3b8; text-transform: uppercase; }}
        .card .metric {{ font-size: 1.8rem; font-weight: bold; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #334155; color: #f1f5f9; text-transform: uppercase; font-size: 0.8rem; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
        .badge.critical {{ background: #ef4444; color: white; }}
        .badge.high {{ background: #f97316; color: white; }}
        .badge.medium {{ background: #eab308; color: black; }}
        .badge.low {{ background: #3b82f6; color: white; }}
        .badge.info {{ background: #10b981; color: white; }}
        .hash-box {{ background: #020617; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 0.85rem; color: #a7f3d0; word-break: break-all; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Enterprise Network & Security Audit Suite</h2>
            <p>Execution Timestamp: {self.data['audit_metadata']['timestamp']} | Host: {self.data['audit_metadata']['target_host']}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>CPU Utilization</h3>
                <div class="metric">{self.data['system_metrics']['cpu_percent']}%</div>
            </div>
            <div class="card">
                <h3>RAM Utilization</h3>
                <div class="metric">{self.data['system_metrics']['ram_percent']}%</div>
            </div>
            <div class="card">
                <h3>Gateway Latency</h3>
                <div class="metric">{self.data['network_latency']['latency_ms']} ms</div>
            </div>
            <div class="card">
                <h3>Open Ports</h3>
                <div class="metric">{len(self.data['security_findings'])}</div>
            </div>
        </div>

        <h3>Security Port Analysis Findings</h3>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Risk Level</th>
                    <th>Analysis & Description</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <div class="hash-box">
            <strong>SHA-256 Report Integrity Hash:</strong><br>
            {self.data['audit_metadata']['sha256_hash']}
        </div>
    </div>
</body>
</html>
"""
        with open(filename, "w") as f:
            f.write(html_content)
        return filename

    def compute_sha256(self):
        json_str = json.dumps(self.data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(json_str).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Enterprise Network & Security Audit Suite CLI")
    parser.add_argument("--target", default="127.0.0.1", help="Target host to audit (default: 127.0.0.1)")
    parser.add_argument("--ports", default="20-1024", help="Port range to scan e.g. 20-100 or 80,443,3389 (default: 20-1024)")
    parser.add_argument("--threads", type=int, default=50, help="Max worker threads (default: 50)")
    args = parser.parse_args()

    print("\n========================================================")
    print("      ENTERPRISE NETWORK & SECURITY AUDIT SUITE         ")
    print("========================================================\n")

    # 1. System Metrics
    print("[+] Sampling System Performance & Resource Metrics...")
    sys_mon = SystemMonitor()
    sys_metrics = sys_mon.collect_metrics()
    print(f"    CPU: {sys_metrics['cpu_percent']}% | RAM: {sys_metrics['ram_percent']}% | Disk Free: {sys_metrics['disk_free_gb']} GB")

    # 2. Network Diagnostics
    net_scanner = NetworkScanner(target_host=args.target)
    print("\n[+] Benchmarking Network Gateway Latency...")
    latency_res = net_scanner.check_latency()
    print(f"    Gateway: {latency_res['target']} | Latency: {latency_res['latency_ms']} ms")

    # Parse port range
    if "-" in args.ports:
        start_p, end_p = map(int, args.ports.split("-"))
        port_list = list(range(start_p, end_p + 1))
    else:
        port_list = [int(p) for p in args.ports.split(",")]

    print(f"\n[+] Executing Multi-Threaded Port Scan ({len(port_list)} ports, {args.threads} threads) on {args.target}...")
    start_time = time.time()
    open_ports = net_scanner.multi_threaded_port_scan(args.target, port_list, max_threads=args.threads)
    scan_duration = round(time.time() - start_time, 2)
    print(f"    Scan Completed in {scan_duration}s. Open Ports Found: {open_ports}")

    # 3. Security Audit
    print("\n[+] Cross-Referencing Open Ports Against Enterprise Risk Registry...")
    auditor = SecurityAuditor()
    security_findings = auditor.audit_open_ports(open_ports)
    for finding in security_findings:
        print(f"    [!] PORT {finding['port']} ({finding['service']}) -> Risk: {finding['risk_level']}")

    # 4. Generate Audit Data Payload
    audit_data = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "target_host": args.target,
            "scan_duration_seconds": scan_duration,
            "sha256_hash": ""
        },
        "system_metrics": sys_metrics,
        "network_latency": latency_res,
        "security_findings": security_findings
    }

    # Compute Hash & Export
    engine = ReportEngine(audit_data)
    report_hash = engine.compute_sha256()
    audit_data["audit_metadata"]["sha256_hash"] = report_hash

    json_file = engine.generate_json()
    html_file = engine.generate_html()

    print("\n========================================================")
    print(f"[✔] SIEM Event Stream Saved: {json_file}")
    print(f"[✔] HTML Dashboard Generated: {html_file}")
    print(f"[🔒] SHA-256 Report Integrity Hash: {report_hash}")
    print("========================================================\n")


if __name__ == "__main__":
    main()