#!/usr/bin/env python3
"""
Network Security Scanner - Professional Portfolio Version
Author: Miguel
GitHub: https://github.com/tuusuario
Description: Advanced network scanner with multiple scan types and reporting
"""

import subprocess
import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any

class PortfolioNetworkScanner:
    """Professional network scanner for security assessments"""
    
    SCAN_PROFILES = {
        "discovery": {
            "command": "-sn",
            "description": "Host discovery only",
            "time": "Fast"
        },
        "quick": {
            "command": "-sS -T4 -F",
            "description": "Quick TCP port scan",
            "time": "Medium"
        },
        "comprehensive": {
            "command": "-sS -sV -sC -O -A",
            "description": "Comprehensive scan with OS/version detection",
            "time": "Slow"
        },
        "vulnerability": {
            "command": "-sV --script vuln,safe",
            "description": "Vulnerability assessment",
            "time": "Very Slow"
        },
        "udp": {
            "command": "-sU --top-ports 100",
            "description": "Top UDP ports scan",
            "time": "Medium"
        }
    }
    
    def __init__(self, target: str, output_dir: str = "reports"):
        self.target = target
        self.output_dir = output_dir
        self.results: Dict = {}
        
        os.makedirs(output_dir, exist_ok=True)
        self._validate_environment()
    
    def _validate_environment(self) -> None:
        """Validate required tools are installed"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                raise SystemExit("❌ Nmap not found. Install with: sudo apt install nmap")
            
            version_line = result.stdout.split('\n')[0] if result.stdout else "Nmap"
            version_parts = version_line.split()
            version = version_parts[2] if len(version_parts) > 2 else "unknown"
            print(f"✅ {version_line}")
        except subprocess.TimeoutExpired:
            print("⚠️  Nmap version check timed out")
        except FileNotFoundError:
            raise SystemExit("❌ Nmap not found. Install with: sudo apt install nmap")
    
    def scan(self, profile: str = "discovery") -> Dict:
        """Execute a network scan with specified profile"""
        
        if profile not in self.SCAN_PROFILES:
            raise ValueError(f"Invalid profile. Choose from: {list(self.SCAN_PROFILES.keys())}")
        
        profile_info = self.SCAN_PROFILES[profile]
        cmd = f"nmap {profile_info['command']} {self.target}"
        
        print(f"\n{'='*60}")
        print(f"🔍 EXECUTING: {profile.upper()} SCAN")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Profile: {profile_info['description']}")
        print(f"Estimated time: {profile_info['time']}")
        print(f"Command: {cmd}")
        print(f"{'='*60}\n")
        
        try:
            # Execute scan with increased timeout for vulnerability scans
            timeout = 900 if profile == "vulnerability" else 600  # 15 min for vuln, 10 min for others
            
            process = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Get the raw output
            stdout = process.stdout
            stderr = process.stderr
            
            # Process results
            scan_result = {
                "metadata": {
                    "target": self.target,
                    "profile": profile,
                    "timestamp": datetime.now().isoformat(),
                    "command": cmd,
                    "success": process.returncode == 0,
                    "return_code": process.returncode
                },
                "raw_output": stdout,
                "raw_errors": stderr,
                "statistics": self._parse_statistics(stdout)
            }
            
            # Save reports
            self._save_reports(scan_result, profile)
            
            # Display results
            self._display_results(scan_result)
            
            return scan_result
            
        except subprocess.TimeoutExpired:
            print(f"\n⏱️  Scan timed out after {'15' if profile == 'vulnerability' else '10'} minutes")
            # Save partial results if any
            partial_result = {
                "metadata": {
                    "target": self.target,
                    "profile": profile,
                    "timestamp": datetime.now().isoformat(),
                    "command": cmd,
                    "success": False,
                    "error": "Timeout"
                },
                "statistics": {
                    "hosts_up": 0,
                    "open_ports": [],
                    "scan_status": "timeout"
                }
            }
            self._save_reports(partial_result, profile)
            return partial_result
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            return {}
    
    def _parse_statistics(self, output: str) -> Dict:
        """Parse scan statistics from nmap output - CORRECTED VERSION"""
        stats = {
            "hosts_up": 0,
            "open_ports": [],
            "services": [],
            "scan_status": "unknown",
            "vulnerabilities": []
        }
        
        if not output:
            stats["scan_status"] = "no_output"
            return stats
        
        lines = output.split('\n')
        
        # Track if we're currently processing a host
        current_host = None
        in_port_section = False
        
        for line in lines:
            # Normalize line for case-insensitive matching
            line_lower = line.lower()
            
            # 1. Check for host status
            if "nmap scan report for" in line_lower:
                stats["hosts_up"] = 1
                stats["scan_status"] = "host_found"
                current_host = line.replace("Nmap scan report for", "").strip()
            elif "host is up" in line_lower or "up" in line_lower and "host" in line_lower:
                stats["hosts_up"] = 1
                stats["scan_status"] = "host_up"
            elif "0 hosts up" in line_lower or "host seems down" in line_lower:
                stats["hosts_up"] = 0
                stats["scan_status"] = "host_down"
            
            # 2. Look for port sections
            if "port" in line_lower and "state" in line_lower and "service" in line_lower:
                in_port_section = True
                continue
            
            # 3. Parse port lines (only if in port section)
            if in_port_section and line.strip() and not line.startswith("Nmap") and not line.startswith("|"):
                # Check for common port patterns: "80/tcp", "443/ssl", etc.
                parts = line.split()
                if len(parts) >= 2 and ("/tcp" in parts[0].lower() or "/udp" in parts[0].lower()):
                    port_protocol = parts[0]
                    state = parts[1]
                    
                    if state.lower() == "open":
                        port_info = {
                            "port": port_protocol.split('/')[0],
                            "protocol": port_protocol.split('/')[1] if '/' in port_protocol else "tcp",
                            "state": state,
                            "service": parts[2] if len(parts) > 2 else "unknown"
                        }
                        
                        # Try to get more service info from following lines
                        idx = lines.index(line)
                        for i in range(1, 4):
                            if idx + i < len(lines):
                                next_line = lines[idx + i].strip()
                                if next_line and not any(x in next_line.lower() for x in ["nmap", "port", "service", "state"]):
                                    if "service" not in port_info or port_info["service"] == "unknown":
                                        port_info["service"] = next_line
                                    elif "version" in next_line.lower() or "product" in next_line.lower():
                                        port_info["version"] = next_line
                        
                        stats["open_ports"].append(port_info)
            
            # 4. Look for end of port section
            if in_port_section and (line.startswith("Nmap") or "read data files" in line_lower or not line.strip()):
                in_port_section = False
            
            # 5. Look for vulnerability findings
            if any(vuln_keyword in line_lower for vuln_keyword in ["vuln", "cve-", "vulnerability", "risk", "exploit"]):
                if line.strip():
                    stats["vulnerabilities"].append(line.strip())
        
        # 6. Fallback: If we found open ports but no host detection, assume host is up
        if stats["hosts_up"] == 0 and stats["open_ports"]:
            stats["hosts_up"] = 1
            stats["scan_status"] = "implied_host_up"
        
        # 7. If no status was determined, check for common patterns
        if stats["scan_status"] == "unknown":
            if "scan report" in output.lower():
                stats["scan_status"] = "completed"
            elif "nmap done" in output.lower():
                stats["scan_status"] = "completed_no_hosts"
        
        return stats
    
    def _save_reports(self, result: Dict, profile: str) -> None:
        """Save scan reports in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace('/', '_').replace('.', '_')
        base_name = f"{self.output_dir}/{safe_target}_{profile}_{timestamp}"
        
        # Save raw output
        with open(f"{base_name}.txt", 'w') as f:
            f.write(f"Network Security Scan Report\n")
            f.write(f"{'='*60}\n")
            f.write(f"Target: {result['metadata']['target']}\n")
            f.write(f"Profile: {result['metadata']['profile']}\n")
            f.write(f"Timestamp: {result['metadata']['timestamp']}\n")
            f.write(f"Command: {result['metadata']['command']}\n")
            f.write(f"Success: {result['metadata']['success']}\n")
            f.write(f"{'='*60}\n\n")
            
            if 'raw_output' in result and result['raw_output']:
                f.write(result['raw_output'])
            else:
                f.write("No scan output available\n")
            
            if 'raw_errors' in result and result['raw_errors']:
                f.write(f"\n{'='*60}\nERRORS/ADVERTENCIAS:\n{'='*60}\n")
                f.write(result['raw_errors'])
        
        # Save JSON report
        with open(f"{base_name}.json", 'w') as f:
            json.dump(result, f, indent=4, default=str)
        
        # Save summary markdown
        self._save_markdown_summary(result, f"{base_name}.md")
        
        # Save HTML report
        self._save_html_report(result, f"{base_name}_report.html")
        
        print(f"\n📁 Reports saved:")
        print(f"  📄 {base_name}.txt")
        print(f"  📊 {base_name}.json")
        print(f"  📋 {base_name}.md")
        print(f"  🌐 {base_name}_report.html")
    
    def _save_markdown_summary(self, result: Dict, filename: str) -> None:
        """Generate a markdown summary report"""
        metadata = result.get('metadata', {})
        stats = result.get('statistics', {})
        
        with open(filename, 'w') as f:
            f.write(f"# Network Security Scan Report\n\n")
            f.write(f"## Scan Details\n")
            f.write(f"- **Target**: {metadata.get('target', 'Unknown')}\n")
            f.write(f"- **Profile**: {metadata.get('profile', 'Unknown')}\n")
            f.write(f"- **Timestamp**: {metadata.get('timestamp', 'Unknown')}\n")
            f.write(f"- **Status**: {'✅ Success' if metadata.get('success') else '❌ Failed'}\n")
            f.write(f"- **Command**: `{metadata.get('command', 'Unknown')}`\n\n")
            
            f.write(f"## Statistics\n")
            f.write(f"- **Hosts Found**: {stats.get('hosts_up', 0)}\n")
            f.write(f"- **Open Ports**: {len(stats.get('open_ports', []))}\n")
            f.write(f"- **Scan Status**: {stats.get('scan_status', 'unknown')}\n\n")
            
            if stats.get('open_ports'):
                f.write(f"## Open Ports\n")
                f.write(f"| Port | Protocol | State | Service |\n")
                f.write(f"|------|----------|-------|---------|\n")
                for port in stats.get('open_ports', []):
                    f.write(f"| {port.get('port', 'N/A')} | {port.get('protocol', 'tcp')} | {port.get('state', 'unknown')} | {port.get('service', 'unknown')} |\n")
                f.write(f"\n")
            
            if stats.get('vulnerabilities'):
                f.write(f"## Potential Vulnerabilities\n")
                for vuln in stats.get('vulnerabilities', []):
                    f.write(f"- {vuln}\n")
                f.write(f"\n")
            
            f.write(f"## Raw Output\n")
            f.write(f"Full scan output is available in the corresponding .txt file.\n")
    
    def _save_html_report(self, result: Dict, filename: str) -> None:
        """Generate an HTML report"""
        metadata = result.get('metadata', {})
        stats = result.get('statistics', {})
        
        profile = metadata.get('profile', 'unknown')
        profile_badge_class = f"badge-{profile}"
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Network Scan Report - {metadata.get('target', 'Unknown')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }}
        
        body {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(90deg, #2c3e50, #4a6491);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-top: 10px;
        }}
        
        .badge-discovery {{ background: #17a2b8; }}
        .badge-quick {{ background: #28a745; }}
        .badge-comprehensive {{ background: #ffc107; color: #000; }}
        .badge-vulnerability {{ background: #dc3545; }}
        .badge-udp {{ background: #6f42c1; }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .info-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            border-left: 5px solid #667eea;
        }}
        
        .results-section {{
            padding: 30px;
        }}
        
        .stats-box {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-item {{
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }}
        
        .stat-label {{
            color: #6c757d;
            margin-top: 5px;
        }}
        
        .ports-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .ports-table th {{
            background: #2c3e50;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        
        .ports-table td {{
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .port-open {{
            color: #28a745;
            font-weight: bold;
        }}
        
        .vuln-list {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}
        
        .vuln-item {{
            padding: 10px;
            border-bottom: 1px solid #ffc107;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 30px;
        }}
        
        @media (max-width: 768px) {{
            .info-grid {{
                grid-template-columns: 1fr;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Network Security Scan Report</h1>
            <div class="badge {profile_badge_class}">{profile.upper()}</div>
        </div>
        
        <div class="info-grid">
            <div class="info-card">
                <h3><i class="fas fa-bullseye"></i> Target</h3>
                <p>{metadata.get('target', 'Unknown')}</p>
            </div>
            
            <div class="info-card">
                <h3><i class="fas fa-calendar-alt"></i> Scan Date</h3>
                <p>{metadata.get('timestamp', 'Unknown').split('T')[0]}</p>
            </div>
            
            <div class="info-card">
                <h3><i class="fas fa-tasks"></i> Scan Status</h3>
                <p>{'✅ Success' if metadata.get('success') else '❌ Failed'}</p>
            </div>
            
            <div class="info-card">
                <h3><i class="fas fa-clock"></i> Report Generated</h3>
                <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
        
        <div class="results-section">
            <div class="stats-box">
                <h2><i class="fas fa-chart-bar"></i> Scan Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value">{stats.get('hosts_up', 0)}</div>
                        <div class="stat-label">Hosts Found</div>
                    </div>
                    
                    <div class="stat-item">
                        <div class="stat-value">{len(stats.get('open_ports', []))}</div>
                        <div class="stat-label">Open Ports</div>
                    </div>
                    
                    <div class="stat-item">
                        <div class="stat-value">{len(stats.get('vulnerabilities', []))}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                    
                    <div class="stat-item">
                        <div class="stat-value">{stats.get('scan_status', 'unknown').replace('_', ' ').title()}</div>
                        <div class="stat-label">Scan Status</div>
                    </div>
                </div>
            </div>
            
            {self._generate_ports_html(stats.get('open_ports', []))}
            {self._generate_vulnerabilities_html(stats.get('vulnerabilities', []))}
        </div>
        
        <div class="footer">
            <p>Generated with <i class="fas fa-heart" style="color: #e74c3c;"></i> by Advanced Network Scanner</p>
            <p style="color: #95a5a6; font-size: 0.9em; margin-top: 5px;">
                Security Tool v1.0 • Report ID: {datetime.now().strftime('%Y%m%d%H%M%S')}
            </p>
        </div>
    </div>
    
    <script>
        // Simple interactivity
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('Network Scan Report loaded');
            
            // Add click handlers to port rows
            document.querySelectorAll('.ports-table tbody tr').forEach(row => {{
                row.addEventListener('click', function() {{
                    this.classList.toggle('selected');
                }});
            }});
        }});
    </script>
</body>
</html>"""
        
        # Add Font Awesome for icons
        html = html.replace('<head>', '<head>\n    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">')
        
        with open(filename, 'w') as f:
            f.write(html)
    
    def _generate_ports_html(self, ports: List[Dict]) -> str:
        """Generate HTML for ports table"""
        if not ports:
            return '<h2><i class="fas fa-plug"></i> Open Ports</h2><p>No open ports found.</p>'
        
        html = '<h2><i class="fas fa-plug"></i> Open Ports</h2>'
        html += '<table class="ports-table">'
        html += '<thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th></tr></thead>'
        html += '<tbody>'
        
        for port in ports:
            state_class = 'port-open' if port.get('state') == 'open' else ''
            html += f'<tr>'
            html += f'<td>{port.get("port", "")}</td>'
            html += f'<td>{port.get("protocol", "tcp")}</td>'
            html += f'<td class="{state_class}">{port.get("state", "")}</td>'
            html += f'<td>{port.get("service", "unknown")}</td>'
            html += '</tr>'
        
        html += '</tbody></table>'
        return html
    
    def _generate_vulnerabilities_html(self, vulnerabilities: List[str]) -> str:
        """Generate HTML for vulnerabilities list"""
        if not vulnerabilities:
            return ''
        
        html = '<h2><i class="fas fa-exclamation-triangle"></i> Potential Vulnerabilities</h2>'
        html += '<div class="vuln-list">'
        
        for vuln in vulnerabilities[:10]:  # Limit to first 10
            html += f'<div class="vuln-item">{vuln}</div>'
        
        if len(vulnerabilities) > 10:
            html += f'<div class="vuln-item">... and {len(vulnerabilities) - 10} more</div>'
        
        html += '</div>'
        return html
    
    def _display_results(self, result: Dict) -> None:
        """Display scan results in console"""
        metadata = result.get('metadata', {})
        stats = result.get('statistics', {})
        
        print(f"\n{'='*60}")
        print(f"📊 SCAN RESULTS")
        print(f"{'='*60}")
        
        if stats.get('hosts_up', 0) > 0:
            print(f"✅ Hosts Found: {stats['hosts_up']}")
            
            if stats.get('open_ports'):
                print(f"\n🔓 Open Ports ({len(stats['open_ports'])}):")
                for port in stats['open_ports'][:5]:  # Show first 5
                    service = port.get('service', 'unknown')
                    if len(service) > 30:
                        service = service[:27] + "..."
                    print(f"  - Port {port.get('port')}/{port.get('protocol', 'tcp')}: {service}")
                
                if len(stats['open_ports']) > 5:
                    print(f"  ... and {len(stats['open_ports']) - 5} more")
            else:
                print(f"🔒 No open ports found")
        else:
            print(f"❌ No hosts found")
        
        if stats.get('vulnerabilities'):
            print(f"\n⚠️  Potential Vulnerabilities Found: {len(stats['vulnerabilities'])}")
            for vuln in stats['vulnerabilities'][:3]:  # Show first 3
                if len(vuln) > 60:
                    vuln = vuln[:57] + "..."
                print(f"  - {vuln}")
            
            if len(stats['vulnerabilities']) > 3:
                print(f"  ... and {len(stats['vulnerabilities']) - 3} more")
        
        print(f"\n📈 Scan Status: {stats.get('scan_status', 'unknown').replace('_', ' ').title()}")
        print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(
        description="Professional Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24              # Discover hosts
  %(prog)s 192.168.1.1 --profile quick # Quick port scan
  %(prog)s example.com --profile comprehensive
  
Scan Profiles:
  discovery      - Find active hosts only
  quick          - Fast TCP port scan
  comprehensive  - Full scan with OS/version detection
  vulnerability  - Vulnerability assessment
  udp            - Top UDP ports scan
        """
    )
    
    parser.add_argument("target", help="Target IP, range, or domain")
    parser.add_argument("--profile", "-p", 
                       choices=list(PortfolioNetworkScanner.SCAN_PROFILES.keys()),
                       default="discovery",
                       help="Scan profile to use")
    parser.add_argument("--output", "-o",
                       default="reports",
                       help="Output directory for reports")
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("🔒 NETWORK SECURITY SCANNER - PORTFOLIO VERSION")
    print("="*60)
    
    scanner = PortfolioNetworkScanner(args.target, args.output)
    scanner.scan(args.profile)

if __name__ == "__main__":
    main()
