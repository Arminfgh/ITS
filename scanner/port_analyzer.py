"""
SecureOffice Hub - Port Analyzer
Analysiert offene Ports detailliert
"""

from typing import Dict, List
import socket


class PortAnalyzer:
    """Analysiert Ports und Services"""
    
    def __init__(self):
        self.well_known_ports = self._load_port_database()
    
    def _load_port_database(self) -> Dict:
        """Port-Datenbank"""
        return {
            20: {'name': 'FTP-DATA', 'type': 'File Transfer', 'risk': 'HIGH'},
            21: {'name': 'FTP', 'type': 'File Transfer', 'risk': 'CRITICAL'},
            22: {'name': 'SSH', 'type': 'Remote Access', 'risk': 'MEDIUM'},
            23: {'name': 'Telnet', 'type': 'Remote Access', 'risk': 'CRITICAL'},
            25: {'name': 'SMTP', 'type': 'Mail', 'risk': 'MEDIUM'},
            53: {'name': 'DNS', 'type': 'Name Resolution', 'risk': 'LOW'},
            80: {'name': 'HTTP', 'type': 'Web', 'risk': 'MEDIUM'},
            110: {'name': 'POP3', 'type': 'Mail', 'risk': 'MEDIUM'},
            143: {'name': 'IMAP', 'type': 'Mail', 'risk': 'MEDIUM'},
            443: {'name': 'HTTPS', 'type': 'Web Secure', 'risk': 'LOW'},
            445: {'name': 'SMB', 'type': 'File Sharing', 'risk': 'CRITICAL'},
            465: {'name': 'SMTPS', 'type': 'Mail Secure', 'risk': 'LOW'},
            587: {'name': 'SMTP', 'type': 'Mail Submission', 'risk': 'MEDIUM'},
            993: {'name': 'IMAPS', 'type': 'Mail Secure', 'risk': 'LOW'},
            995: {'name': 'POP3S', 'type': 'Mail Secure', 'risk': 'LOW'},
            1433: {'name': 'MSSQL', 'type': 'Database', 'risk': 'HIGH'},
            3306: {'name': 'MySQL', 'type': 'Database', 'risk': 'HIGH'},
            3389: {'name': 'RDP', 'type': 'Remote Desktop', 'risk': 'HIGH'},
            5432: {'name': 'PostgreSQL', 'type': 'Database', 'risk': 'HIGH'},
            5900: {'name': 'VNC', 'type': 'Remote Desktop', 'risk': 'HIGH'},
            8080: {'name': 'HTTP-Alt', 'type': 'Web', 'risk': 'MEDIUM'},
            8443: {'name': 'HTTPS-Alt', 'type': 'Web Secure', 'risk': 'LOW'},
        }
    
    def analyze_port(self, port: int, service: str = None) -> Dict:
        """Analysiert einzelnen Port"""
        
        port_info = self.well_known_ports.get(port, {
            'name': service or 'Unknown',
            'type': 'Unknown',
            'risk': 'UNKNOWN'
        })
        
        return {
            'port': port,
            'service_name': port_info['name'],
            'service_type': port_info['type'],
            'risk_level': port_info['risk'],
            'common_uses': self._get_common_uses(port),
            'security_notes': self._get_security_notes(port),
            'recommended_action': self._get_recommendation(port)
        }
    
    def analyze_all_ports(self, scan_results: List[Dict]) -> Dict:
        """Analysiert alle gefundenen Ports"""
        
        analysis = {
            'total_ports': 0,
            'by_risk': {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'UNKNOWN': []},
            'by_type': {},
            'detailed_analysis': []
        }
        
        for host in scan_results:
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                analysis['total_ports'] += 1
                
                # Detailanalyse
                port_analysis = self.analyze_port(port, service)
                port_analysis['host'] = host.get('ip_address')
                port_analysis['hostname'] = host.get('hostname')
                
                analysis['detailed_analysis'].append(port_analysis)
                
                # Gruppiere nach Risk
                risk = port_analysis['risk_level']
                analysis['by_risk'][risk].append(port_analysis)
                
                # Gruppiere nach Type
                svc_type = port_analysis['service_type']
                if svc_type not in analysis['by_type']:
                    analysis['by_type'][svc_type] = []
                analysis['by_type'][svc_type].append(port_analysis)
        
        return analysis
    
    def _get_common_uses(self, port: int) -> List[str]:
        """Häufige Verwendung"""
        uses = {
            21: ["Datei-Upload/-Download", "FTP-Server", "Legacy File Transfer"],
            22: ["SSH-Zugriff", "SFTP", "Secure Shell"],
            23: ["Legacy Remote Access", "Terminal-Zugriff"],
            80: ["Webserver", "HTTP-Traffic", "APIs"],
            443: ["HTTPS Webserver", "Sichere APIs", "TLS/SSL"],
            445: ["Windows File Sharing", "SMB", "Network Shares"],
            3306: ["MySQL Datenbank", "MariaDB"],
            3389: ["Windows Remote Desktop", "RDP-Verbindungen"]
        }
        return uses.get(port, ["Unbekannte Verwendung"])
    
    def _get_security_notes(self, port: int) -> List[str]:
        """Sicherheitshinweise"""
        notes = {
            21: ["Unverschlüsselt!", "Credentials im Klartext", "Anfällig für Sniffing"],
            23: ["EXTREM unsicher!", "Keine Verschlüsselung", "Niemals verwenden!"],
            80: ["Unverschlüsselt", "HTTPS bevorzugen", "MITM-Angriffe möglich"],
            445: ["EternalBlue Risiko", "SMBv1 deaktivieren", "Patches wichtig"],
            3306: ["Nicht exponieren", "Bind to localhost", "Starke Passwörter"],
            3389: ["BlueKeep Vulnerability", "Brute-Force Risiko", "VPN empfohlen"]
        }
        return notes.get(port, ["Standard Security Practices anwenden"])
    
    def _get_recommendation(self, port: int) -> str:
        """Empfehlung"""
        recs = {
            21: "SFTP (Port 22) verwenden statt FTP",
            23: "SSH (Port 22) verwenden, Telnet deaktivieren!",
            80: "HTTPS (Port 443) erzwingen, HTTP-Redirect",
            445: "SMBv1 deaktivieren, Firewall-Regeln, Patches",
            3306: "Nur localhost-Binding, VPN für Remote-Access",
            3389: "VPN-only, NLA aktivieren, MFA verwenden"
        }
        return recs.get(port, "Security Best Practices befolgen")
    
    def get_port_statistics(self, analysis: Dict) -> str:
        """Statistik-Report"""
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    PORT ANALYSIS STATISTICS                      ║
╚══════════════════════════════════════════════════════════════════╝

📊 GESAMTÜBERSICHT:
   Total offene Ports: {analysis['total_ports']}

🚦 NACH RISIKO:
   🔴 CRITICAL: {len(analysis['by_risk']['CRITICAL'])}
   🟠 HIGH:     {len(analysis['by_risk']['HIGH'])}
   🟡 MEDIUM:   {len(analysis['by_risk']['MEDIUM'])}
   🟢 LOW:      {len(analysis['by_risk']['LOW'])}

📁 NACH SERVICE-TYP:
"""
        
        for svc_type, ports in analysis['by_type'].items():
            report += f"   • {svc_type}: {len(ports)} Port(s)\n"
        
        report += "\n🔍 KRITISCHE PORTS:\n"
        for port_info in analysis['by_risk']['CRITICAL']:
            report += f"""
   Port {port_info['port']}: {port_info['service_name']}
   Host: {port_info['host']} ({port_info['hostname']})
   → {port_info['recommended_action']}
"""
        
        return report


if __name__ == "__main__":
    print("🔌 Teste Port Analyzer...\n")
    
    analyzer = PortAnalyzer()
    
    # Test einzelner Port
    print("="*70)
    print("TEST: Einzelner Port (Port 23 - Telnet)")
    print("="*70)
    
    port_info = analyzer.analyze_port(23, "Telnet")
    print(f"Port: {port_info['port']}")
    print(f"Service: {port_info['service_name']}")
    print(f"Risk: {port_info['risk_level']}")
    print(f"Empfehlung: {port_info['recommended_action']}")
    
    # Test komplette Analyse
    print("\n" + "="*70)
    print("TEST: Komplette Port-Analyse")
    print("="*70)
    
    mock_scan = [
        {
            'ip_address': '192.168.1.10',
            'hostname': 'server1',
            'open_ports': [
                {'port': 21, 'service': 'FTP'},
                {'port': 23, 'service': 'Telnet'},
                {'port': 445, 'service': 'SMB'}
            ]
        }
    ]
    
    analysis = analyzer.analyze_all_ports(mock_scan)
    print(analyzer.get_port_statistics(analysis))
    
    print("\n✅ Port Analyzer Test OK!")