"""
SecureOffice Hub - OSI Model Analyzer
Analysiert Netzwerk-Traffic und ordnet ihn den OSI-Layern zu
Demonstriert Verständnis des OSI-Modells
"""

import socket
import struct
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class OSILayer(Enum):
    """OSI-Modell Layers"""
    PHYSICAL = 1      # Physikalische Schicht - Bits, Kabel
    DATA_LINK = 2     # Sicherungsschicht - MAC, Ethernet, Switches
    NETWORK = 3       # Vermittlungsschicht - IP, Routing
    TRANSPORT = 4     # Transportschicht - TCP/UDP, Ports
    SESSION = 5       # Sitzungsschicht - Session Management
    PRESENTATION = 6  # Darstellungsschicht - Encryption, Encoding
    APPLICATION = 7   # Anwendungsschicht - HTTP, FTP, SSH


@dataclass
class OSIAnalysis:
    """Ergebnis der OSI-Analyse"""
    layer: OSILayer
    protocol: str
    description: str
    data: Dict
    security_relevance: str
    vulnerabilities: List[str]


class OSIAnalyzer:
    """
    Analysiert Netzwerk-Kommunikation nach OSI-Modell
    """
    
    def __init__(self):
        self.analysis_results = []
        
        # OSI Layer Definitions mit Security-Kontext
        self.layer_info = {
            OSILayer.PHYSICAL: {
                "name": "Physical Layer (Layer 1)",
                "protocols": ["Ethernet", "WiFi", "Fiber"],
                "security_concerns": [
                    "Physical access to cables (Wiretapping)",
                    "Signal interference",
                    "Unauthorized physical connections"
                ],
                "security_measures": [
                    "Physical access control",
                    "Cable encryption",
                    "Signal monitoring"
                ]
            },
            OSILayer.DATA_LINK: {
                "name": "Data Link Layer (Layer 2)",
                "protocols": ["Ethernet", "MAC", "ARP", "Switch"],
                "security_concerns": [
                    "MAC spoofing",
                    "ARP poisoning attacks",
                    "VLAN hopping",
                    "Switch port attacks"
                ],
                "security_measures": [
                    "Port security",
                    "Dynamic ARP Inspection (DAI)",
                    "VLAN segmentation",
                    "802.1X authentication"
                ]
            },
            OSILayer.NETWORK: {
                "name": "Network Layer (Layer 3)",
                "protocols": ["IP", "ICMP", "IPSec", "Router"],
                "security_concerns": [
                    "IP spoofing",
                    "ICMP floods (Ping of Death)",
                    "Routing attacks",
                    "Man-in-the-middle"
                ],
                "security_measures": [
                    "IPSec encryption",
                    "Access Control Lists (ACLs)",
                    "Router hardening",
                    "Anti-spoofing filters"
                ]
            },
            OSILayer.TRANSPORT: {
                "name": "Transport Layer (Layer 4)",
                "protocols": ["TCP", "UDP", "Port numbers"],
                "security_concerns": [
                    "Port scanning",
                    "SYN flooding (DoS)",
                    "Session hijacking",
                    "Open unnecessary ports"
                ],
                "security_measures": [
                    "Firewall port filtering",
                    "SYN cookies",
                    "Port knocking",
                    "Close unused ports"
                ]
            },
            OSILayer.SESSION: {
                "name": "Session Layer (Layer 5)",
                "protocols": ["NetBIOS", "RPC", "PPTP"],
                "security_concerns": [
                    "Session hijacking",
                    "Session replay attacks",
                    "Unauthorized session access"
                ],
                "security_measures": [
                    "Session tokens",
                    "Session timeout",
                    "Mutual authentication",
                    "Session encryption"
                ]
            },
            OSILayer.PRESENTATION: {
                "name": "Presentation Layer (Layer 6)",
                "protocols": ["SSL/TLS", "JPEG", "ASCII", "Encryption"],
                "security_concerns": [
                    "Weak encryption",
                    "Data format exploits",
                    "Certificate issues",
                    "Encoding attacks"
                ],
                "security_measures": [
                    "Strong encryption (AES-256)",
                    "Valid SSL/TLS certificates",
                    "Secure encoding",
                    "Certificate pinning"
                ]
            },
            OSILayer.APPLICATION: {
                "name": "Application Layer (Layer 7)",
                "protocols": ["HTTP", "HTTPS", "FTP", "SSH", "DNS", "SMTP"],
                "security_concerns": [
                    "SQL injection",
                    "XSS attacks",
                    "Brute force attacks",
                    "Malware downloads",
                    "Phishing"
                ],
                "security_measures": [
                    "Input validation",
                    "WAF (Web Application Firewall)",
                    "Rate limiting",
                    "HTTPS enforcement",
                    "Security headers"
                ]
            }
        }
    
    def analyze_port_communication(self, port: int, service: str) -> List[OSIAnalysis]:
        """
        Analysiert einen Port und seine Kommunikation über alle OSI-Layer
        
        Args:
            port: Port-Nummer
            service: Service-Name (z.B. "HTTP", "SSH")
        
        Returns:
            Liste von OSI-Analysen für alle relevanten Layer
        """
        analyses = []
        
        # Layer 1: Physical
        analyses.append(OSIAnalysis(
            layer=OSILayer.PHYSICAL,
            protocol="Ethernet/WiFi",
            description=f"Physikalische Übertragung der Daten für Port {port}",
            data={
                "medium": "Copper/Fiber/Wireless",
                "signal_type": "Electrical/Optical/Radio"
            },
            security_relevance="🔴 CRITICAL: Physical layer kann abgehört werden",
            vulnerabilities=[
                "Wiretapping möglich ohne Verschlüsselung",
                "Physical access ermöglicht komplette Überwachung"
            ]
        ))
        
        # Layer 2: Data Link
        analyses.append(OSIAnalysis(
            layer=OSILayer.DATA_LINK,
            protocol="Ethernet/MAC",
            description=f"MAC-Adress-basierte Übertragung im lokalen Netzwerk",
            data={
                "frame_type": "Ethernet II",
                "addressing": "MAC addresses"
            },
            security_relevance="🟡 MEDIUM: ARP-Angriffe möglich",
            vulnerabilities=[
                "ARP spoofing kann Traffic umleiten",
                "MAC flooding kann Switch überlasten",
                "VLAN hopping bei falscher Konfiguration"
            ]
        ))
        
        # Layer 3: Network
        analyses.append(OSIAnalysis(
            layer=OSILayer.NETWORK,
            protocol="IP",
            description=f"IP-basiertes Routing zwischen Netzwerken",
            data={
                "protocol": "IPv4/IPv6",
                "routing": "Router-based"
            },
            security_relevance="🔴 HIGH: IP-Spoofing und Routing-Angriffe",
            vulnerabilities=[
                "IP-Spoofing kann Quelle verschleiern",
                "ICMP-Angriffe (Ping of Death, Smurf)",
                "Routing-Manipulation möglich"
            ]
        ))
        
        # Layer 4: Transport
        protocol = "TCP" if port not in [53, 123, 161] else "UDP"
        analyses.append(OSIAnalysis(
            layer=OSILayer.TRANSPORT,
            protocol=protocol,
            description=f"Port {port} nutzt {protocol} für zuverlässige/schnelle Übertragung",
            data={
                "port": port,
                "protocol": protocol,
                "service": service
            },
            security_relevance=self._get_port_risk(port),
            vulnerabilities=self._get_port_vulnerabilities(port, service)
        ))
        
        # Layer 5: Session
        analyses.append(OSIAnalysis(
            layer=OSILayer.SESSION,
            protocol="Session Management",
            description=f"Session-Management für {service}",
            data={
                "service": service,
                "session_type": "Stateful" if protocol == "TCP" else "Stateless"
            },
            security_relevance="🟡 MEDIUM: Session-Angriffe möglich",
            vulnerabilities=[
                "Session hijacking wenn keine Verschlüsselung",
                "Session replay attacks möglich",
                "Fehlende session timeouts"
            ]
        ))
        
        # Layer 6: Presentation
        encryption_status = self._check_encryption(port, service)
        analyses.append(OSIAnalysis(
            layer=OSILayer.PRESENTATION,
            protocol=encryption_status['protocol'],
            description=encryption_status['description'],
            data=encryption_status['data'],
            security_relevance=encryption_status['risk'],
            vulnerabilities=encryption_status['vulnerabilities']
        ))
        
        # Layer 7: Application
        app_analysis = self._analyze_application_layer(port, service)
        analyses.append(OSIAnalysis(
            layer=OSILayer.APPLICATION,
            protocol=service,
            description=app_analysis['description'],
            data=app_analysis['data'],
            security_relevance=app_analysis['risk'],
            vulnerabilities=app_analysis['vulnerabilities']
        ))
        
        return analyses
    
    def _get_port_risk(self, port: int) -> str:
        """Bewertet Risiko eines Ports"""
        critical_ports = [21, 23, 445, 3389]
        high_ports = [22, 3306, 5432, 1433]
        
        if port in critical_ports:
            return "🔴 CRITICAL: Hochriskanter Port"
        elif port in high_ports:
            return "🟠 HIGH: Sensitiver Port"
        elif port in [80, 8080]:
            return "🟡 MEDIUM: Unverschlüsselter Web-Traffic"
        else:
            return "🟢 LOW: Standard-Port"
    
    def _get_port_vulnerabilities(self, port: int, service: str) -> List[str]:
        """Gibt bekannte Vulnerabilities für einen Port zurück"""
        vuln_db = {
            21: ["Unencrypted FTP - credentials in plaintext", "Bounce attacks"],
            22: ["Brute-force attacks", "Weak SSH configurations"],
            23: ["CRITICAL: Telnet completely unencrypted", "Credential theft"],
            80: ["HTTP - no encryption", "Man-in-the-middle"],
            443: ["SSL/TLS misconfiguration", "Expired certificates"],
            445: ["EternalBlue (MS17-010)", "SMB exploits"],
            3306: ["MySQL remote access", "Default credentials"],
            3389: ["RDP brute-force", "BlueKeep vulnerability"]
        }
        return vuln_db.get(port, ["Port scanning detection", "DoS potential"])
    
    def _check_encryption(self, port: int, service: str) -> Dict:
        """Prüft Verschlüsselungsstatus"""
        encrypted_ports = {443, 22, 993, 995, 465}
        
        if port in encrypted_ports:
            return {
                'protocol': 'TLS/SSL',
                'description': f'{service} nutzt Verschlüsselung',
                'data': {
                    'encrypted': True,
                    'protocol': 'TLS 1.2/1.3',
                    'cipher': 'AES-256-GCM'
                },
                'risk': '🟢 LOW: Verschlüsselte Kommunikation',
                'vulnerabilities': [
                    'Nur bei schwachen Ciphers gefährdet',
                    'Certificate validation wichtig'
                ]
            }
        else:
            return {
                'protocol': 'PLAINTEXT',
                'description': f'{service} überträgt UNVERSCHLÜSSELT',
                'data': {
                    'encrypted': False,
                    'protocol': 'None',
                    'cipher': 'None'
                },
                'risk': '🔴 CRITICAL: Keine Verschlüsselung!',
                'vulnerabilities': [
                    'CRITICAL: Alle Daten lesbar (Plaintext)',
                    'Credentials können abgefangen werden',
                    'Man-in-the-middle attacks möglich',
                    'DSGVO-Verletzung bei personenbezogenen Daten'
                ]
            }
    
    def _analyze_application_layer(self, port: int, service: str) -> Dict:
        """Analysiert Application Layer (Layer 7)"""
        app_risks = {
            'HTTP': {
                'description': 'Unverschlüsselter Web-Traffic',
                'data': {'protocol': 'HTTP/1.1', 'methods': ['GET', 'POST']},
                'risk': '🟡 MEDIUM: Unverschlüsselt',
                'vulnerabilities': [
                    'Session cookie theft',
                    'Form data interception',
                    'Enforce HTTPS stattdessen'
                ]
            },
            'HTTPS': {
                'description': 'Verschlüsselter Web-Traffic',
                'data': {'protocol': 'HTTP/2 over TLS', 'security': 'Strong'},
                'risk': '🟢 LOW: Gut gesichert',
                'vulnerabilities': [
                    'Certificate validation wichtig',
                    'HSTS Header verwenden'
                ]
            },
            'SSH': {
                'description': 'Verschlüsselte Remote-Administration',
                'data': {'protocol': 'SSH-2', 'key_based': True},
                'risk': '🟢 LOW: Sicher wenn konfiguriert',
                'vulnerabilities': [
                    'Brute-force bei Password-Auth',
                    'Key-based Authentication empfohlen'
                ]
            },
            'FTP': {
                'description': 'Unverschlüsselter Dateitransfer',
                'data': {'protocol': 'FTP', 'encryption': False},
                'risk': '🔴 CRITICAL: Völlig unsicher',
                'vulnerabilities': [
                    'CRITICAL: Credentials in Plaintext',
                    'Dateiinhalte unverschlüsselt',
                    'SFTP/FTPS verwenden!'
                ]
            },
            'Telnet': {
                'description': 'Unverschlüsselter Remote-Zugriff',
                'data': {'protocol': 'Telnet', 'encryption': False},
                'risk': '🔴 CRITICAL: Extrem gefährlich',
                'vulnerabilities': [
                    'CRITICAL: Komplette Session lesbar',
                    'Credentials direkt abfangbar',
                    'SSH stattdessen verwenden!'
                ]
            }
        }
        
        return app_risks.get(service, {
            'description': f'{service} Application Layer Protocol',
            'data': {'protocol': service},
            'risk': '🟡 UNKNOWN: Unbekanntes Protokoll',
            'vulnerabilities': ['Unbekannte Risiken - genauer untersuchen']
        })
    
    def generate_osi_report(self, port: int, service: str) -> str:
        """
        Generiert detaillierten OSI-Layer Report
        """
        analyses = self.analyze_port_communication(port, service)
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║           OSI MODEL ANALYSIS - Port {port} ({service})
╚══════════════════════════════════════════════════════════════════╝

📊 VOLLSTÄNDIGE OSI-LAYER ANALYSE:
"""
        
        for analysis in analyses:
            report += f"""
┌─ {self.layer_info[analysis.layer]['name']} ─────────────────────
│ Protocol: {analysis.protocol}
│ {analysis.description}
│
│ Security Relevance: {analysis.security_relevance}
│
│ Vulnerabilities:
"""
            for vuln in analysis.vulnerabilities:
                report += f"│   • {vuln}\n"
            
            report += "└────────────────────────────────────────────────────────\n"
        
        # Sicherheits-Zusammenfassung
        report += f"""
╔══════════════════════════════════════════════════════════════════╗
║                    SECURITY ASSESSMENT                            ║
╚══════════════════════════════════════════════════════════════════╝

🔍 OSI-Layer mit höchstem Risiko:
"""
        
        # Finde risikoreichste Layer
        risk_layers = [a for a in analyses if '🔴' in a.security_relevance]
        if risk_layers:
            for layer_analysis in risk_layers:
                report += f"   • {self.layer_info[layer_analysis.layer]['name']}\n"
                report += f"     Grund: {layer_analysis.security_relevance}\n"
        
        report += f"""
💡 EMPFEHLUNGEN nach OSI-Layer:
"""
        
        for layer, info in self.layer_info.items():
            if layer in [OSILayer.DATA_LINK, OSILayer.NETWORK, OSILayer.TRANSPORT, OSILayer.PRESENTATION]:
                report += f"""
{info['name']}:
  Maßnahmen:
"""
                for measure in info['security_measures'][:2]:
                    report += f"    ✓ {measure}\n"
        
        return report
    
    def get_layer_statistics(self, scan_results: List[Dict]) -> Dict:
        """
        Berechnet Statistiken über OSI-Layer-Probleme im gesamten Netzwerk
        """
        stats = {
            'total_services': len(scan_results),
            'unencrypted_services': 0,
            'critical_layer4_issues': 0,
            'layer7_vulnerabilities': 0,
            'network_layer_issues': 0
        }
        
        for result in scan_results:
            port = result.get('port', 0)
            service = result.get('service', 'unknown')
            
            # Layer 6: Verschlüsselung
            if port not in [443, 22, 993, 995, 465]:
                stats['unencrypted_services'] += 1
            
            # Layer 4: Kritische Ports
            if port in [21, 23, 445, 3389]:
                stats['critical_layer4_issues'] += 1
            
            # Layer 7: Bekannte App-Vulnerabilities
            if service.lower() in ['ftp', 'telnet', 'http']:
                stats['layer7_vulnerabilities'] += 1
        
        return stats


def demonstrate_osi_knowledge():
    """
    Demonstriert OSI-Modell-Verständnis mit Beispielen
    """
    print("="*70)
    print("OSI-MODELL DEMONSTRATION")
    print("="*70)
    
    analyzer = OSIAnalyzer()
    
    # Zeige Analyse für verschiedene kritische Services
    test_cases = [
        (23, 'Telnet'),
        (443, 'HTTPS'),
        (3389, 'RDP')
    ]
    
    for port, service in test_cases:
        print(f"\n{'='*70}")
        print(f"ANALYSIERE: Port {port} ({service})")
        print('='*70)
        
        report = analyzer.generate_osi_report(port, service)
        print(report)
        
        input("\nDrücke Enter für nächstes Beispiel...")


if __name__ == "__main__":
    demonstrate_osi_knowledge()