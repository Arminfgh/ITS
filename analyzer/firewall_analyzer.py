"""
SecureOffice Hub - Firewall Analyzer
Analysiert Firewall-Konfigurationen und Sicherheitsregeln
Demonstriert Verständnis von Firewall-Konzepten
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import subprocess
import platform
import re


class FirewallAction(Enum):
    """Firewall Aktionen"""
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"
    REJECT = "REJECT"


class FirewallDirection(Enum):
    """Traffic-Richtung"""
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BIDIRECTIONAL = "BIDIRECTIONAL"


@dataclass
class FirewallRule:
    """Firewall-Regel"""
    rule_id: int
    name: str
    action: FirewallAction
    direction: FirewallDirection
    protocol: str
    source_ip: str
    source_port: Optional[str]
    dest_ip: str
    dest_port: Optional[str]
    enabled: bool
    priority: int


class FirewallAnalyzer:
    """
    Analysiert Firewall-Konfiguration und erstellt Sicherheitsempfehlungen
    """
    
    def __init__(self):
        self.firewall_rules = []
        self.security_issues = []
        
        # Best Practice Port-Listen
        self.critical_ports = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            445: "SMB",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        
        self.allowed_outbound_ports = [80, 443, 53, 123]  # HTTP, HTTPS, DNS, NTP
        
    def analyze_firewall_configuration(self, scan_results: List[Dict]) -> Dict:
        """
        Hauptanalyse der Firewall-Konfiguration
        
        Args:
            scan_results: Scan-Ergebnisse mit offenen Ports
            
        Returns:
            Dictionary mit Firewall-Analyse
        """
        print("\n" + "="*70)
        print("🛡️  FIREWALL KONFIGURATIONSANALYSE")
        print("="*70)
        
        analysis = {
            'system_firewall': self._check_system_firewall(),
            'exposed_ports': self._analyze_exposed_ports(scan_results),
            'rule_recommendations': self._generate_rule_recommendations(scan_results),
            'security_score': 0,
            'critical_findings': []
        }
        
        # Berechne Security Score
        analysis['security_score'] = self._calculate_firewall_score(analysis)
        
        return analysis
    
    def _check_system_firewall(self) -> Dict:
        """
        Prüft System-Firewall-Status
        """
        print("\n🔍 Prüfe System-Firewall-Status...")
        
        firewall_status = {
            'active': False,
            'type': 'unknown',
            'rules_count': 0,
            'default_policy': 'unknown'
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                # Windows Firewall
                output = subprocess.check_output(
                    ['netsh', 'advfirewall', 'show', 'allprofiles'],
                    timeout=5
                ).decode('utf-8', errors='ignore')
                
                if 'ON' in output:
                    firewall_status['active'] = True
                    firewall_status['type'] = 'Windows Defender Firewall'
                    print("  ✓ Windows Firewall: AKTIV")
                else:
                    print("  ❌ Windows Firewall: INAKTIV")
                    
            elif system == 'linux':
                # Linux iptables/ufw/firewalld
                try:
                    # Versuche ufw
                    output = subprocess.check_output(['ufw', 'status'], timeout=5).decode()
                    if 'active' in output.lower():
                        firewall_status['active'] = True
                        firewall_status['type'] = 'UFW (Uncomplicated Firewall)'
                        print("  ✓ UFW Firewall: AKTIV")
                except:
                    try:
                        # Versuche iptables
                        output = subprocess.check_output(['iptables', '-L'], timeout=5).decode()
                        firewall_status['active'] = True
                        firewall_status['type'] = 'iptables'
                        firewall_status['rules_count'] = len(output.split('\n'))
                        print("  ✓ iptables Firewall: AKTIV")
                    except:
                        print("  ⚠️  Keine Standard-Firewall gefunden")
            
            elif system == 'darwin':
                # macOS PF Firewall
                try:
                    output = subprocess.check_output(['pfctl', '-s', 'info'], timeout=5).decode()
                    if 'Enabled' in output:
                        firewall_status['active'] = True
                        firewall_status['type'] = 'PF (Packet Filter)'
                        print("  ✓ macOS Firewall: AKTIV")
                except:
                    print("  ⚠️  macOS Firewall-Status unbekannt")
        
        except Exception as e:
            print(f"  ⚠️  Firewall-Check-Fehler: {e}")
        
        return firewall_status
    
    def _analyze_exposed_ports(self, scan_results: List[Dict]) -> Dict:
        """
        Analysiert exponierte Ports aus Security-Perspektive
        """
        print("\n🔓 Analysiere exponierte Ports...")
        
        exposed = {
            'total_open_ports': 0,
            'critical_exposed': [],
            'should_be_blocked': [],
            'acceptable_exposed': []
        }
        
        for host in scan_results:
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                exposed['total_open_ports'] += 1
                
                # Kritische Ports die NIE exponiert sein sollten
                if port in [21, 23, 445, 3306, 5432, 1433]:
                    exposed['critical_exposed'].append({
                        'host': host.get('ip_address'),
                        'port': port,
                        'service': service,
                        'severity': 'CRITICAL',
                        'reason': f'{service} sollte NIEMALS vom Internet erreichbar sein'
                    })
                    print(f"  🔴 KRITISCH: Port {port} ({service}) auf {host.get('ip_address')}")
                
                # Ports die geblockt werden sollten
                elif port in [22, 3389]:
                    exposed['should_be_blocked'].append({
                        'host': host.get('ip_address'),
                        'port': port,
                        'service': service,
                        'severity': 'HIGH',
                        'reason': f'{service} sollte durch VPN geschützt sein'
                    })
                    print(f"  🟠 HOCH: Port {port} ({service}) auf {host.get('ip_address')}")
                
                # Akzeptable exponierte Ports
                elif port in [80, 443]:
                    exposed['acceptable_exposed'].append({
                        'host': host.get('ip_address'),
                        'port': port,
                        'service': service,
                        'severity': 'LOW',
                        'note': f'{service} ist normal exponiert, sollte aber gehärtet sein'
                    })
                    print(f"  🟢 OK: Port {port} ({service}) auf {host.get('ip_address')}")
        
        return exposed
    
    def _generate_rule_recommendations(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Generiert konkrete Firewall-Regel-Empfehlungen
        """
        print("\n💡 Generiere Firewall-Regel-Empfehlungen...")
        
        recommendations = []
        
        # Standard-Empfehlung: Default Deny
        recommendations.append({
            'priority': 1,
            'severity': 'CRITICAL',
            'category': 'Default Policy',
            'rule': {
                'action': 'DENY',
                'direction': 'INBOUND',
                'protocol': 'ALL',
                'source': 'ANY',
                'destination': 'ANY',
                'ports': 'ALL'
            },
            'reason': 'Default Deny Policy - Nur explizit erlaubter Traffic wird durchgelassen',
            'implementation': '''
# iptables (Linux):
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Windows Firewall:
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
            '''
        })
        
        # Empfehlung: Etablierte Verbindungen erlauben
        recommendations.append({
            'priority': 2,
            'severity': 'HIGH',
            'category': 'Stateful Firewall',
            'rule': {
                'action': 'ALLOW',
                'direction': 'INBOUND',
                'protocol': 'ALL',
                'state': 'ESTABLISHED,RELATED'
            },
            'reason': 'Erlaubt Antworten auf ausgehende Verbindungen (Stateful Firewall)',
            'implementation': '''
# iptables:
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ufw:
ufw default allow routed
            '''
        })
        
        # Analysiere gefundene Ports und erstelle spezifische Regeln
        for host in scan_results:
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                host_ip = host.get('ip_address')
                
                # Kritische