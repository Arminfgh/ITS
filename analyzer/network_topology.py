"""
SecureOffice Hub - Network Topology Analyzer
Analysiert Netzwerk-Topologie: Routing, Switching, VLANs
Demonstriert Verständnis von Netzwerk-Infrastruktur
"""

import ipaddress
import subprocess
import platform
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class DeviceType(Enum):
    """Netzwerk-Geräte-Typen"""
    ROUTER = "Router"
    SWITCH = "Switch"
    FIREWALL = "Firewall"
    HOST = "Host"
    GATEWAY = "Gateway"
    UNKNOWN = "Unknown"


@dataclass
class NetworkDevice:
    """Netzwerk-Gerät"""
    ip_address: str
    device_type: DeviceType
    is_gateway: bool
    subnet: str
    vlan_id: Optional[int]
    routing_capable: bool
    switching_capable: bool


@dataclass
class RoutingEntry:
    """Routing-Tabellen-Eintrag"""
    destination: str
    gateway: str
    interface: str
    metric: int


@dataclass
class VLANInfo:
    """VLAN-Information"""
    vlan_id: int
    name: str
    subnet: str
    devices: List[str]
    security_level: str


class NetworkTopologyAnalyzer:
    """
    Analysiert Netzwerk-Topologie und zeigt Routing/Switching/VLAN-Konzepte
    """
    
    def __init__(self):
        self.routing_table = []
        self.detected_devices = []
        self.vlans = []
        self.gateways = []
        
    def analyze_network_topology(self, scan_results: List[Dict]) -> Dict:
        """
        Hauptanalyse der Netzwerk-Topologie
        
        Args:
            scan_results: Ergebnisse vom Network-Scan
        
        Returns:
            Dictionary mit vollständiger Topologie-Analyse
        """
        print("\n" + "="*70)
        print("🌐 NETZWERK-TOPOLOGIE ANALYSE")
        print("="*70)
        
        topology = {
            'routing': self._analyze_routing(),
            'switching': self._analyze_switching(scan_results),
            'vlans': self._analyze_vlans(scan_results),
            'gateways': self._detect_gateways(),
            'security_analysis': self._analyze_topology_security(scan_results)
        }
        
        return topology
    
    def _analyze_routing(self) -> Dict:
        """
        Analysiert Routing-Tabelle des Systems
        ZEIGT: Verständnis von Layer 3 Routing
        """
        print("\n📍 Analysiere Routing-Tabelle...")
        
        routing_info = {
            'entries': [],
            'default_gateway': None,
            'routing_protocols': [],
            'security_issues': []
        }
        
        try:
            # Lese System-Routing-Tabelle
            if platform.system().lower() == 'windows':
                output = subprocess.check_output(['route', 'print'], 
                                                timeout=5).decode('utf-8', errors='ignore')
            else:
                output = subprocess.check_output(['ip', 'route'], 
                                                timeout=5).decode('utf-8', errors='ignore')
            
            # Parse Routing-Einträge
            routes = self._parse_routing_table(output)
            routing_info['entries'] = routes
            
            # Finde Default Gateway
            for route in routes:
                if route['destination'] == '0.0.0.0' or route['destination'] == 'default':
                    routing_info['default_gateway'] = route['gateway']
                    print(f"  ✓ Default Gateway gefunden: {route['gateway']}")
            
            # Analyse Routing Security
            routing_info['security_issues'] = self._analyze_routing_security(routes)
            
        except Exception as e:
            print(f"  ⚠️  Routing-Analyse-Fehler: {e}")
        
        return routing_info
    
    def _parse_routing_table(self, output: str) -> List[Dict]:
        """Parst Routing-Tabelle (OS-spezifisch)"""
        routes = []
        
        if platform.system().lower() == 'windows':
            # Windows route print Format
            lines = output.split('\n')
            for line in lines:
                # Beispiel: 0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.100     25
                parts = line.split()
                if len(parts) >= 4 and self._is_valid_ip(parts[0]):
                    routes.append({
                        'destination': parts[0],
                        'netmask': parts[1],
                        'gateway': parts[2],
                        'interface': parts[3],
                        'metric': int(parts[4]) if len(parts) > 4 else 0
                    })
        else:
            # Linux/Mac ip route Format
            lines = output.split('\n')
            for line in lines:
                if 'default' in line or '/' in line:
                    parts = line.split()
                    route = {'destination': parts[0] if parts[0] != 'default' else '0.0.0.0'}
                    
                    if 'via' in parts:
                        idx = parts.index('via')
                        route['gateway'] = parts[idx + 1]
                    
                    if 'dev' in parts:
                        idx = parts.index('dev')
                        route['interface'] = parts[idx + 1]
                    
                    routes.append(route)
        
        return routes
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Prüft ob String eine gültige IP ist"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def _analyze_routing_security(self, routes: List[Dict]) -> List[str]:
        """
        Analysiert Routing-Sicherheit
        ZEIGT: Security-Verständnis von Routing
        """
        issues = []
        
        # Check: Mehrere Default Routes (kann problematisch sein)
        default_routes = [r for r in routes if r.get('destination') in ['0.0.0.0', 'default']]
        if len(default_routes) > 1:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Multiple Default Gateways detected',
                'risk': 'Kann zu Routing-Loops oder Traffic-Leaks führen',
                'recommendation': 'Prüfen Sie Routing-Prioritäten (Metrics)'
            })
        
        # Check: 0.0.0.0/0 Route (alle Destination)
        if any(r.get('destination') == '0.0.0.0' for r in routes):
            issues.append({
                'severity': 'INFO',
                'issue': 'Default Route (0.0.0.0/0) vorhanden',
                'risk': 'Sendet allen unbekannten Traffic zum Gateway',
                'recommendation': 'Normale Konfiguration - Gateway sollte Firewall sein'
            })
        
        # Check: Routing zu privaten Netzwerken über öffentliche IPs
        for route in routes:
            dest = route.get('destination', '')
            gateway = route.get('gateway', '')
            
            if self._is_private_ip(dest) and not self._is_private_ip(gateway):
                issues.append({
                    'severity': 'HIGH',
                    'issue': f'Private network {dest} routed through public gateway {gateway}',
                    'risk': 'Traffic zu privaten Netzen könnte ins Internet geleakt werden',
                    'recommendation': 'Routing-Konfiguration überprüfen'
                })
        
        return issues
    
    def _is_private_ip(self, ip: str) -> bool:
        """Prüft ob IP privat ist (RFC1918)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _analyze_switching(self, scan_results: List[Dict]) -> Dict:
        """
        Analysiert Switching-Verhalten im Netzwerk
        ZEIGT: Verständnis von Layer 2 Switching
        """
        print("\n🔄 Analysiere Switching-Topologie...")
        
        switching_info = {
            'detected_switches': [],
            'mac_table_size': 0,
            'broadcast_domains': [],
            'security_issues': []
        }
        
        # Gruppiere Geräte nach Subnetz (= Broadcast Domain)
        subnets = {}
        for result in scan_results:
            ip = result.get('ip_address', '')
            try:
                ip_obj = ipaddress.ip_address(ip)
                # Annahme: /24 Netzwerk
                network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                
                if network not in subnets:
                    subnets[network] = []
                subnets[network].append(result)
            except:
                continue
        
        switching_info['broadcast_domains'] = [
            {
                'network': net,
                'device_count': len(devices),
                'devices': [d.get('ip_address') for d in devices]
            }
            for net, devices in subnets.items()
        ]
        
        print(f"  ✓ {len(subnets)} Broadcast Domain(s) gefunden")
        
        # Switching Security Analysis
        switching_info['security_issues'] = self._analyze_switching_security(subnets)
        
        return switching_info
    
    def _analyze_switching_security(self, subnets: Dict) -> List[Dict]:
        """
        Analysiert Switching-Sicherheit
        ZEIGT: Security-Verständnis von Layer 2
        """
        issues = []
        
        # Check: Zu viele Geräte in einem Broadcast Domain
        for network, devices in subnets.items():
            if len(devices) > 100:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': f'Large broadcast domain: {network} ({len(devices)} devices)',
                    'risk': 'Broadcast storms, ARP-Table overflow, Performance-Probleme',
                    'recommendation': 'Netzwerk in kleinere VLANs segmentieren'
                })
        
        # Check: Flat Network (keine Segmentierung)
        if len(subnets) == 1:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Flat Network - Keine Segmentierung erkannt',
                'risk': 'Keine Isolation zwischen Geräten, laterale Bewegung einfach',
                'recommendation': 'VLANs implementieren für verschiedene Geräteklassen'
            })
        
        # Switch Security Best Practices
        issues.append({
            'severity': 'INFO',
            'issue': 'Switch Security Best Practices',
            'risk': 'Layer 2 Angriffe möglich',
            'recommendation': '''
                ✓ Port Security aktivieren (MAC-Binding)
                ✓ DHCP Snooping aktivieren
                ✓ Dynamic ARP Inspection (DAI) aktivieren
                ✓ Ungenutzte Ports deaktivieren
                ✓ Native VLAN ändern (nicht VLAN 1)
            '''
        })
        
        return issues
    
    def _analyze_vlans(self, scan_results: List[Dict]) -> Dict:
        """
        Analysiert VLAN-Konfiguration (simuliert basierend auf IP-Ranges)
        ZEIGT: Verständnis von VLAN-Segmentierung
        """
        print("\n🏷️  Analysiere VLAN-Struktur...")
        
        vlan_info = {
            'detected_vlans': [],
            'vlan_security': [],
            'segmentation_score': 0
        }
        
        # Simuliere VLAN-Erkennung basierend auf IP-Ranges
        # In echter Umgebung würde man Switch-Config auslesen
        vlans = self._infer_vlans_from_ips(scan_results)
        
        vlan_info['detected_vlans'] = vlans
        
        # Berechne Segmentierung-Score
        if len(vlans) >= 3:
            vlan_info['segmentation_score'] = 90
            print(f"  ✓ Gute Segmentierung: {len(vlans)} VLANs erkannt")
        elif len(vlans) == 2:
            vlan_info['segmentation_score'] = 60
            print(f"  ⚠️  Moderate Segmentierung: {len(vlans)} VLANs")
        else:
            vlan_info['segmentation_score'] = 20
            print(f"  ❌ Schlechte Segmentierung: {len(vlans)} VLAN")
        
        # VLAN Security Analysis
        vlan_info['vlan_security'] = self._analyze_vlan_security(vlans)
        
        return vlan_info
    
    def _infer_vlans_from_ips(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Inferiert VLANs basierend auf IP-Adress-Ranges
        In echter Umgebung: 802.1Q Tags auslesen
        """
        vlans = []
        vlan_id = 10
        
        # Gruppiere nach Subnetz
        subnets = {}
        for result in scan_results:
            ip = result.get('ip_address', '')
            try:
                network = str(ipaddress.ip_network(f"{ip}/24", strict=False))
                if network not in subnets:
                    subnets[network] = []
                subnets[network].append(ip)
            except:
                continue
        
        # Erstelle VLAN-Einträge
        for network, ips in subnets.items():
            # Kategorisiere basierend auf IP-Range
            third_octet = int(network.split('.')[2])
            
            if third_octet < 10:
                vlan_name = "VLAN_MANAGEMENT"
                security_level = "HIGH"
            elif third_octet < 100:
                vlan_name = "VLAN_USERS"
                security_level = "MEDIUM"
            elif third_octet < 200:
                vlan_name = "VLAN_SERVERS"
                security_level = "HIGH"
            else:
                vlan_name = "VLAN_GUEST"
                security_level = "LOW"
            
            vlans.append({
                'vlan_id': vlan_id,
                'name': vlan_name,
                'subnet': network,
                'device_count': len(ips),
                'security_level': security_level,
                'purpose': self._get_vlan_purpose(vlan_name)
            })
            vlan_id += 10
        
        return vlans
    
    def _get_vlan_purpose(self, vlan_name: str) -> str:
        """Gibt Zweck eines VLANs zurück"""
        purposes = {
            'VLAN_MANAGEMENT': 'Network management devices (switches, routers, firewalls)',
            'VLAN_USERS': 'End-user workstations and devices',
            'VLAN_SERVERS': 'Server infrastructure (databases, file servers)',
            'VLAN_GUEST': 'Guest WiFi and untrusted devices'
        }
        return purposes.get(vlan_name, 'General purpose VLAN')
    
    def _analyze_vlan_security(self, vlans: List[Dict]) -> List[Dict]:
        """
        Analysiert VLAN-Sicherheit
        ZEIGT: Security-Best-Practices für VLANs
        """
        recommendations = []
        
        # Best Practice 1: VLAN Segmentierung
        if len(vlans) < 3:
            recommendations.append({
                'severity': 'HIGH',
                'issue': 'Insufficient VLAN Segmentation',
                'description': 'Netzwerk sollte in mehrere VLANs segmentiert sein',
                'recommendation': '''
                    Empfohlene VLAN-Struktur:
                    • VLAN 10: Management (Switches, Router, Firewall)
                    • VLAN 20: Servers (Kritische Infrastruktur)
                    • VLAN 30: Workstations (Benutzer-PCs)
                    • VLAN 40: WiFi/Guests (Untrusted)
                    • VLAN 50: VoIP (Telefonie)
                    • VLAN 60: IoT (Smart Devices)
                '''
            })
        
        # Best Practice 2: VLAN 1 nicht nutzen
        if any(v['vlan_id'] == 1 for v in vlans):
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'VLAN 1 (Native VLAN) in use',
                'description': 'VLAN 1 ist Default und sollte nicht genutzt werden',
                'recommendation': 'Native VLAN ändern, VLAN 1 für Management-Traffic reservieren'
            })
        
        # Best Practice 3: Inter-VLAN Routing Security
        recommendations.append({
            'severity': 'INFO',
            'issue': 'Inter-VLAN Routing Security',
            'description': 'Traffic zwischen VLANs muss durch Firewall',
            'recommendation': '''
                ✓ ACLs zwischen VLANs konfigurieren
                ✓ Firewall für Inter-VLAN Routing nutzen
                ✓ Private VLANs für zusätzliche Isolation
                ✓ VLAN Hopping verhindern (DTP deaktivieren)
            '''
        })
        
        # Best Practice 4: VLAN für Sensible Daten
        server_vlans = [v for v in vlans if 'SERVER' in v['name'].upper()]
        if not server_vlans:
            recommendations.append({
                'severity': 'MEDIUM',
                'issue': 'No dedicated Server VLAN',
                'description': 'Server sollten in separatem VLAN sein',
                'recommendation': 'Erstellen Sie VLAN für Server mit strengeren Firewall-Regeln'
            })
        
        return recommendations
    
    def _detect_gateways(self) -> List[Dict]:
        """
        Erkennt Gateways im Netzwerk
        """
        print("\n🚪 Erkenne Gateways...")
        
        gateways = []
        
        try:
            # Default Gateway aus Routing-Tabelle
            routing = self._analyze_routing()
            if routing['default_gateway']:
                gateways.append({
                    'ip': routing['default_gateway'],
                    'type': 'Default Gateway',
                    'role': 'Primary Internet Gateway',
                    'security_note': 'Sollte Firewall-Funktionalität haben'
                })
                print(f"  ✓ Default Gateway: {routing['default_gateway']}")
        
        except Exception as e:
            print(f"  ⚠️  Gateway-Detection-Fehler: {e}")
        
        return gateways
    
    def _analyze_topology_security(self, scan_results: List[Dict]) -> Dict:
        """
        Gesamtheitliche Security-Analyse der Topologie
        """
        print("\n🔒 Analysiere Topologie-Sicherheit...")
        
        security = {
            'overall_score': 0,
            'strengths': [],
            'weaknesses': [],
            'critical_issues': [],
            'recommendations': []
        }
        
        # Bewerte verschiedene Aspekte
        scores = []
        
        # 1. Network Segmentation
        routing = self._analyze_routing()
        switching = self._analyze_switching(scan_results)
        vlans = self._analyze_vlans(scan_results)
        
        segmentation_score = vlans['segmentation_score']
        scores.append(segmentation_score)
        
        if segmentation_score >= 80:
            security['strengths'].append('Gute Netzwerk-Segmentierung durch VLANs')
        else:
            security['weaknesses'].append('Unzureichende Netzwerk-Segmentierung')
            security['critical_issues'].append({
                'issue': 'Flat Network oder zu wenig VLANs',
                'impact': 'Laterale Bewegung bei Kompromittierung einfach möglich',
                'cvss': 7.5
            })
        
        # 2. Gateway Security
        if routing.get('default_gateway'):
            security['strengths'].append('Default Gateway konfiguriert')
            security['recommendations'].append({
                'priority': 'HIGH',
                'recommendation': f"Sicherstellen dass Gateway {routing['default_gateway']} Firewall-Funktionalität hat"
            })
        
        # 3. Broadcast Domain Size
        for domain in switching['broadcast_domains']:
            if domain['device_count'] > 100:
                security['weaknesses'].append(f"Große Broadcast Domain: {domain['network']}")
        
        # Berechne Gesamt-Score
        security['overall_score'] = sum(scores) // len(scores) if scores else 0
        
        # Generiere Empfehlungen
        security['recommendations'].extend([
            {
                'priority': 'HIGH',
                'category': 'Layer 2 Security',
                'recommendation': 'Port Security auf allen Switch-Ports aktivieren'
            },
            {
                'priority': 'HIGH',
                'category': 'Layer 3 Security',
                'recommendation': 'Inter-VLAN Routing durch Firewall erzwingen'
            },
            {
                'priority': 'MEDIUM',
                'category': 'Monitoring',
                'recommendation': 'NetFlow oder sFlow für Traffic-Analyse aktivieren'
            }
        ])
        
        return security
    
    def generate_topology_report(self, scan_results: List[Dict]) -> str:
        """
        Generiert detaillierten Topologie-Report
        """
        topology = self.analyze_network_topology(scan_results)
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║             NETZWERK-TOPOLOGIE SICHERHEITS-ANALYSE               ║
╚══════════════════════════════════════════════════════════════════╝

📊 ROUTING ANALYSE (Layer 3):
──────────────────────────────────────────────────────────────────
"""
        
        routing = topology['routing']
        if routing['default_gateway']:
            report += f"  Default Gateway: {routing['default_gateway']}\n"
        report += f"  Routing Entries: {len(routing['entries'])}\n"
        
        if routing['security_issues']:
            report += "\n  ⚠️  Routing Security Issues:\n"
            for issue in routing['security_issues']:
                report += f"    • [{issue['severity']}] {issue['issue']}\n"
                report += f"      → {issue['recommendation']}\n"
        
        report += f"""

🔄 SWITCHING ANALYSE (Layer 2):
──────────────────────────────────────────────────────────────────
  Broadcast Domains: {len(topology['switching']['broadcast_domains'])}
"""
        
        for domain in topology['switching']['broadcast_domains']:
            report += f"    • {domain['network']}: {domain['device_count']} devices\n"
        
        if topology['switching']['security_issues']:
            report += "\n  ⚠️  Switching Security Issues:\n"
            for issue in topology['switching']['security_issues'][:3]:
                report += f"    • [{issue['severity']}] {issue['issue']}\n"
        
        report += f"""

🏷️  VLAN ANALYSE:
──────────────────────────────────────────────────────────────────
  Detected VLANs: {len(topology['vlans']['detected_vlans'])}
  Segmentation Score: {topology['vlans']['segmentation_score']}/100
"""
        
        for vlan in topology['vlans']['detected_vlans']:
            report += f"""
    VLAN {vlan['vlan_id']} - {vlan['name']}
      Subnet: {vlan['subnet']}
      Devices: {vlan['device_count']}
      Security Level: {vlan['security_level']}
      Purpose: {vlan['purpose']}
"""
        
        report += f"""

🔒 GESAMT-SECURITY-BEWERTUNG:
──────────────────────────────────────────────────────────────────
  Overall Score: {topology['security_analysis']['overall_score']}/100
"""
        
        security = topology['security_analysis']
        
        if security['strengths']:
            report += "\n  ✅ Stärken:\n"
            for strength in security['strengths']:
                report += f"    • {strength}\n"
        
        if security['critical_issues']:
            report += "\n  🔴 KRITISCHE PROBLEME:\n"
            for issue in security['critical_issues']:
                report += f"    • {issue['issue']}\n"
                report += f"      Impact: {issue['impact']}\n"
                report += f"      CVSS: {issue['cvss']}\n"
        
        report += "\n  💡 TOP EMPFEHLUNGEN:\n"
        for rec in security['recommendations'][:5]:
            report += f"    [{rec['priority']}] {rec['recommendation']}\n"
        
        report += """

╔══════════════════════════════════════════════════════════════════╗
║                     NETZWERK-KONZEPTE ERKLÄRT                    ║
╚══════════════════════════════════════════════════════════════════╝

🔹 ROUTING (Layer 3):
  • Verbindet verschiedene Netzwerke/Subnetze
  • Router nutzen IP-Adressen für Weiterleitung
  • Routing-Tabelle bestimmt Pfad für Pakete
  • Firewall sollte Inter-Network Traffic filtern

🔹 SWITCHING (Layer 2):
  • Verbindet Geräte im gleichen Netzwerk
  • Switch nutzt MAC-Adressen
  • Broadcast Domain = alle Geräte am Switch
  • Port Security verhindert MAC-Spoofing

🔹 VLANs (Virtual LANs):
  • Logische Segmentierung eines physischen Netzwerks
  • Trennt Traffic ohne zusätzliche Hardware
  • Jedes VLAN = eigene Broadcast Domain
  • Verhindert laterale Bewegung bei Kompromittierung

🔹 GATEWAY:
  • Verbindung zwischen Netzwerken (z.B. LAN ↔ Internet)
  • Sollte Firewall-Funktionen haben
  • NAT (Network Address Translation) für private IPs
  • Erste Verteidigungslinie gegen externe Angriffe
"""
        
        return report


def demonstrate_network_topology():
    """
    Demonstriert Netzwerk-Topologie-Verständnis
    """
    print("="*70)
    print("NETZWERK-TOPOLOGIE DEMONSTRATION")
    print("="*70)
    
    analyzer = NetworkTopologyAnalyzer()
    
    # Simuliere Scan-Ergebnisse
    mock_scan = [
        {'ip_address': '192.168.1.1', 'hostname': 'router'},
        {'ip_address': '192.168.1.10', 'hostname': 'switch'},
        {'ip_address': '192.168.1.100', 'hostname': 'pc1'},
        {'ip_address': '192.168.1.101', 'hostname': 'pc2'},
        {'ip_address': '192.168.10.50', 'hostname': 'server1'},
        {'ip_address': '192.168.10.51', 'hostname': 'server2'},
    ]
    
    report = analyzer.generate_topology_report(mock_scan)
    print(report)


if __name__ == "__main__":
    demonstrate_network_topology()