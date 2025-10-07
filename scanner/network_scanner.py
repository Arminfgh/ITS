"""
SecureOffice Hub - Network Scanner
Scannt das lokale Netzwerk und findet alle Geräte
"""

import socket
import struct
import subprocess
import platform
import ipaddress
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import uuid

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("⚠️  python-nmap nicht installiert - Fallback zu einfachem Scan")


class NetworkScanner:
    """
    Hauptklasse für Netzwerk-Scanning
    """
    
    def __init__(self, network_range: Optional[str] = None):
        self.network_range = network_range or self._detect_local_network()
        self.scan_id = str(uuid.uuid4())[:8]
        self.scan_results = {
            'scan_id': self.scan_id,
            'timestamp': datetime.now(),
            'network_range': self.network_range,
            'hosts': [],
            'total_hosts': 0,
            'scan_duration': 0,
            'status': 'not_started'
        }
        
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
            print(f"✅ NMAP verfügbar - Erweiterte Scans möglich")
        else:
            self.nm = None
            print(f"⚠️  NMAP nicht verfügbar - Basic Scan wird verwendet")
    
    def _detect_local_network(self) -> str:
        """
        Erkennt automatisch das lokale Netzwerk
        """
        try:
            # Hole lokale IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Berechne Netzwerk-Range (Standard /24)
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            print(f"🔍 Erkanntes Netzwerk: {network}")
            return network
            
        except Exception as e:
            print(f"❌ Fehler bei Netzwerk-Erkennung: {e}")
            return "192.168.1.0/24"  # Fallback
    
    def scan_network(self, ports: List[int] = None, 
                    fast_mode: bool = True) -> Dict:
        """
        Haupt-Scan-Funktion
        
        Args:
            ports: Liste der zu scannenden Ports (None = Standard-Ports)
            fast_mode: Schneller Scan (True) oder ausführlich (False)
        
        Returns:
            Dictionary mit Scan-Ergebnissen
        """
        print(f"\n{'='*60}")
        print(f"🚀 STARTE NETZWERK-SCAN")
        print(f"{'='*60}")
        print(f"📍 Netzwerk: {self.network_range}")
        print(f"🆔 Scan-ID: {self.scan_id}")
        print(f"⏰ Startzeit: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        self.scan_results['status'] = 'running'
        
        try:
            if NMAP_AVAILABLE and not fast_mode:
                # Erweiterte NMAP-Scans
                self._nmap_scan(ports)
            else:
                # Schneller Basic-Scan
                self._basic_scan(ports or [80, 443, 22, 3389])
            
            # Berechne Scan-Dauer
            duration = time.time() - start_time
            self.scan_results['scan_duration'] = round(duration, 2)
            self.scan_results['total_hosts'] = len(self.scan_results['hosts'])
            self.scan_results['status'] = 'completed'
            
            print(f"\n{'='*60}")
            print(f"✅ SCAN ABGESCHLOSSEN")
            print(f"{'='*60}")
            print(f"⏱️  Dauer: {duration:.2f} Sekunden")
            print(f"🖥️  Gefundene Hosts: {self.scan_results['total_hosts']}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"\n❌ FEHLER beim Scan: {e}")
            self.scan_results['status'] = 'failed'
            self.scan_results['error'] = str(e)
        
        return self.scan_results
    
    def _basic_scan(self, ports: List[int]):
        """
        Schneller Basic-Scan ohne NMAP
        Funktioniert immer, auch ohne Zusatz-Tools
        """
        print("🔍 Führe Basic-Scan durch...")
        
        # Parse Netzwerk
        network = ipaddress.ip_network(self.network_range, strict=False)
        all_ips = list(network.hosts())
        
        print(f"📊 Scanne {len(all_ips)} IP-Adressen...")
        
        # Multi-Threading für schnelleren Scan
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_host, str(ip), ports): str(ip) 
                for ip in all_ips
            }
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    host_info = future.result()
                    if host_info:
                        self.scan_results['hosts'].append(host_info)
                        print(f"  ✓ Gefunden: {host_info['ip_address']} - {host_info['hostname']}")
                except Exception as e:
                    pass  # Host nicht erreichbar
    
    def _check_host(self, ip: str, ports: List[int]) -> Optional[Dict]:
        """
        Prüft ob Host erreichbar ist und scannt Ports
        """
        # Ping-Test
        if not self._ping_host(ip):
            return None
        
        # Host ist erreichbar!
        host_info = {
            'ip_address': ip,
            'hostname': self._get_hostname(ip),
            'mac_address': self._get_mac_address(ip),
            'status': 'up',
            'response_time': None,
            'open_ports': [],
            'os_guess': 'Unknown'
        }
        
        # Port-Scan
        for port in ports:
            if self._check_port(ip, port):
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': self._guess_service(port)
                }
                host_info['open_ports'].append(port_info)
        
        return host_info
    
    def _ping_host(self, ip: str, timeout: int = 1) -> bool:
        """
        Pingt einen Host (plattformunabhängig)
        """
        try:
            # Plattform-spezifischer Ping-Befehl
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w' if platform.system().lower() == 'windows' else '-W', 
                      str(timeout * 1000) if platform.system().lower() == 'windows' else str(timeout), ip]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _check_port(self, ip: str, port: int, timeout: float = 0.5) -> bool:
        """
        Prüft ob ein Port offen ist
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _get_hostname(self, ip: str) -> str:
        """
        Versucht Hostname aufzulösen
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return 'Unknown'
    
    def _get_mac_address(self, ip: str) -> Optional[str]:
        """
        Versucht MAC-Adresse zu bekommen (funktioniert nur im lokalen Netzwerk)
        """
        try:
            # ARP-Tabelle auslesen (plattformabhängig)
            if platform.system().lower() == 'windows':
                output = subprocess.check_output(['arp', '-a', ip], timeout=2).decode()
            else:
                output = subprocess.check_output(['arp', '-n', ip], timeout=2).decode()
            
            # MAC-Adresse extrahieren (vereinfacht)
            for line in output.split('\n'):
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part or '-' in part:
                            return part.replace('-', ':')
        except Exception:
            pass
        return None
    
    def _guess_service(self, port: int) -> str:
        """
        Rät welcher Service auf dem Port läuft
        """
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
        }
        return common_ports.get(port, 'Unknown')
    
    def _nmap_scan(self, ports: List[int] = None):
        """
        Erweiterte NMAP-Scans (wenn verfügbar)
        """
        print("🔍 Führe erweiterten NMAP-Scan durch...")
        
        try:
            # Bereite Port-Liste vor
            port_range = ','.join(map(str, ports)) if ports else '21-443,3389'
            
            # NMAP-Scan mit OS-Detection
            print(f"📊 Scanne Ports: {port_range}")
            self.nm.scan(
                hosts=self.network_range,
                arguments=f'-sV -O --top-ports 20 -T4'  # Service Version + OS Detection
            )
            
            # Verarbeite Ergebnisse
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = self._parse_nmap_host(host)
                    self.scan_results['hosts'].append(host_info)
                    print(f"  ✓ Gefunden: {host_info['ip_address']} - {host_info['hostname']}")
                    
        except Exception as e:
            print(f"⚠️  NMAP-Scan Fehler: {e}")
            print("   Fallback zu Basic-Scan...")
            self._basic_scan(ports or [80, 443, 22])
    
    def _parse_nmap_host(self, host: str) -> Dict:
        """
        Parst NMAP-Ergebnisse für einen Host
        """
        host_data = self.nm[host]
        
        host_info = {
            'ip_address': host,
            'hostname': host_data.hostname(),
            'mac_address': host_data['addresses'].get('mac', None),
            'status': host_data.state(),
            'open_ports': []
        }
        
        # OS-Erkennung
        if 'osmatch' in host_data and host_data['osmatch']:
            host_info['os_guess'] = host_data['osmatch'][0]['name']
        else:
            host_info['os_guess'] = 'Unknown'
        
        # Ports
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                port_info = {
                    'port': port,
                    'state': port_data['state'],
                    'service': port_data.get('name', 'unknown'),
                    'version': port_data.get('version', '')
                }
                host_info['open_ports'].append(port_info)
        
        return host_info
    
    def get_summary(self) -> str:
        """
        Gibt eine lesbare Zusammenfassung zurück
        """
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║              NETZWERK-SCAN ZUSAMMENFASSUNG                   ║
╠══════════════════════════════════════════════════════════════╣
║ Scan-ID:        {self.scan_id:<45} ║
║ Netzwerk:       {self.network_range:<45} ║
║ Status:         {self.scan_results['status']:<45} ║
║ Dauer:          {self.scan_results['scan_duration']:<45} ║
║ Hosts gefunden: {self.scan_results['total_hosts']:<45} ║
╚══════════════════════════════════════════════════════════════╝

GEFUNDENE GERÄTE:
"""
        
        for i, host in enumerate(self.scan_results['hosts'], 1):
            summary += f"""
  [{i}] {host['ip_address']} ({host['hostname']})
      Status: {host['status']}
      MAC: {host.get('mac_address', 'N/A')}
      OS: {host.get('os_guess', 'Unknown')}
      Offene Ports: {len(host.get('open_ports', []))}
"""
            for port in host.get('open_ports', [])[:5]:  # Zeige max. 5 Ports
                summary += f"        - Port {port['port']}: {port.get('service', 'unknown')}\n"
        
        return summary


# Convenience-Funktion für schnellen Scan
def quick_scan(network_range: Optional[str] = None) -> Dict:
    """
    Führt schnellen Netzwerk-Scan durch
    """
    scanner = NetworkScanner(network_range)
    results = scanner.scan_network(fast_mode=True)
    print(scanner.get_summary())
    return results


if __name__ == "__main__":
    # Test des Scanners
    print("🔧 Teste Network Scanner...\n")
    
    scanner = NetworkScanner()
    results = scanner.scan_network(ports=[80, 443, 22, 3389], fast_mode=True)
    
    print(scanner.get_summary())
    
    print("\n✅ Scanner-Test abgeschlossen!")