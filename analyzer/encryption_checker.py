"""
SecureOffice Hub - Encryption Checker
Analysiert Verschlüsselung: TLS/SSL, Zertifikate, Cipher Suites
Demonstriert Verständnis von Kryptografie und sicherer Kommunikation
"""

import socket
import ssl
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import subprocess


class EncryptionStrength(Enum):
    """Verschlüsselungs-Stärke"""
    STRONG = "STRONG"
    ADEQUATE = "ADEQUATE"
    WEAK = "WEAK"
    NONE = "NONE"


@dataclass
class TLSAnalysis:
    """TLS/SSL Analyse-Ergebnis"""
    host: str
    port: int
    has_ssl: bool
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    certificate_valid: bool
    certificate_expires: Optional[datetime]
    certificate_issuer: Optional[str]
    encryption_strength: EncryptionStrength
    vulnerabilities: List[str]
    recommendations: List[str]


class EncryptionChecker:
    """
    Analysiert Verschlüsselung und TLS/SSL-Konfiguration
    """
    
    def __init__(self):
        # Schwache/veraltete Cipher Suites
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
        ]
        
        # Veraltete TLS-Versionen
        self.deprecated_tls = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        
        # Empfohlene moderne Cipher Suites
        self.recommended_ciphers = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256'
        ]
    
    def analyze_encryption(self, scan_results: List[Dict]) -> Dict:
        """
        Hauptanalyse der Verschlüsselung im Netzwerk
        
        Args:
            scan_results: Scan-Ergebnisse mit offenen Ports
            
        Returns:
            Dictionary mit Verschlüsselungs-Analyse
        """
        print("\n" + "="*70)
        print("🔐 VERSCHLÜSSELUNGSANALYSE (TLS/SSL)")
        print("="*70)
        
        analysis = {
            'total_services': 0,
            'encrypted_services': [],
            'unencrypted_services': [],
            'tls_analyses': [],
            'encryption_score': 0,
            'critical_findings': []
        }
        
        # Analysiere jeden Host und Port
        for host in scan_results:
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                host_ip = host.get('ip_address')
                
                analysis['total_services'] += 1
                
                # Prüfe ob Port normalerweise verschlüsselt ist
                if self._should_be_encrypted(port, service):
                    # Versuche TLS-Analyse
                    tls_analysis = self._analyze_tls(host_ip, port, service)
                    
                    if tls_analysis.has_ssl:
                        analysis['encrypted_services'].append({
                            'host': host_ip,
                            'port': port,
                            'service': service,
                            'tls_version': tls_analysis.tls_version,
                            'strength': tls_analysis.encryption_strength.value
                        })
                    else:
                        # Service sollte verschlüsselt sein, ist es aber nicht!
                        analysis['unencrypted_services'].append({
                            'host': host_ip,
                            'port': port,
                            'service': service,
                            'severity': 'CRITICAL'
                        })
                        analysis['critical_findings'].append({
                            'type': 'UNENCRYPTED_SERVICE',
                            'host': host_ip,
                            'port': port,
                            'service': service,
                            'risk': f'{service} überträgt Daten UNVERSCHLÜSSELT - DSGVO-Verstoß möglich!'
                        })
                    
                    analysis['tls_analyses'].append(tls_analysis)
                
                else:
                    # Prüfe ob unverschlüsselter Port (z.B. HTTP, FTP, Telnet)
                    if port in [21, 23, 80]:
                        analysis['unencrypted_services'].append({
                            'host': host_ip,
                            'port': port,
                            'service': service,
                            'severity': 'HIGH'
                        })
        
        # Berechne Encryption Score
        analysis['encryption_score'] = self._calculate_encryption_score(analysis)
        
        return analysis
    
    def _should_be_encrypted(self, port: int, service: str) -> bool:
        """
        Prüft ob ein Port/Service normalerweise verschlüsselt sein sollte
        """
        encrypted_ports = {
            443,   # HTTPS
            22,    # SSH
            465,   # SMTPS
            587,   # SMTP with STARTTLS
            993,   # IMAPS
            995,   # POP3S
            3306,  # MySQL (sollte zumindest TLS unterstützen)
            5432,  # PostgreSQL (sollte TLS unterstützen)
        }
        return port in encrypted_ports or 'HTTPS' in service.upper()
    
    def _analyze_tls(self, host: str, port: int, service: str) -> TLSAnalysis:
        """
        Führt TLS/SSL-Analyse für einen Host:Port durch
        """
        print(f"\n🔍 Analysiere TLS für {host}:{port} ({service})...")
        
        tls_analysis = TLSAnalysis(
            host=host,
            port=port,
            has_ssl=False,
            tls_version=None,
            cipher_suite=None,
            certificate_valid=False,
            certificate_expires=None,
            certificate_issuer=None,
            encryption_strength=EncryptionStrength.NONE,
            vulnerabilities=[],
            recommendations=[]
        )
        
        try:
            # Erstelle SSL-Context mit verschiedenen Protokollen
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Für Analyse: Zertifikat nicht verifizieren
            
            # Versuche TLS-Verbindung
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_analysis.has_ssl = True
                    
                    # TLS-Version
                    tls_analysis.tls_version = ssock.version()
                    print(f"  ✓ TLS Version: {tls_analysis.tls_version}")
                    
                    # Cipher Suite
                    tls_analysis.cipher_suite = ssock.cipher()[0] if ssock.cipher() else None
                    print(f"  ✓ Cipher: {tls_analysis.cipher_suite}")
                    
                    # Zertifikat-Info
                    cert = ssock.getpeercert()
                    if cert:
                        # Ablaufdatum
                        not_after = cert.get('notAfter')
                        if not_after:
                            tls_analysis.certificate_expires = datetime.strptime(
                                not_after, '%b %d %H:%M:%S %Y %Z'
                            )
                            days_until_expiry = (tls_analysis.certificate_expires - datetime.now()).days
                            print(f"  ✓ Zertifikat läuft ab: {tls_analysis.certificate_expires.date()} ({days_until_expiry} Tage)")
                            
                            if days_until_expiry < 0:
                                tls_analysis.vulnerabilities.append('Zertifikat ist ABGELAUFEN!')
                            elif days_until_expiry < 30:
                                tls_analysis.vulnerabilities.append(f'Zertifikat läuft bald ab ({days_until_expiry} Tage)')
                        
                        # Issuer
                        issuer = cert.get('issuer', ())
                        for item in issuer:
                            if item[0][0] == 'organizationName':
                                tls_analysis.certificate_issuer = item[0][1]
                                print(f"  ✓ Issuer: {tls_analysis.certificate_issuer}")
                        
                        tls_analysis.certificate_valid = True
                    
                    # Bewerte Verschlüsselungs-Stärke
                    tls_analysis.encryption_strength = self._assess_encryption_strength(
                        tls_analysis.tls_version,
                        tls_analysis.cipher_suite
                    )
                    
                    # Prüfe auf Vulnerabilities
                    tls_analysis.vulnerabilities.extend(
                        self._check_tls_vulnerabilities(tls_analysis)
                    )
                    
                    # Generiere Empfehlungen
                    tls_analysis.recommendations = self._generate_tls_recommendations(tls_analysis)
        
        except ssl.SSLError as e:
            print(f"  ⚠️  SSL-Fehler: {e}")
            tls_analysis.vulnerabilities.append(f'SSL-Fehler: {str(e)}')
        except socket.timeout:
            print(f"  ⚠️  Timeout - Host nicht erreichbar")
        except Exception as e:
            print(f"  ⚠️  Fehler bei TLS-Analyse: {e}")
        
        return tls_analysis
    
    def _assess_encryption_strength(self, tls_version: str, cipher: str) -> EncryptionStrength:
        """
        Bewertet Verschlüsselungs-Stärke
        """
        if not tls_version or not cipher:
            return EncryptionStrength.NONE
        
        # Prüfe