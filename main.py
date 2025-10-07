"""
SecureOffice Hub - MAIN ENTRY POINT
100% LEGAL - Nur Localhost oder Demo-Modus!

Starten mit: python main.py
"""

import sys
import os
from pathlib import Path

# Füge Project-Root zum Path hinzu
ROOT_DIR = Path(__file__).parent
sys.path.insert(0, str(ROOT_DIR))

def print_banner():
    """Zeigt cooles Banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     🛡️  SECUREOFFICE HUB - NETWORK SECURITY SCANNER  🛡️         ║
║                                                                  ║
║                    Entwickelt für BVB Interview                  ║
║                         100% LEGAL & SAFE                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

    """
    print(banner)

def show_menu():
    """Zeigt Hauptmenü"""
    print("\n" + "="*70)
    print("WÄHLE EINEN MODUS:")
    print("="*70)
    print()
    print("  [1] 🎨 DEMO MODE (für Interview/Präsentation)")
    print("      → Zeigt simulierte Daten")
    print("      → Perfekt für Live-Demo")
    print("      → 100% sicher, kein echter Scan")
    print()
    print("  [2] 🖥️  LOCAL MODE (Localhost-Scan)")
    print("      → Scannt NUR deinen eigenen PC (127.0.0.1)")
    print("      → Zum Testen der Funktionalität")
    print("      → 100% legal, nur dein System")
    print()
    print("  [3] 📊 DASHBOARD (Interaktives Web-Interface)")
    print("      → Streamlit Dashboard starten")
    print("      → Visualisierung & Reports")
    print("      → Beste Option für Interview!")
    print()
    print("  [4] 📄 PDF-REPORT generieren")
    print("      → Erstellt professionellen Security-Report")
    print("      → Zum Vorzeigen/Ausdrucken")
    print()
    print("  [5] ℹ️  INFO über das Projekt")
    print()
    print("  [0] ❌ Beenden")
    print()
    print("="*70)

def run_demo_mode():
    """Demo-Modus mit simulierten Daten"""
    print("\n🎨 Starte DEMO MODE...")
    print("="*70)
    print("✅ Verwende simulierte Daten (kein echter Scan)")
    print("✅ 100% sicher für Präsentationen")
    print()
    
    from scanner.network_scanner import NetworkScanner
    from detector.vulnerability_db import VulnerabilityDatabase
    from detector.risk_calculator import RiskCalculator
    
    # Erstelle Demo-Scanner mit simulierten Daten
    print("📊 Generiere Demo-Daten...")
    
    # Simulierte Scan-Ergebnisse
    demo_results = {
        'scan_id': 'DEMO-001',
        'timestamp': 'Demo Mode',
        'network_range': '192.168.1.0/24 (Simuliert)',
        'total_hosts': 5,
        'scan_duration': 2.5,
        'status': 'completed',
        'hosts': [
            {
                'ip_address': '192.168.1.1',
                'hostname': 'router.local',
                'status': 'up',
                'os_guess': 'Linux/Router',
                'open_ports': [
                    {'port': 80, 'state': 'open', 'service': 'HTTP'},
                    {'port': 443, 'state': 'open', 'service': 'HTTPS'}
                ]
            },
            {
                'ip_address': '192.168.1.10',
                'hostname': 'file-server',
                'status': 'up',
                'os_guess': 'Windows Server 2019',
                'open_ports': [
                    {'port': 445, 'state': 'open', 'service': 'SMB'},
                    {'port': 3389, 'state': 'open', 'service': 'RDP'}
                ]
            },
            {
                'ip_address': '192.168.1.20',
                'hostname': 'legacy-ftp',
                'status': 'up',
                'os_guess': 'Linux Ubuntu',
                'open_ports': [
                    {'port': 21, 'state': 'open', 'service': 'FTP'},
                    {'port': 23, 'state': 'open', 'service': 'Telnet'}
                ]
            }
        ]
    }
    
    print("\n✅ Demo-Scan abgeschlossen!")
    print(f"✅ {demo_results['total_hosts']} Hosts gefunden (simuliert)")
    print(f"✅ Dauer: {demo_results['scan_duration']}s")
    
    # Zeige Ergebnisse
    print("\n" + "="*70)
    print("📋 GEFUNDENE HOSTS (Demo-Daten):")
    print("="*70)
    
    for host in demo_results['hosts']:
        print(f"\n  [{host['ip_address']}] {host['hostname']}")
        print(f"    OS: {host['os_guess']}")
        print(f"    Ports: {len(host['open_ports'])} offen")
        for port in host['open_ports']:
            print(f"      • Port {port['port']}: {port['service']}")
    
    # Vulnerability Analysis
    print("\n" + "="*70)
    print("🔍 SICHERHEITSANALYSE:")
    print("="*70)
    print("\n  🔴 KRITISCHE FINDINGS:")
    print("    • FTP (Port 21) auf 192.168.1.20 - UNVERSCHLÜSSELT!")
    print("    • Telnet (Port 23) auf 192.168.1.20 - KRITISCH!")
    print("    • SMB (Port 445) auf 192.168.1.10 - EternalBlue Risiko")
    print("\n  🟡 WARNUNGEN:")
    print("    • RDP (Port 3389) exponiert - VPN empfohlen")
    print("    • HTTP ohne HTTPS auf Router")
    print("\n  🟢 OK:")
    print("    • HTTPS korrekt konfiguriert")
    
    print("\n" + "="*70)
    print("💡 Für vollständige Analyse: Dashboard starten (Option 3)")
    print("="*70)

def run_local_mode():
    """Localhost-Scan - 100% legal"""
    print("\n🖥️  Starte LOCAL MODE...")
    print("="*70)
    print("✅ Scanne NUR localhost (127.0.0.1)")
    print("✅ 100% legal - nur dein eigener PC!")
    print()
    
    from scanner.network_scanner import NetworkScanner
    
    # Nur localhost scannen
    scanner = NetworkScanner(network_range="127.0.0.1/32")
    
    print("🔍 Scanne deinen lokalen PC...")
    results = scanner.scan_network(
        ports=[21, 22, 23, 80, 443, 3306, 3389, 5432, 8080],
        fast_mode=True
    )
    
    print(scanner.get_summary())
    
    if results['total_hosts'] > 0:
        print("\n✅ Scan erfolgreich!")
        print("💡 Für bessere Visualisierung: Dashboard starten (Option 3)")
    else:
        print("\n⚠️  Keine offenen Ports gefunden")
        print("💡 Das ist normal - dein PC ist gut geschützt!")
        print("💡 Nutze DEMO MODE für Präsentationen (Option 1)")

def run_dashboard():
    """Startet Streamlit Dashboard"""
    print("\n📊 Starte DASHBOARD...")
    print("="*70)
    print("🚀 Streamlit Dashboard wird gestartet...")
    print("🌐 Öffnet automatisch im Browser")
    print()
    print("⚠️  Zum Beenden: CTRL+C drücken")
    print("="*70)
    print()
    
    import subprocess
    try:
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run',
            str(ROOT_DIR / 'dashboard' / 'app.py'),
            '--server.headless', 'true'
        ])
    except KeyboardInterrupt:
        print("\n\n✅ Dashboard beendet")
    except Exception as e:
        print(f"\n❌ Fehler: {e}")
        print("\n💡 Installiere Streamlit: pip install streamlit")

def generate_pdf_report():
    """Generiert PDF-Report"""
    print("\n📄 Generiere PDF-REPORT...")
    print("="*70)
    
    from reports.generator import ReportGenerator
    
    # Demo-Daten für Report
    demo_data = {
        'scan_id': 'DEMO-001',
        'network': '192.168.1.0/24',
        'total_hosts': 5,
        'critical_issues': 3,
        'warnings': 2,
        'timestamp': 'Demo'
    }
    
    generator = ReportGenerator()
    
    try:
        pdf_path = generator.generate_security_report(demo_data)
        print(f"\n✅ Report erstellt: {pdf_path}")
        print("💡 Öffne die PDF-Datei zum Anschauen!")
    except Exception as e:
        print(f"\n❌ Fehler beim Erstellen: {e}")
        print("💡 Installiere Dependencies: pip install -r requirements.txt")

def show_info():
    """Zeigt Projekt-Informationen"""
    info = """
╔══════════════════════════════════════════════════════════════════╗
║                    SECUREOFFICE HUB - INFO                       ║
╚══════════════════════════════════════════════════════════════════╝

📌 PROJEKTBESCHREIBUNG:
   Network Security Scanner & Analyzer
   Entwickelt für BVB Werkstudent Interview (IT-Sicherheit)

🎯 HAUPTFUNKTIONEN:
   • Network Scanner (findet Hosts & offene Ports)
   • Vulnerability Detection (bekannte Schwachstellen)
   • OSI-Layer Analyse (zeigt Netzwerk-Verständnis)
   • Firewall Analyzer (Regel-Empfehlungen)
   • Encryption Checker (TLS/SSL Prüfung)
   • Network Topology (Routing/Switching/VLANs)
   • PDF-Report Generator

🛡️ SICHERHEIT:
   ✅ 100% LEGAL - Kein Hacking!
   ✅ Demo-Modus für Präsentationen
   ✅ Localhost-only für Tests
   ✅ Keine fremden Netzwerke

🎓 ZEIGT KOMPETENZ IN:
   • Python-Programmierung
   • Netzwerk-Grundlagen (OSI, TCP/IP)
   • IT-Sicherheit (Vulnerabilities, Firewalls)
   • Verschlüsselung (TLS/SSL)
   • Datenbank (SQLite)
   • Web-Dashboard (Streamlit)
   • Report-Generierung (PDF)

📚 TECHNOLOGIEN:
   • Python 3.x
   • Streamlit (Dashboard)
   • SQLite (Datenbank)
   • ReportLab (PDF)
   • Socket/Subprocess (Network Scanning)

👨‍💻 ENTWICKELT VON:
   Armin (Bewerber für BVB Werkstudent IT-Sicherheit)

📅 INTERVIEW:
   16.10.2025 um 12:30 Uhr
   Borussia Dortmund

💡 VERWENDUNG IM INTERVIEW:
   1. Demo-Modus starten (Option 1)
   2. Dashboard zeigen (Option 3)
   3. PDF-Report präsentieren (Option 4)
   4. Technisches Wissen erklären (OSI, Security, etc.)

═══════════════════════════════════════════════════════════════════
"""
    print(info)

def main():
    """Hauptfunktion"""
    print_banner()
    
    while True:
        show_menu()
        
        try:
            choice = input("Deine Wahl: ").strip()
            
            if choice == '1':
                run_demo_mode()
            elif choice == '2':
                run_local_mode()
            elif choice == '3':
                run_dashboard()
            elif choice == '4':
                generate_pdf_report()
            elif choice == '5':
                show_info()
            elif choice == '0':
                print("\n👋 Auf Wiedersehen! Viel Erfolg beim Interview! 🍀")
                print("🟡⚫ HEJA BVB! ⚫🟡\n")
                break
            else:
                print("\n❌ Ungültige Eingabe! Bitte 0-5 wählen.")
            
            input("\n⏎  Drücke ENTER um fortzufahren...")
            
        except KeyboardInterrupt:
            print("\n\n👋 Programm beendet. Viel Erfolg! 🍀")
            break
        except Exception as e:
            print(f"\n❌ Fehler: {e}")
            input("\n⏎  Drücke ENTER um fortzufahren...")

if __name__ == "__main__":
    # Prüfe ob alle Dependencies installiert sind
    try:
        import streamlit
    except ImportError:
        print("\n⚠️  WARNUNG: Streamlit nicht installiert!")
        print("💡 Installiere mit: pip install -r requirements.txt\n")
    
    main()