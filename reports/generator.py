"""
SecureOffice Hub - PDF Report Generator
Erstellt professionelle Security Reports
"""

from pathlib import Path
from datetime import datetime
from typing import Dict
import json


class ReportGenerator:
    """Generiert Security Reports (PDF oder TXT)"""
    
    def __init__(self):
        self.reports_dir = Path(__file__).parent.parent / "data" / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_security_report(self, scan_data: Dict, 
                                 vuln_data: Dict = None,
                                 risk_data: Dict = None) -> str:
        """Hauptfunktion: Generiert Report"""
        
        print("\n" + "="*70)
        print("📄 GENERIERE SECURITY REPORT")
        print("="*70)
        
        # Versuche PDF, Fallback zu TXT
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            from reportlab.lib.colors import HexColor
            
            return self._generate_pdf_report(scan_data, vuln_data, risk_data)
        except ImportError:
            print("⚠️  ReportLab nicht installiert - Erstelle TXT Report")
            return self._generate_text_report(scan_data, vuln_data, risk_data)
        except Exception as e:
            print(f"❌ PDF-Fehler: {e} - Fallback zu TXT")
            return self._generate_text_report(scan_data, vuln_data, risk_data)
    
    def _generate_pdf_report(self, scan_data, vuln_data, risk_data) -> str:
        """Erstellt PDF Report"""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.pdfgen import canvas
        from reportlab.lib.colors import HexColor
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = scan_data.get('scan_id', 'UNKNOWN')
        filename = f"security_report_{scan_id}_{timestamp}.pdf"
        filepath = self.reports_dir / filename
        
        print(f"📝 Erstelle PDF: {filename}")
        
        c = canvas.Canvas(str(filepath), pagesize=A4)
        width, height = A4
        
        # BVB Colors
        black = HexColor('#000000')
        yellow = HexColor('#FDE100')
        
        # Header
        c.setFillColor(black)
        c.rect(0, height - 3*cm, width, 3*cm, fill=True)
        c.setFillColor(yellow)
        c.setFont("Helvetica-Bold", 20)
        c.drawString(2*cm, height - 2*cm, "SECURITY ASSESSMENT REPORT")
        c.setFillColor(HexColor('#FFFFFF'))
        c.setFont("Helvetica", 10)
        c.drawString(2*cm, height - 2.5*cm, f"Scan-ID: {scan_id}")
        c.drawString(2*cm, height - 2.7*cm, f"Date: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        # Content
        y = height - 4*cm
        
        # Summary
        c.setFillColor(black)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2*cm, y, "EXECUTIVE SUMMARY")
        y -= 0.7*cm
        
        c.setFont("Helvetica", 10)
        c.drawString(2*cm, y, f"Network: {scan_data.get('network_range', 'N/A')}")
        y -= 0.5*cm
        c.drawString(2*cm, y, f"Hosts: {scan_data.get('total_hosts', 0)}")
        y -= 0.5*cm
        c.drawString(2*cm, y, f"Duration: {scan_data.get('scan_duration', 0):.2f}s")
        y -= 1*cm
        
        # Risk Score
        if risk_data:
            score = risk_data.get('overall_score', 0)
            level = risk_data.get('risk_level', 'UNKNOWN')
            
            c.setFont("Helvetica-Bold", 12)
            c.drawString(2*cm, y, "RISK ASSESSMENT")
            y -= 0.7*cm
            
            # Color based on score
            if score >= 80:
                color = HexColor('#f44336')
            elif score >= 60:
                color = HexColor('#ff9800')
            elif score >= 40:
                color = HexColor('#fdd835')
            else:
                color = HexColor('#4caf50')
            
            c.setFillColor(color)
            c.rect(2*cm, y - 1.2*cm, 5*cm, 1.2*cm, fill=True)
            c.setFillColor(HexColor('#FFFFFF'))
            c.setFont("Helvetica-Bold", 14)
            c.drawString(2.3*cm, y - 0.7*cm, f"Score: {score:.1f}/100")
            c.setFont("Helvetica", 10)
            c.drawString(2.3*cm, y - 1*cm, f"Level: {level}")
            y -= 1.5*cm
        
        # Vulnerabilities
        if vuln_data:
            c.setFillColor(black)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(2*cm, y, "VULNERABILITIES")
            y -= 0.7*cm
            
            by_sev = vuln_data.get('by_severity', {})
            c.setFont("Helvetica", 10)
            
            c.drawString(2*cm, y, f"Critical: {len(by_sev.get('CRITICAL', []))}")
            y -= 0.4*cm
            c.drawString(2*cm, y, f"High: {len(by_sev.get('HIGH', []))}")
            y -= 0.4*cm
            c.drawString(2*cm, y, f"Medium: {len(by_sev.get('MEDIUM', []))}")
            y -= 0.4*cm
            c.drawString(2*cm, y, f"Low: {len(by_sev.get('LOW', []))}")
            y -= 1*cm
        
        # Hosts
        c.setFillColor(black)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(2*cm, y, "DISCOVERED HOSTS")
        y -= 0.7*cm
        
        c.setFont("Helvetica", 9)
        for host in scan_data.get('hosts', [])[:5]:
            c.drawString(2*cm, y, f"{host.get('ip_address')} - {host.get('hostname')}")
            y -= 0.4*cm
            c.drawString(2.5*cm, y, f"OS: {host.get('os_guess', 'Unknown')}")
            y -= 0.4*cm
            c.drawString(2.5*cm, y, f"Ports: {len(host.get('open_ports', []))}")
            y -= 0.5*cm
        
        # Footer
        c.setFillColor(HexColor('#666666'))
        c.setFont("Helvetica", 8)
        c.drawString(2*cm, 1.5*cm, "SecureOffice Hub - BVB Interview Project")
        c.drawString(2*cm, 1*cm, "100% Legal & Safe")
        
        c.save()
        print(f"✅ PDF erstellt: {filepath}")
        return str(filepath)
    
    def _generate_text_report(self, scan_data, vuln_data, risk_data) -> str:
        """Fallback: Text Report"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = scan_data.get('scan_id', 'UNKNOWN')
        filename = f"security_report_{scan_id}_{timestamp}.txt"
        filepath = self.reports_dir / filename
        
        print(f"📝 Erstelle TXT Report: {filename}")
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║              SECURITY ASSESSMENT REPORT                          ║
╚══════════════════════════════════════════════════════════════════╝

Scan-ID: {scan_id}
Generated: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}

═══════════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════

Network Range:    {scan_data.get('network_range', 'N/A')}
Hosts Found:      {scan_data.get('total_hosts', 0)}
Scan Duration:    {scan_data.get('scan_duration', 0):.2f} seconds
Status:           {scan_data.get('status', 'unknown')}

"""
        
        # Risk Assessment
        if risk_data:
            score = risk_data.get('overall_score', 0)
            level = risk_data.get('risk_level', 'UNKNOWN')
            
            report += f"""
═══════════════════════════════════════════════════════════════════
RISK ASSESSMENT
═══════════════════════════════════════════════════════════════════

Overall Risk Score: {score:.1f}/100
Risk Level:         {level}

Component Scores:
  - Ports:            {risk_data.get('component_scores', {}).get('ports', 0):.1f}/100
  - Vulnerabilities:  {risk_data.get('component_scores', {}).get('vulnerabilities', 0):.1f}/100
  - Encryption:       {risk_data.get('component_scores', {}).get('encryption', 0):.1f}/100

"""
        
        # Vulnerabilities
        if vuln_data:
            by_sev = vuln_data.get('by_severity', {})
            
            report += f"""
═══════════════════════════════════════════════════════════════════
VULNERABILITIES
═══════════════════════════════════════════════════════════════════

🔴 CRITICAL:  {len(by_sev.get('CRITICAL', []))}
🟠 HIGH:      {len(by_sev.get('HIGH', []))}
🟡 MEDIUM:    {len(by_sev.get('MEDIUM', []))}
🟢 LOW:       {len(by_sev.get('LOW', []))}

"""
            
            # Critical Details
            if by_sev.get('CRITICAL'):
                report += "Critical Findings:\n\n"
                for v in by_sev['CRITICAL'][:5]:
                    report += f"  • {v['title']}\n"
                    report += f"    Host: {v['host']}\n"
                    report += f"    Port: {v['port']} ({v['service']})\n"
                    report += f"    Fix: {v['recommendation']}\n\n"
        
        # Discovered Hosts
        report += f"""
═══════════════════════════════════════════════════════════════════
DISCOVERED HOSTS
═══════════════════════════════════════════════════════════════════

"""
        
        for i, host in enumerate(scan_data.get('hosts', []), 1):
            report += f"""
[{i}] {host.get('ip_address')} - {host.get('hostname')}
    Status:       {host.get('status', 'unknown')}
    OS:           {host.get('os_guess', 'Unknown')}
    MAC:          {host.get('mac_address', 'N/A')}
    Open Ports:   {len(host.get('open_ports', []))}
    
    Ports:
"""
            for p in host.get('open_ports', []):
                report += f"      - Port {p['port']}: {p.get('service', 'unknown')}\n"
        
        # Recommendations
        if risk_data and risk_data.get('recommendations'):
            report += f"""

═══════════════════════════════════════════════════════════════════
RECOMMENDATIONS
═══════════════════════════════════════════════════════════════════

"""
            for rec in risk_data['recommendations'][:10]:
                report += f"  • {rec}\n"
        
        # Footer
        report += f"""

═══════════════════════════════════════════════════════════════════
REPORT INFORMATION
═══════════════════════════════════════════════════════════════════

Generated by:     SecureOffice Hub
Purpose:          BVB Werkstudent Interview Demo
Legal Status:     100% Legal & Safe
Contact:          Armin (Bewerber)

═══════════════════════════════════════════════════════════════════
"""
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✅ TXT Report erstellt: {filepath}")
        return str(filepath)
    
    def generate_json_export(self, scan_data: Dict, 
                            vuln_data: Dict = None,
                            risk_data: Dict = None) -> str:
        """Exportiert als JSON"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = scan_data.get('scan_id', 'UNKNOWN')
        filename = f"security_export_{scan_id}_{timestamp}.json"
        filepath = self.reports_dir / filename
        
        export_data = {
            'scan_results': scan_data,
            'vulnerability_analysis': vuln_data,
            'risk_assessment': risk_data,
            'generated_at': datetime.now().isoformat()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"✅ JSON Export: {filepath}")
        return str(filepath)


if __name__ == "__main__":
    print("📄 Teste Report Generator...\n")
    
    generator = ReportGenerator()
    
    # Mock Data
    mock_scan = {
        'scan_id': 'TEST-001',
        'network_range': '192.168.43.0/24',
        'total_hosts': 3,
        'scan_duration': 2.5,
        'status': 'completed',
        'hosts': [
            {
                'ip_address': '192.168.43.1',
                'hostname': 'hotspot',
                'status': 'up',
                'os_guess': 'Android',
                'open_ports': [
                    {'port': 80, 'service': 'HTTP'},
                    {'port': 443, 'service': 'HTTPS'}
                ]
            }
        ]
    }
    
    mock_risk = {
        'overall_score': 65.5,
        'risk_level': 'HIGH',
        'component_scores': {
            'ports': 55.0,
            'vulnerabilities': 75.0,
            'encryption': 45.0
        },
        'recommendations': [
            'HTTPS erzwingen',
            'Firewall konfigurieren',
            'Patches installieren'
        ]
    }
    
    # Test Report Generation
    report_path = generator.generate_security_report(mock_scan, None, mock_risk)
    print(f"\n✅ Report erstellt: {report_path}")
    
    # Test JSON Export
    json_path = generator.generate_json_export(mock_scan, None, mock_risk)
    print(f"✅ JSON Export: {json_path}")
    
    print("\n✅ Report Generator Test abgeschlossen!")