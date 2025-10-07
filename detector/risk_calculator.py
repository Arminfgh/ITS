"""
SecureOffice Hub - Risk Calculator
Berechnet Security Risk Score
"""

from typing import Dict, List
from enum import Enum


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class RiskCalculator:
    """Berechnet Risiko-Scores"""
    
    def __init__(self):
        self.port_risks = {
            21: 15, 23: 20, 25: 5, 80: 8, 443: 2,
            445: 18, 1433: 12, 3306: 12, 3389: 15, 5432: 12
        }
    
    def calculate_overall_risk(self, scan_results: List[Dict], 
                               vuln_analysis: Dict = None) -> Dict:
        """Hauptfunktion: Berechnet Gesamt-Risiko"""
        
        print("\n" + "="*70)
        print("📊 RISK CALCULATION")
        print("="*70)
        
        # Berechne Teil-Scores
        ports_score = self._calc_ports_risk(scan_results)
        vuln_score = self._calc_vuln_risk(vuln_analysis) if vuln_analysis else 0
        enc_score = self._calc_encryption_risk(scan_results)
        
        # Gewichtet kombinieren
        overall = (ports_score * 0.3 + vuln_score * 0.5 + enc_score * 0.2)
        
        risk_level = self._get_risk_level(overall)
        
        print(f"🔌 Ports Risk: {ports_score:.1f}/100")
        print(f"🔍 Vuln Risk: {vuln_score:.1f}/100")
        print(f"🔐 Encryption Risk: {enc_score:.1f}/100")
        print(f"\n🎯 OVERALL: {overall:.1f}/100 - {risk_level.value}")
        
        return {
            'overall_score': overall,
            'risk_level': risk_level,
            'component_scores': {
                'ports': ports_score,
                'vulnerabilities': vuln_score,
                'encryption': enc_score
            },
            'risk_factors': self._get_risk_factors(scan_results, vuln_analysis),
            'recommendations': self._get_recommendations(overall, vuln_analysis)
        }
    
    def _calc_ports_risk(self, scan_results: List[Dict]) -> float:
        """Port-basiertes Risiko"""
        if not scan_results:
            return 0
        
        total_risk = 0
        port_count = 0
        
        for host in scan_results:
            for p in host.get('open_ports', []):
                port = p.get('port')
                port_count += 1
                total_risk += self.port_risks.get(port, 5)
        
        if port_count == 0:
            return 0
        
        avg = total_risk / port_count
        penalty = min(port_count * 2, 30)
        return min(100, avg + penalty)
    
    def _calc_vuln_risk(self, vuln_analysis: Dict) -> float:
        """Vulnerability-basiertes Risiko"""
        if not vuln_analysis:
            return 0
        
        weights = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3, 'INFO': 1}
        risk = 0
        
        for sev, vulns in vuln_analysis.get('by_severity', {}).items():
            risk += len(vulns) * weights.get(sev, 5)
        
        return min(100, risk)
    
    def _calc_encryption_risk(self, scan_results: List[Dict]) -> float:
        """Verschlüsselungs-Risiko"""
        encrypted = {443, 22, 993, 995, 465}
        critical_plain = {21, 23, 80}
        
        total = 0
        plain = 0
        critical = 0
        
        for host in scan_results:
            for p in host.get('open_ports', []):
                port = p.get('port')
                total += 1
                if port not in encrypted:
                    plain += 1
                    if port in critical_plain:
                        critical += 1
        
        if total == 0:
            return 0
        
        ratio = plain / total
        return min(100, ratio * 60 + critical * 10)
    
    def _get_risk_level(self, score: float) -> RiskLevel:
        """Score → Risk Level"""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _get_risk_factors(self, scan_results: List[Dict], 
                          vuln_analysis: Dict) -> List[Dict]:
        """Identifiziert Haupt-Risikofaktoren"""
        factors = []
        
        # Kritische Ports
        critical_ports = {21, 23, 445, 3389, 3306, 1433}
        for host in scan_results:
            for p in host.get('open_ports', []):
                if p['port'] in critical_ports:
                    factors.append({
                        'type': 'Critical Port Exposed',
                        'host': host['ip_address'],
                        'port': p['port'],
                        'service': p['service'],
                        'severity': 'HIGH'
                    })
        
        # Unverschlüsselte Services
        plain_ports = {21, 23, 80}
        for host in scan_results:
            for p in host.get('open_ports', []):
                if p['port'] in plain_ports:
                    factors.append({
                        'type': 'Unencrypted Service',
                        'host': host['ip_address'],
                        'port': p['port'],
                        'service': p['service'],
                        'severity': 'MEDIUM'
                    })
        
        return factors
    
    def _get_recommendations(self, score: float, 
                            vuln_analysis: Dict) -> List[str]:
        """Generiert Empfehlungen"""
        recs = []
        
        if score >= 80:
            recs.append("🔴 KRITISCH: Sofortige Maßnahmen erforderlich!")
            recs.append("Deaktiviere Telnet, FTP sofort")
            recs.append("Patche SMB gegen EternalBlue")
        
        if score >= 60:
            recs.append("🟠 Datenbanken nicht exponieren")
            recs.append("RDP nur über VPN")
            recs.append("Firewall Default Deny Policy")
        
        if score >= 40:
            recs.append("🟡 HTTPS erzwingen")
            recs.append("SSH härten (Keys only)")
            recs.append("Monitoring einrichten")
        
        recs.append("✅ Regelmäßige Security-Audits")
        recs.append("✅ Patch Management")
        
        return recs
    
    def generate_risk_report(self, risk_assessment: Dict) -> str:
        """Generiert lesbaren Report"""
        score = risk_assessment['overall_score']
        level = risk_assessment['risk_level'].value
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    RISK ASSESSMENT REPORT                        ║
╚══════════════════════════════════════════════════════════════════╝

📊 OVERALL RISK SCORE: {score:.1f}/100
🎯 RISK LEVEL: {level}

📈 COMPONENT SCORES:
   Ports:          {risk_assessment['component_scores']['ports']:.1f}/100
   Vulnerabilities: {risk_assessment['component_scores']['vulnerabilities']:.1f}/100
   Encryption:     {risk_assessment['component_scores']['encryption']:.1f}/100

🔍 TOP RISK FACTORS:
"""
        
        for i, factor in enumerate(risk_assessment['risk_factors'][:5], 1):
            report += f"""
   [{i}] {factor['type']}
       Host: {factor['host']} | Port: {factor['port']} ({factor['service']})
       Severity: {factor['severity']}
"""
        
        report += "\n💡 EMPFEHLUNGEN:\n"
        for rec in risk_assessment['recommendations'][:8]:
            report += f"   • {rec}\n"
        
        return report


if __name__ == "__main__":
    print("🧪 Teste Risk Calculator...\n")
    
    calc = RiskCalculator()
    
    # Mock Data
    mock_scan = [
        {
            'ip_address': '192.168.1.10',
            'hostname': 'server',
            'open_ports': [
                {'port': 21, 'service': 'FTP'},
                {'port': 23, 'service': 'Telnet'},
                {'port': 445, 'service': 'SMB'}
            ]
        }
    ]
    
    mock_vuln = {
        'by_severity': {
            'CRITICAL': [1, 2, 3],
            'HIGH': [1, 2],
            'MEDIUM': [1],
            'LOW': [],
            'INFO': []
        }
    }
    
    assessment = calc.calculate_overall_risk(mock_scan, mock_vuln)
    print(calc.generate_risk_report(assessment))
    
    print("\n✅ Risk Calculator Test OK!")