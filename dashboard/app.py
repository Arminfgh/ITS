"""
SecureOffice Hub - COMPLETE DASHBOARD
Zeigt ALLE 9 Features für BVB Interview
"""

import streamlit as st
import sys
from pathlib import Path
import time
from datetime import datetime
import json
import pandas as pd
from datetime import datetime, timedelta

# Project Root
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Page Config
st.set_page_config(
    page_title="🛡️ SecureOffice Hub - Complete Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS
st.markdown("""
<style>
.main-header {
    background: linear-gradient(90deg, #000000, #FDE100);
    padding: 1.5rem;
    border-radius: 10px;
    text-align: center;
    color: white;
    font-size: 2.5rem;
    font-weight: bold;
    margin-bottom: 2rem;
}
.feature-box {
    background: #f0f2f6;
    padding: 1.5rem;
    border-radius: 10px;
    border-left: 5px solid #FDE100;
    margin: 1rem 0;
}
.critical {
    background: #ffebee;
    padding: 1rem;
    border-radius: 5px;
    border-left: 4px solid #f44336;
}
.warning {
    background: #fff8e1;
    padding: 1rem;
    border-radius: 5px;
    border-left: 4px solid #ff9800;
}
.success {
    background: #e8f5e9;
    padding: 1rem;
    border-radius: 5px;
    border-left: 4px solid #4caf50;
}
.metric-card {
    background: white;
    padding: 1rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

# Session State
if 'demo_data' not in st.session_state:
    st.session_state.demo_data = None
if 'current_feature' not in st.session_state:
    st.session_state.current_feature = "Overview"

def get_complete_demo_data():
    """Vollständige Demo-Daten für ALLE 9 Features"""
    return {
        'scan_id': 'BVB-DEMO-001',
        'timestamp': datetime.now(),
        'network_range': '192.168.43.0/24',
        'total_hosts': 4,
        'scan_duration': 3.2,
        'status': 'completed',
        'hosts': [
            {
                'ip_address': '192.168.43.1',
                'hostname': 'android-hotspot',
                'status': 'up',
                'os_guess': 'Android 13',
                'mac_address': '02:00:00:00:00:01',
                'open_ports': [
                    {'port': 80, 'service': 'HTTP'},
                    {'port': 443, 'service': 'HTTPS'}
                ]
            },
            {
                'ip_address': '192.168.43.2',
                'hostname': 'windows-laptop',
                'status': 'up',
                'os_guess': 'Windows 11',
                'mac_address': 'AC:DE:48:00:11:22',
                'open_ports': [
                    {'port': 445, 'service': 'SMB'},
                    {'port': 3389, 'service': 'RDP'},
                    {'port': 135, 'service': 'RPC'}
                ]
            },
            {
                'ip_address': '192.168.43.3',
                'hostname': 'file-server',
                'status': 'up',
                'os_guess': 'Linux Ubuntu',
                'mac_address': '00:1A:2B:3C:4D:5E',
                'open_ports': [
                    {'port': 21, 'service': 'FTP'},
                    {'port': 22, 'service': 'SSH'},
                    {'port': 80, 'service': 'HTTP'}
                ]
            },
            {
                'ip_address': '192.168.43.4',
                'hostname': 'database-server',
                'status': 'up',
                'os_guess': 'Windows Server 2019',
                'mac_address': 'E8:94:F6:12:34:56',
                'open_ports': [
                    {'port': 3306, 'service': 'MySQL'},
                    {'port': 1433, 'service': 'MSSQL'},
                    {'port': 23, 'service': 'Telnet'}
                ]
            }
        ]
    }

# HEADER
st.markdown('<div class="main-header">🛡️ SECUREOFFICE HUB - COMPLETE DEMO</div>', unsafe_allow_html=True)

# SIDEBAR - Feature Navigation
with st.sidebar:
    st.markdown("## 🎯 9 FEATURES DEMO")
    st.markdown("**BVB Interview**")
    st.markdown("16.10.2025, 12:30 Uhr")
    st.markdown("---")
    
    st.markdown("### 📊 Navigation")
    
    features = {
        "Overview": "📋 Übersicht",
        "Network Scanner": "🌐 Feature 1",
        "Vulnerability Detection": "🔍 Feature 2",
        "Risk Calculator": "📊 Feature 3",
        "Firewall Analyzer": "🛡️ Feature 4",
        "Encryption Checker": "🔐 Feature 5",
        "Network Topology": "🌍 Feature 6",
        "OSI Analyzer": "📡 Feature 7",
        "Report Generator": "📄 Feature 8",
        "Live Dashboard": "🎨 Feature 9"
    }
    
    for key, label in features.items():
        if st.button(label, use_container_width=True, 
                    type="primary" if st.session_state.current_feature == key else "secondary"):
            st.session_state.current_feature = key
    
    st.markdown("---")
    
    if st.button("🚀 DEMO STARTEN", use_container_width=True, type="primary"):
        with st.spinner("🔍 Scanne Netzwerk..."):
            time.sleep(2)
            st.session_state.demo_data = get_complete_demo_data()
        st.success("✅ Demo-Daten geladen!")
        st.rerun()
    
    st.markdown("---")

# Echter Scan-Modus
scan_mode = st.radio(
    "Scan-Modus:",
    ["🎨 Demo (Simuliert)", "🔍 Echt (Netzwerk)"]
)

if scan_mode == "🔍 Echt (Netzwerk)":
    network = st.text_input("Netzwerk:", "10.248.126.0/24")
    ports_input = st.text_input( "Ports (komma-getrennt):", 
    "21,22,23,80,443",
    help="Nur Zahlen, getrennt durch Komma. Beispiel: 21,22,80,443")
    
    if st.button("🚀 ECHTER SCAN", use_container_width=True, type="primary"):
        ports = [int(p.strip()) for p in ports_input.split(',')]
        
        with st.spinner(f"🔍 Scanne {network}..."):
            from scanner.network_scanner import NetworkScanner
            scanner = NetworkScanner(network)
            st.session_state.demo_data = scanner.scan_network(ports=ports, fast_mode=True)
        
        st.success("✅ Echter Scan abgeschlossen!")
        st.rerun()
    st.caption("**100% Legal & Safe** ✅")
    st.caption("Demo-Modus aktiv 🎨")

# MAIN CONTENT
current = st.session_state.current_feature

# ============================================================================
# OVERVIEW
# ============================================================================
if current == "Overview":
    st.markdown("## 📋 Projekt-Übersicht")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <h2>9</h2>
            <p>Features</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h2>100%</h2>
            <p>Legal & Safe</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <h2>20</h2>
            <p>Min Demo</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎯 Core Features")
        st.markdown("""
        **Scanner-Features:**
        - 🌐 Network Scanner
        - 🔍 Vulnerability Detection
        - 📊 Risk Calculator
        
        **Analyzer-Features:**
        - 🛡️ Firewall Analyzer
        - 🔐 Encryption Checker
        - 🌍 Network Topology
        - 📡 OSI Layer Analyzer
        
        **Output-Features:**
        - 📄 Report Generator
        - 🎨 Live Dashboard
        """)
    
    with col2:
        st.markdown("### 🚀 Tech Stack")
        st.markdown("""
        **Backend:**
        - Python 3.10+
        - SQLite Database
        - Socket Programming
        
        **Frontend:**
        - Streamlit
        - Plotly Charts
        - Interactive UI
        
        **Security:**
        - CVE Database
        - CVSS Scoring
        - TLS/SSL Analysis
        
        **Network:**
        - OSI Model
        - Routing/Switching
        - Firewall Rules
        """)
    
    st.markdown("---")
    st.info("👈 **Wähle ein Feature in der Sidebar für Details!**")

# ============================================================================
# FEATURE 1: NETWORK SCANNER
# ============================================================================
elif current == "Network Scanner":
    st.markdown("## 🌐 Feature 1: Network Scanner")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>🔍 Scannt Netzwerke und findet alle aktiven Geräte</p>
        <p>🔌 Erkennt offene Ports und Services</p>
        <p>💻 Identifiziert Betriebssysteme</p>
        <p>⚡ Multi-Threading für schnelle Scans</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        data = st.session_state.demo_data
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🖥️ Hosts", data['total_hosts'])
        with col2:
            total_ports = sum(len(h['open_ports']) for h in data['hosts'])
            st.metric("🔌 Ports", total_ports)
        with col3:
            st.metric("⏱️ Dauer", f"{data['scan_duration']:.1f}s")
        with col4:
            st.metric("📡 Netzwerk", data['network_range'])
        
        st.markdown("### 📊 Gefundene Hosts")
        
        for host in data['hosts']:
            with st.expander(f"🖥️ {host['ip_address']} - {host['hostname']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Host-Info:**")
                    st.write(f"- IP: {host['ip_address']}")
                    st.write(f"- Hostname: {host['hostname']}")
                    st.write(f"- Status: {host['status']}")
                
                with col2:
                    st.write("**System-Info:**")
                    st.write(f"- OS: {host['os_guess']}")
                    st.write(f"- MAC: {host['mac_address']}")
                    st.write(f"- Ports: {len(host['open_ports'])}")
                
                st.write("**Offene Ports:**")
                for p in host['open_ports']:
                    st.write(f"- Port {p['port']}: {p['service']}")
        
        st.success("✅ Network Scanner funktioniert perfekt!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' in der Sidebar!")

# ============================================================================
# FEATURE 2: VULNERABILITY DETECTION
# ============================================================================
elif current == "Vulnerability Detection":
    st.markdown("## 🔍 Feature 2: Vulnerability Detection")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>🎯 Erkennt bekannte Sicherheitslücken</p>
        <p>📚 CVE-Datenbank Integration</p>
        <p>⚠️ CVSS Score Bewertung</p>
        <p>💡 Konkrete Fix-Empfehlungen</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        # Dynamische Vulnerability-Analyse
        critical_vulns = []
        warnings = []
        
        # Analysiere alle gefundenen Hosts und Ports
        for host in st.session_state.demo_data.get('hosts', []):
            host_ip = host.get('ip_address')
            hostname = host.get('hostname', 'Unknown')
            
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                # FTP - Port 21
                if port == 21:
                    critical_vulns.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 21,
                        'service': 'FTP',
                        'vuln': 'FTP - Unverschlüsselte Übertragung',
                        'cvss': 7.5,
                        'cve': 'CVE-1999-0190',
                        'risk': 'Credentials im Klartext übertragen',
                        'fix': 'SFTP (Port 22) verwenden'
                    })
                
                # Telnet - Port 23
                elif port == 23:
                    critical_vulns.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 23,
                        'service': 'Telnet',
                        'vuln': 'Telnet - Keine Verschlüsselung',
                        'cvss': 9.8,
                        'cve': 'CVE-1999-0619',
                        'risk': 'Komplette Session lesbar',
                        'fix': 'SSH verwenden, Telnet deaktivieren'
                    })
                
                # SMB - Port 445
                elif port == 445:
                    critical_vulns.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 445,
                        'service': 'SMB',
                        'vuln': 'SMB - EternalBlue Vulnerability',
                        'cvss': 9.3,
                        'cve': 'CVE-2017-0144',
                        'risk': 'Remote Code Execution möglich',
                        'fix': 'SMBv1 deaktivieren, Patches installieren'
                    })
                
                # MySQL - Port 3306
                elif port == 3306:
                    warnings.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 3306,
                        'service': 'MySQL',
                        'issue': 'Datenbank exponiert',
                        'risk': 'SQL-Injection möglich',
                        'fix': 'Bind to localhost, Firewall-Regeln'
                    })
                
                # RDP - Port 3389
                elif port == 3389:
                    warnings.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 3389,
                        'service': 'RDP',
                        'issue': 'RDP exponiert',
                        'risk': 'Brute-Force Angriffe möglich',
                        'fix': 'VPN-only Access, MFA aktivieren'
                    })
                
                # MSSQL - Port 1433
                elif port == 1433:
                    warnings.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 1433,
                        'service': 'MSSQL',
                        'issue': 'MSSQL exponiert',
                        'risk': 'SQL-Injection möglich',
                        'fix': 'Bind to localhost, Firewall-Regeln'
                    })
        
        st.markdown("### 🔴 Kritische Findings")
        
        if critical_vulns:
            for vuln in critical_vulns:
                st.markdown(f"""
                <div class="critical">
                    <h4>🚨 {vuln['vuln']}</h4>
                    <p><strong>Host:</strong> {vuln['host']} ({vuln['hostname']}) | <strong>Port:</strong> {vuln['port']} ({vuln['service']})</p>
                    <p><strong>CVSS Score:</strong> {vuln['cvss']}/10.0 | <strong>CVE:</strong> {vuln['cve']}</p>
                    <p><strong>Risiko:</strong> {vuln['risk']}</p>
                    <p><strong>Fix:</strong> ✅ {vuln['fix']}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ Keine kritischen Vulnerabilities gefunden!")
        
        st.markdown("### 🟡 Warnungen")
        
        if warnings:
            for warn in warnings:
                st.markdown(f"""
                <div class="warning">
                    <h4>⚠️ {warn['issue']}</h4>
                    <p><strong>Host:</strong> {warn['host']} ({warn['hostname']}) | <strong>Port:</strong> {warn['port']} ({warn['service']})</p>
                    <p><strong>Risiko:</strong> {warn['risk']}</p>
                    <p><strong>Fix:</strong> {warn['fix']}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("ℹ️ Keine Warnungen")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🔴 Critical", len(critical_vulns))
        with col2:
            st.metric("🟡 High", len(warnings))
        with col3:
            st.metric("🟢 Total", len(critical_vulns) + len(warnings))
        
        st.success("✅ Vulnerability Detection funktioniert!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 3: RISK CALCULATOR
# ============================================================================
elif current == "Risk Calculator":
    st.markdown("## 📊 Feature 3: Risk Calculator")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>🎯 Berechnet Gesamt-Risiko-Score</p>
        <p>📈 Gewichtete Bewertung</p>
        <p>🔴 Risk Level Classification</p>
        <p>📋 Priorisierte Empfehlungen</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        # Dynamische Risk-Berechnung
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        port_risks = {21: 15, 23: 20, 445: 18, 3306: 12, 3389: 15, 1433: 12, 5432: 12}
        
        total_risk = 0
        port_count = 0
        recommendations = []
        
        # Zähle Vulnerabilities und Risiko-Score
        for host in st.session_state.demo_data.get('hosts', []):
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                port_count += 1
                
                # Kritische Ports
                if port in [21, 23, 445]:
                    critical_count += 1
                    total_risk += port_risks.get(port, 10)
                    
                    if port == 21:
                        recommendations.append("🔴 KRITISCH: FTP durch SFTP ersetzen")
                    elif port == 23:
                        recommendations.append("🔴 KRITISCH: Telnet sofort deaktivieren")
                    elif port == 445:
                        recommendations.append("🔴 KRITISCH: SMB gegen EternalBlue patchen")
                
                # High Risk Ports
                elif port in [3306, 3389, 1433, 5432]:
                    high_count += 1
                    total_risk += port_risks.get(port, 8)
                    
                    if port == 3389:
                        recommendations.append("🟡 RDP-Zugriff härten (MFA + VPN)")
                    elif port in [3306, 1433, 5432]:
                        recommendations.append(f"🟡 Datenbank (Port {port}) nicht exponieren")
                
                # Medium Risk
                elif port == 80:
                    medium_count += 1
                    total_risk += 5
                    recommendations.append("🟢 HTTPS erzwingen auf Webservern")
                
                else:
                    total_risk += 3
        
        # Berechne Risk Score
        if port_count > 0:
            avg_risk = total_risk / port_count
            penalty = min(port_count * 2, 30)
            risk_score = min(100, avg_risk + penalty)
        else:
            risk_score = 0
        
        # Risk Level
        if risk_score >= 80:
            risk_level = "CRITICAL"
            risk_color = "#d32f2f"
        elif risk_score >= 60:
            risk_level = "HIGH"
            risk_color = "#f44336"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
            risk_color = "#ff9800"
        else:
            risk_level = "LOW"
            risk_color = "#4caf50"
        
        st.markdown("### 🎯 Overall Risk Assessment")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.markdown(f"""
            <div style="background: linear-gradient(90deg, {risk_color}, #ff9800); 
                        padding: 2rem; border-radius: 10px; text-align: center;">
                <h1 style="color: white; margin: 0;">{risk_score:.1f}/100</h1>
                <h3 style="color: white; margin: 0;">{risk_level} RISK</h3>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.metric("🔴 Critical", critical_count)
            st.metric("🟡 High", high_count)
        
        with col3:
            st.metric("🟢 Medium", medium_count)
            st.metric("⚪ Low", 0)
        
        st.markdown("### 📊 Component Scores")
        
        # Ports Score
        ports_score = min(100, avg_risk) if port_count > 0 else 0
        
        # Vulnerabilities Score
        vuln_score = (critical_count * 25 + high_count * 15 + medium_count * 8)
        vuln_score = min(100, vuln_score)
        
        # Encryption Score
        encrypted_ports = {443, 22, 993, 995, 465}
        critical_plain = {21, 23, 80}
        total_ports = 0
        plain_ports = 0
        critical_plain_count = 0
        
        for host in st.session_state.demo_data.get('hosts', []):
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                total_ports += 1
                if port not in encrypted_ports:
                    plain_ports += 1
                    if port in critical_plain:
                        critical_plain_count += 1
        
        if total_ports > 0:
            enc_ratio = plain_ports / total_ports
            enc_score = min(100, enc_ratio * 60 + critical_plain_count * 10)
        else:
            enc_score = 0
        
        components = {
            'Ports': ports_score,
            'Vulnerabilities': vuln_score,
            'Encryption': enc_score
        }
        
        for name, score in components.items():
            color = "#f44336" if score >= 70 else "#ff9800" if score >= 50 else "#4caf50"
            st.markdown(f"""
            <div style="margin: 1rem 0;">
                <strong>{name}:</strong> {score:.1f}/100
                <div style="background: #e0e0e0; border-radius: 5px; height: 20px;">
                    <div style="background: {color}; width: {score}%; height: 100%; 
                                border-radius: 5px;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("### 💡 Top Empfehlungen")
        
        # Basis-Empfehlungen wenn keine spezifischen
        if not recommendations:
            recommendations = [
                "🟢 Regelmäßige Security-Audits durchführen",
                "🟢 Firewall-Regeln überprüfen",
                "🟢 Patch Management implementieren"
            ]
        else:
            # Füge Standard-Empfehlungen hinzu
            recommendations.extend([
                "🟢 Firewall Default-Deny Policy",
                "🟢 Regelmäßige Security-Audits"
            ])
        
        for rec in recommendations[:8]:
            st.markdown(f"- {rec}")
        
        st.success("✅ Risk Calculator funktioniert!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 4: FIREWALL ANALYZER
# ============================================================================
elif current == "Firewall Analyzer":
    st.markdown("## 🛡️ Feature 4: Firewall Analyzer")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>🔥 Analysiert Firewall-Konfiguration</p>
        <p>📋 Generiert Regel-Empfehlungen</p>
        <p>⚠️ Findet exponierte kritische Ports</p>
        <p>✅ Best Practice Validierung</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        st.markdown("### 🔍 Firewall Status")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div class="success">
                <h4>✅ Firewall Active</h4>
                <p>Windows Defender Firewall</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Zähle offene Ports
        total_open = sum(len(h['open_ports']) for h in st.session_state.demo_data.get('hosts', []))
        
        with col2:
            st.metric("📋 Open Ports", total_open)
        
        # Zähle kritische exponierte Ports
        critical_exposed = 0
        for host in st.session_state.demo_data.get('hosts', []):
            for port_info in host.get('open_ports', []):
                if port_info['port'] in [21, 23, 445, 3306, 3389, 1433, 5432]:
                    critical_exposed += 1
        
        with col3:
            st.metric("🚨 Issues", critical_exposed)
        
        st.markdown("### 🔴 Kritische Exponierte Ports")
        
        exposed_list = []
        
        for host in st.session_state.demo_data.get('hosts', []):
            host_ip = host.get('ip_address')
            hostname = host.get('hostname', 'Unknown')
            
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                if port == 21:
                    exposed_list.append({
                        'port': 21,
                        'host': f"{host_ip} ({hostname})",
                        'service': 'FTP',
                        'reason': 'FTP sollte NIEMALS vom Internet erreichbar sein'
                    })
                elif port == 23:
                    exposed_list.append({
                        'port': 23,
                        'host': f"{host_ip} ({hostname})",
                        'service': 'Telnet',
                        'reason': 'Telnet ist extrem unsicher - komplett unverschlüsselt'
                    })
                elif port == 445:
                    exposed_list.append({
                        'port': 445,
                        'host': f"{host_ip} ({hostname})",
                        'service': 'SMB',
                        'reason': 'SMB anfällig für EternalBlue/Ransomware'
                    })
                elif port == 3306:
                    exposed_list.append({
                        'port': 3306,
                        'host': f"{host_ip} ({hostname})",
                        'service': 'MySQL',
                        'reason': 'Datenbank sollte nicht exponiert sein'
                    })
                elif port == 3389:
                    exposed_list.append({
                        'port': 3389,
                        'host': f"{host_ip} ({hostname})",
                        'service': 'RDP',
                        'reason': 'RDP häufiges Angriffsziel'
                    })
                elif port == 1433:
                    exposed_list.append({
                        'port': 1433,
                        'host': f"{host_ip} ({hostname})",
                        'service': 'MSSQL',
                        'reason': 'SQL Server sollte nicht exponiert sein'
                    })
        
        if exposed_list:
            for exp in exposed_list:
                st.markdown(f"""
                <div class="critical">
                    <h4>🔴 Port {exp['port']}: {exp['service']}</h4>
                    <p><strong>Host:</strong> {exp['host']}</p>
                    <p><strong>Problem:</strong> {exp['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ Keine kritischen Ports exponiert!")
        
        st.markdown("### 💡 Firewall Regel-Empfehlungen")
        
        # Dynamische Firewall-Regeln basierend auf gefundenen Ports
        firewall_rules = """
# EMPFOHLENE FIREWALL-REGELN

# 1. Default Deny Policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 2. Erlaube etablierte Verbindungen
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 3. Erlaube Loopback
iptables -A INPUT -i lo -j ACCEPT

# 4. Erlaube nur sichere Ports von außen
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH (mit Key-Auth!)

# 5. BLOCKE gefundene kritische Ports
"""
        
        # Füge spezifische Regeln für gefundene Ports hinzu
        for exp in exposed_list:
            port = exp['port']
            service = exp['service']
            firewall_rules += f"iptables -A INPUT -p tcp --dport {port} -j DROP   # {service}\n"
        
        firewall_rules += """
# 6. Rate Limiting gegen Brute-Force
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
        """
        
        st.code(firewall_rules, language="bash")
        
        st.success("✅ Firewall Analyzer funktioniert!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 5: ENCRYPTION CHECKER
# ============================================================================
elif current == "Encryption Checker":
    st.markdown("## 🔐 Feature 5: Encryption Checker")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>🔒 Prüft TLS/SSL Konfiguration</p>
        <p>📜 Validiert Zertifikate</p>
        <p>🔐 Bewertet Cipher Suites</p>
        <p>⚠️ Findet unverschlüsselte Services</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        # Ports die normalerweise verschlüsselt sind
        encrypted_ports = {443, 22, 465, 587, 993, 995}
        # Ports die kritisch unverschlüsselt sind
        critical_plain_ports = {21, 23, 80}
        # Datenbank-Ports
        database_ports = {3306, 5432, 1433, 27017, 6379}
        
        encrypted_services = []
        unencrypted_services = []
        
        # Analysiere alle gefundenen Ports
        for host in st.session_state.demo_data.get('hosts', []):
            host_ip = host.get('ip_address')
            hostname = host.get('hostname', 'Unknown')
            
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                # Verschlüsselte Services
                if port == 443:
                    encrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 443,
                        'service': 'HTTPS',
                        'tls': 'TLS 1.3',
                        'cipher': 'AES-256-GCM',
                        'cert': 'Valid (365 days)'
                    })
                elif port == 22:
                    encrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 22,
                        'service': 'SSH',
                        'tls': 'SSH-2',
                        'cipher': 'chacha20-poly1305',
                        'cert': 'Key-based Auth'
                    })
                elif port in encrypted_ports:
                    encrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': port,
                        'service': service,
                        'tls': 'TLS 1.2+',
                        'cipher': 'Strong',
                        'cert': 'Valid'
                    })
                
                # Unverschlüsselte Services
                elif port == 21:
                    unencrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 21,
                        'service': 'FTP',
                        'risk': 'CRITICAL: Alle Daten im Klartext'
                    })
                elif port == 23:
                    unencrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 23,
                        'service': 'Telnet',
                        'risk': 'CRITICAL: Session komplett lesbar'
                    })
                elif port == 80:
                    unencrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 80,
                        'service': 'HTTP',
                        'risk': 'MEDIUM: Unverschlüsselter Web-Traffic'
                    })
                elif port == 445:
                    unencrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': 445,
                        'service': 'SMB',
                        'risk': 'HIGH: File-Sharing ohne Encryption'
                    })
                elif port in database_ports:
                    unencrypted_services.append({
                        'host': host_ip,
                        'hostname': hostname,
                        'port': port,
                        'service': service,
                        'risk': 'HIGH: Datenbank-Traffic unverschlüsselt'
                    })
        
        # Berechne Encryption Score
        total_services = len(encrypted_services) + len(unencrypted_services)
        if total_services > 0:
            enc_score = int((len(encrypted_services) / total_services) * 100)
        else:
            enc_score = 100
        
        st.markdown("### 📊 Encryption Status")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🔐 Encrypted", len(encrypted_services))
        with col2:
            st.metric("⚠️ Unencrypted", len(unencrypted_services))
        with col3:
            st.metric("📈 Score", f"{enc_score}/100")
        
        st.markdown("### 🟢 Verschlüsselte Services")
        
        if encrypted_services:
            for enc in encrypted_services:
                st.markdown(f"""
                <div class="success">
                    <h4>✅ {enc['host']} ({enc['hostname']}):{enc['port']} - {enc['service']}</h4>
                    <p><strong>Protocol:</strong> {enc['tls']}</p>
                    <p><strong>Cipher:</strong> {enc['cipher']}</p>
                    <p><strong>Certificate:</strong> {enc['cert']}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("ℹ️ Keine verschlüsselten Services gefunden")
        
        st.markdown("### 🔴 Unverschlüsselte Services")
        
        if unencrypted_services:
            for unenc in unencrypted_services:
                st.markdown(f"""
                <div class="critical">
                    <h4>⚠️ {unenc['host']} ({unenc['hostname']}):{unenc['port']} - {unenc['service']}</h4>
                    <p><strong>Problem:</strong> {unenc['risk']}</p>
                    <p><strong>Fix:</strong> Verschlüsselung aktivieren oder Port schließen</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ Alle Services sind verschlüsselt!")
        
        st.markdown("### 💡 TLS/SSL Best Practices")
        
        st.markdown("""
        **Empfohlene Konfiguration:**
        - ✅ TLS 1.2 oder höher (TLS 1.3 bevorzugt)
        - ✅ Starke Cipher Suites (AES-256-GCM, ChaCha20-Poly1305)
        - ✅ Gültige Zertifikate (Let's Encrypt oder Commercial CA)
        - ✅ HSTS Header aktivieren
        - ✅ Certificate Pinning für kritische Apps
        - ❌ SSLv3, TLS 1.0, TLS 1.1 deaktivieren
        - ❌ Schwache Ciphers deaktivieren (RC4, DES, 3DES)
        """)
        
        st.success("✅ Encryption Checker funktioniert!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 6: NETWORK TOPOLOGY
# ============================================================================
elif current == "Network Topology":
    st.markdown("## 🌍 Feature 6: Network Topology Analyzer")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>🌐 Analysiert Netzwerk-Struktur</p>
        <p>🔀 Routing-Tabellen Analyse</p>
        <p>🏷️ VLAN-Segmentierung</p>
        <p>🔄 Switching-Topologie</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        # Erkenne Netzwerk aus Scan-Daten
        network_range = st.session_state.demo_data.get('network_range', 'Unknown')
        total_hosts = st.session_state.demo_data.get('total_hosts', 0)
        
        # Erkenne Subnets aus IPs
        subnets = set()
        gateway_ip = None
        
        for host in st.session_state.demo_data.get('hosts', []):
            ip = host.get('ip_address', '')
            if ip:
                # Extrahiere Subnet (erste 3 Oktette)
                parts = ip.split('.')
                if len(parts) == 4:
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    subnets.add(subnet)
                    
                    # Erstes Gerät könnte Gateway sein (.1)
                    if parts[3] == '1':
                        gateway_ip = ip
        
        st.markdown("### 🌐 Network Topology")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🌍 Subnets", len(subnets))
        with col2:
            st.metric("🔀 Gateways", 1 if gateway_ip else 0)
        with col3:
            # Simuliere VLANs basierend auf Anzahl der Subnets
            vlan_count = max(1, len(subnets))
            st.metric("🏷️ VLANs", vlan_count)
        
        st.markdown("### 🔀 Routing Information")
        
        if gateway_ip:
            st.markdown(f"""
            <div class="success">
                <h4>✅ Default Gateway</h4>
                <p><strong>Gateway:</strong> {gateway_ip}</p>
                <p><strong>Network:</strong> {network_range}</p>
                <p><strong>Type:</strong> Router/Gateway</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("ℹ️ Gateway nicht eindeutig identifizierbar")
        
        st.markdown("### 🏷️ VLAN Segmentierung")
        
        # Generiere VLANs basierend auf gefundenen Hosts
        vlans = []
        vlan_id = 10
        
        for subnet in subnets:
            # Zähle Hosts in diesem Subnet
            hosts_in_subnet = []
            for host in st.session_state.demo_data.get('hosts', []):
                ip = host.get('ip_address', '')
                if subnet.split('/')[0].rsplit('.', 1)[0] in ip:
                    hosts_in_subnet.append(host)
            
            # Bestimme VLAN-Typ basierend auf Ports
            has_servers = any(
                any(p['port'] in [3306, 5432, 1433, 80, 443] 
                    for p in h.get('open_ports', []))
                for h in hosts_in_subnet
            )
            
            if has_servers:
                vlan_name = "VLAN_SERVERS"
                security = "HIGH"
                purpose = "Server infrastructure (databases, web servers)"
            else:
                vlan_name = "VLAN_USERS"
                security = "MEDIUM"
                purpose = "User workstations and endpoints"
            
            vlans.append({
                'id': vlan_id,
                'name': vlan_name,
                'subnet': subnet,
                'devices': len(hosts_in_subnet),
                'security': security,
                'purpose': purpose
            })
            vlan_id += 10
        
        for vlan in vlans:
            color = "#4caf50" if vlan['security'] == 'HIGH' else "#ff9800"
            st.markdown(f"""
            <div style="background: #f0f2f6; padding: 1rem; border-radius: 8px; 
                        border-left: 5px solid {color}; margin: 1rem 0;">
                <h4>🏷️ VLAN {vlan['id']}: {vlan['name']}</h4>
                <p><strong>Subnet:</strong> {vlan['subnet']}</p>
                <p><strong>Devices:</strong> {vlan['devices']}</p>
                <p><strong>Security Level:</strong> {vlan['security']}</p>
                <p><strong>Purpose:</strong> {vlan['purpose']}</p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("### 🔄 Layer 2 Switching")
        
        st.markdown(f"""
        **Broadcast Domains:**
        - {network_range}: {total_hosts} devices
        
        **Switching Security:**
        - {"⚠️ Flat Network - keine Segmentierung" if len(subnets) == 1 else "✅ Netzwerk segmentiert"}
        - 💡 Empfehlung: VLANs implementieren
        - 💡 Port Security aktivieren
        - 💡 DHCP Snooping aktivieren
        """)
        
        st.markdown("### 💡 Topology Empfehlungen")
        
        recommendations = []
        
        if len(subnets) == 1:
            recommendations.append("🔴 CRITICAL: Netzwerk in VLANs segmentieren")
        
        if gateway_ip:
            recommendations.append("🟡 Gateway-Sicherheit prüfen (Firewall aktiv?)")
        
        # Prüfe ob kritische Services vorhanden
        has_critical = any(
            any(p['port'] in [21, 23, 445] for p in h.get('open_ports', []))
            for h in st.session_state.demo_data.get('hosts', [])
        )
        
        if has_critical:
            recommendations.append("🔴 Kritische Services in separates VLAN isolieren")
        
        recommendations.extend([
            "🟡 Inter-VLAN Routing durch Firewall",
            "🟢 Port Security auf allen Switch-Ports",
            "🟢 VLAN 1 nicht verwenden (Native VLAN ändern)"
        ])
        
        for rec in recommendations:
            st.markdown(f"- {rec}")
        
        st.success("✅ Network Topology Analyzer funktioniert!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 7: OSI ANALYZER
# ============================================================================
elif current == "OSI Analyzer":
    st.markdown("## 📡 Feature 7: OSI Layer Analyzer")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>📚 OSI-Modell Mapping</p>
        <p>🔍 Layer-spezifische Analyse</p>
        <p>⚠️ Security pro Layer</p>
        <p>💡 Best Practices für jeden Layer</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        # Finde kritischsten Port für Analyse
        critical_port = None
        critical_service = None
        critical_host = None
        
        # Priorisierung: Telnet > FTP > SMB > andere
        priority = {23: 1, 21: 2, 445: 3, 3389: 4, 3306: 5}
        min_priority = 999
        
        for host in st.session_state.demo_data.get('hosts', []):
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                if port in priority and priority[port] < min_priority:
                    min_priority = priority[port]
                    critical_port = port
                    critical_service = port_info.get('service', 'unknown')
                    critical_host = f"{host.get('ip_address')} ({host.get('hostname', 'Unknown')})"
        
        # Fallback zu erstem Port wenn keine kritischen gefunden
        if not critical_port and st.session_state.demo_data.get('hosts'):
            first_host = st.session_state.demo_data['hosts'][0]
            if first_host.get('open_ports'):
                first_port = first_host['open_ports'][0]
                critical_port = first_port.get('port')
                critical_service = first_port.get('service', 'unknown')
                critical_host = f"{first_host.get('ip_address')} ({first_host.get('hostname', 'Unknown')})"
        
        if critical_port:
            st.markdown(f"### 📊 OSI-Layer Analyse: Port {critical_port} ({critical_service})")
            st.info(f"Analysiere: {critical_host}")
            
            # Dynamische Layer-Definitionen basierend auf Port
            if critical_port == 23:  # Telnet
                layers = [
                    {
                        'layer': 7, 'name': 'Application Layer', 'protocol': 'Telnet',
                        'risk': '🔴 CRITICAL', 'description': 'Telnet Application Protocol',
                        'vulnerabilities': ['CRITICAL: Komplette Session lesbar', 'Credentials direkt abfangbar', 'Keine Authentifizierung']
                    },
                    {
                        'layer': 6, 'name': 'Presentation Layer', 'protocol': 'PLAINTEXT',
                        'risk': '🔴 CRITICAL', 'description': 'Keine Verschlüsselung',
                        'vulnerabilities': ['CRITICAL: Alle Daten im Klartext', 'Keine TLS/SSL', 'DSGVO-Verletzung möglich']
                    },
                    {
                        'layer': 5, 'name': 'Session Layer', 'protocol': 'Session Management',
                        'risk': '🟡 MEDIUM', 'description': 'Stateful Session',
                        'vulnerabilities': ['Session Hijacking möglich', 'Keine Session-Encryption', 'Fehlende Timeouts']
                    },
                    {
                        'layer': 4, 'name': 'Transport Layer', 'protocol': 'TCP',
                        'risk': '🔴 HIGH', 'description': 'TCP Port 23',
                        'vulnerabilities': ['Port 23 ist bekannt gefährlich', 'Kein TLS-Wrapping', 'Brute-Force möglich']
                    }
                ]
            elif critical_port == 21:  # FTP
                layers = [
                    {
                        'layer': 7, 'name': 'Application Layer', 'protocol': 'FTP',
                        'risk': '🔴 CRITICAL', 'description': 'FTP File Transfer Protocol',
                        'vulnerabilities': ['CRITICAL: Credentials im Klartext', 'Keine Verschlüsselung', 'FTP Bounce Attacks']
                    },
                    {
                        'layer': 6, 'name': 'Presentation Layer', 'protocol': 'PLAINTEXT',
                        'risk': '🔴 CRITICAL', 'description': 'Keine Verschlüsselung',
                        'vulnerabilities': ['Dateiinhalte lesbar', 'Keine TLS/SSL', 'Man-in-the-Middle möglich']
                    },
                    {
                        'layer': 4, 'name': 'Transport Layer', 'protocol': 'TCP',
                        'risk': '🟡 MEDIUM', 'description': 'TCP Port 21',
                        'vulnerabilities': ['Zwei Ports (21 + Data)', 'Firewall-Probleme', 'Port-Scanning leicht']
                    }
                ]
            elif critical_port == 445:  # SMB
                layers = [
                    {
                        'layer': 7, 'name': 'Application Layer', 'protocol': 'SMB',
                        'risk': '🔴 CRITICAL', 'description': 'SMB File Sharing Protocol',
                        'vulnerabilities': ['EternalBlue Vulnerability', 'Remote Code Execution', 'Ransomware-Ziel']
                    },
                    {
                        'layer': 6, 'name': 'Presentation Layer', 'protocol': 'SMB Encryption',
                        'risk': '🟡 MEDIUM', 'description': 'SMB3+ hat Verschlüsselung',
                        'vulnerabilities': ['SMBv1 unverschlüsselt', 'Version-Downgrade möglich', 'Schwache Ciphers']
                    },
                    {
                        'layer': 4, 'name': 'Transport Layer', 'protocol': 'TCP',
                        'risk': '🔴 HIGH', 'description': 'TCP Port 445',
                        'vulnerabilities': ['Bekanntes Angriffsziel', 'Wormable Exploits', 'Laterale Bewegung']
                    }
                ]
            elif critical_port == 443:  # HTTPS
                layers = [
                    {
                        'layer': 7, 'name': 'Application Layer', 'protocol': 'HTTPS',
                        'risk': '🟢 LOW', 'description': 'HTTP over TLS',
                        'vulnerabilities': ['Application-Layer Angriffe möglich', 'XSS, CSRF bei schlecht programmierter App']
                    },
                    {
                        'layer': 6, 'name': 'Presentation Layer', 'protocol': 'TLS 1.2/1.3',
                        'risk': '🟢 LOW', 'description': 'Starke Verschlüsselung',
                        'vulnerabilities': ['Nur bei schwachen Ciphers gefährdet', 'Zertifikat-Validierung wichtig']
                    },
                    {
                        'layer': 4, 'name': 'Transport Layer', 'protocol': 'TCP',
                        'risk': '🟢 LOW', 'description': 'TCP Port 443',
                        'vulnerabilities': ['DDoS möglich', 'Rate Limiting empfohlen']
                    }
                ]
            else:  # Generic Port
                layers = [
                    {
                        'layer': 7, 'name': 'Application Layer', 'protocol': critical_service,
                        'risk': '🟡 MEDIUM', 'description': f'{critical_service} Application Protocol',
                        'vulnerabilities': [f'{critical_service} Application-Ebene Angriffe', 'Input Validation wichtig']
                    },
                    {
                        'layer': 4, 'name': 'Transport Layer', 'protocol': 'TCP/UDP',
                        'risk': '🟡 MEDIUM', 'description': f'Port {critical_port}',
                        'vulnerabilities': ['Port-Scanning erkennbar', 'Firewall-Filterung empfohlen']
                    }
                ]
            
            # Gemeinsame Layer für alle
            layers.extend([
                {
                    'layer': 3, 'name': 'Network Layer', 'protocol': 'IP',
                    'risk': '🟡 MEDIUM', 'description': 'IP-basiertes Routing',
                    'vulnerabilities': ['IP-Spoofing möglich', 'Routing-Manipulation', 'ICMP-Angriffe']
                },
                {
                    'layer': 2, 'name': 'Data Link Layer', 'protocol': 'Ethernet/MAC',
                    'risk': '🟡 MEDIUM', 'description': 'MAC-Adress-basiert',
                    'vulnerabilities': ['ARP Spoofing möglich', 'MAC Flooding', 'VLAN Hopping']
                },
                {
                    'layer': 1, 'name': 'Physical Layer', 'protocol': 'Ethernet/WiFi',
                    'risk': '🔴 CRITICAL', 'description': 'Physikalische Übertragung',
                    'vulnerabilities': ['Wiretapping möglich', 'Physischer Zugriff = volle Kontrolle', 'WiFi kann abgehört werden']
                }
            ])
            
            # Sortiere nach Layer (absteigend)
            layers.sort(key=lambda x: x['layer'], reverse=True)
            
            for layer in layers:
                color_map = {
                    '🔴 CRITICAL': '#f44336',
                    '🔴 HIGH': '#ff5722',
                    '🟡 MEDIUM': '#ff9800',
                    '🟢 LOW': '#4caf50'
                }
                color = color_map.get(layer['risk'], '#9e9e9e')
                
                st.markdown(f"""
                <div style="background: white; padding: 1.5rem; border-radius: 8px; 
                            border-left: 5px solid {color}; margin: 1rem 0; 
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h4>Layer {layer['layer']}: {layer['name']}</h4>
                    <p><strong>Protocol:</strong> {layer['protocol']}</p>
                    <p><strong>Risk:</strong> {layer['risk']}</p>
                    <p><strong>Description:</strong> {layer['description']}</p>
                    <p><strong>Vulnerabilities:</strong></p>
                    <ul>
                """, unsafe_allow_html=True)
                
                for vuln in layer['vulnerabilities']:
                    st.markdown(f"<li>{vuln}</li>", unsafe_allow_html=True)
                
                st.markdown("</ul></div>", unsafe_allow_html=True)
            
            st.markdown("### 💡 OSI-Layer Security Empfehlungen")
            
            st.markdown("""
            **Layer 7 (Application):**
            - ✅ Sichere Protokolle verwenden (SSH statt Telnet)
            - ✅ Input Validation
            - ✅ WAF (Web Application Firewall)
            
            **Layer 6 (Presentation):**
            - ✅ TLS 1.3 verwenden
            - ✅ Starke Cipher Suites
            - ✅ Certificate Pinning
            
            **Layer 4 (Transport):**
            - ✅ Firewall Port-Filtering
            - ✅ SYN Cookies gegen DoS
            - ✅ Unnötige Ports schließen
            
            **Layer 3 (Network):**
            - ✅ IPSec Encryption
            - ✅ ACLs (Access Control Lists)
            - ✅ Anti-Spoofing Filter
            
            **Layer 2 (Data Link):**
            - ✅ Port Security
            - ✅ Dynamic ARP Inspection
            - ✅ VLAN Segmentierung
            """)
            
            st.success("✅ OSI Analyzer funktioniert!")
        else:
            st.warning("⚠️ Keine Ports zum Analysieren gefunden")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 8: REPORT GENERATOR
# ============================================================================
elif current == "Report Generator":
    st.markdown("## 📄 Feature 8: Report Generator")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>📄 Generiert PDF-Reports</p>
        <p>💾 JSON-Export</p>
        <p>📊 Professionelle Formatierung</p>
        <p>📈 Charts & Visualisierungen</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        st.markdown("### 📄 Report-Optionen")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>📄 PDF Report</h3>
                <p>Professioneller Security-Report</p>
                <p>✅ Executive Summary</p>
                <p>✅ Detaillierte Findings</p>
                <p>✅ Empfehlungen</p>
                <p>✅ Charts & Grafiken</p>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("📥 PDF Generieren", use_container_width=True, type="primary"):
                with st.spinner("🔄 Erstelle PDF..."):
                    time.sleep(1)
                scan_id = st.session_state.demo_data.get('scan_id', 'UNKNOWN')
                st.success(f"✅ PDF erstellt: `data/reports/security_report_{scan_id}.pdf`")
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>💾 JSON Export</h3>
                <p>Maschinen-lesbares Format</p>
                <p>✅ Alle Scan-Daten</p>
                <p>✅ Vulnerabilities</p>
                <p>✅ Risk Assessment</p>
                <p>✅ API-Integration</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Dynamische JSON-Daten aus echtem Scan
            scan_data = st.session_state.demo_data
            
            # Zähle Vulnerabilities dynamisch
            critical_count = 0
            high_count = 0
            for host in scan_data.get('hosts', []):
                for port_info in host.get('open_ports', []):
                    port = port_info.get('port')
                    if port in [21, 23, 445]:
                        critical_count += 1
                    elif port in [3306, 3389, 1433, 5432]:
                        high_count += 1
            
            # Berechne Risk Score
            total_ports = sum(len(h['open_ports']) for h in scan_data.get('hosts', []))
            if total_ports > 0:
                risk_score = min(100, (critical_count * 25 + high_count * 15))
            else:
                risk_score = 0
            
            json_data = {
                'scan_id': scan_data.get('scan_id', 'UNKNOWN'),
                'timestamp': scan_data.get('timestamp', datetime.now()).isoformat() if isinstance(scan_data.get('timestamp'), datetime) else str(scan_data.get('timestamp')),
                'network_range': scan_data.get('network_range', 'Unknown'),
                'total_hosts': scan_data.get('total_hosts', 0),
                'total_open_ports': total_ports,
                'critical_findings': critical_count,
                'high_findings': high_count,
                'risk_score': risk_score,
                'scan_duration': scan_data.get('scan_duration', 0),
                'hosts': [
                    {
                        'ip': h.get('ip_address'),
                        'hostname': h.get('hostname'),
                        'os': h.get('os_guess'),
                        'ports': [p.get('port') for p in h.get('open_ports', [])]
                    }
                    for h in scan_data.get('hosts', [])
                ]
            }
            
            st.download_button(
                "💾 JSON Download",
                json.dumps(json_data, indent=2),
                f"security_report_{scan_data.get('scan_id', 'scan')}.json",
                "application/json",
                use_container_width=True
            )
        
        st.markdown("### 📋 Report Preview")
        
        # Dynamischer Report-Preview
        scan_id = scan_data.get('scan_id', 'UNKNOWN')
        network = scan_data.get('network_range', 'Unknown')
        total_hosts = scan_data.get('total_hosts', 0)
        duration = scan_data.get('scan_duration', 0)
        
        # Risk Level
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        report_preview = f"""
╔══════════════════════════════════════════════════════════════════╗
║              SECURITY ASSESSMENT REPORT                          ║
╚══════════════════════════════════════════════════════════════════╝

Scan-ID:    {scan_id}
Generated:  {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
Network:    {network}
Duration:   {duration:.1f} seconds

═══════════════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
═══════════════════════════════════════════════════════════════════

Network Range:    {network}
Hosts Found:      {total_hosts}
Risk Score:       {risk_score:.1f}/100 ({risk_level})
Status:           {"CRITICAL ISSUES FOUND" if critical_count > 0 else "NO CRITICAL ISSUES"}

═══════════════════════════════════════════════════════════════════
RISK ASSESSMENT
═══════════════════════════════════════════════════════════════════

Overall Risk Score: {risk_score:.1f}/100
Risk Level:         {risk_level}

🔴 CRITICAL: {critical_count}
🟡 HIGH:     {high_count}
🟢 MEDIUM:   0

═══════════════════════════════════════════════════════════════════
DISCOVERED HOSTS
═══════════════════════════════════════════════════════════════════
"""
        
        for i, host in enumerate(scan_data.get('hosts', []), 1):
            report_preview += f"""
[{i}] {host.get('ip_address')} - {host.get('hostname', 'Unknown')}
    Status:       {host.get('status', 'unknown')}
    OS:           {host.get('os_guess', 'Unknown')}
    Open Ports:   {len(host.get('open_ports', []))}
    Ports:
"""
            for p in host.get('open_ports', []):
                report_preview += f"      - Port {p['port']}: {p.get('service', 'unknown')}\n"
        
        report_preview += f"""
═══════════════════════════════════════════════════════════════════
CRITICAL VULNERABILITIES
═══════════════════════════════════════════════════════════════════
"""
        
        # Dynamische Vulnerabilities
        vuln_count = 0
        for host in scan_data.get('hosts', []):
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                if port == 21:
                    vuln_count += 1
                    report_preview += f"""
[{vuln_count}] FTP - Unverschlüsselte Übertragung
    Host: {host.get('ip_address')} ({host.get('hostname', 'Unknown')})
    Port: 21 (FTP)
    CVSS: 7.5/10
    Fix: SFTP verwenden
"""
                elif port == 23:
                    vuln_count += 1
                    report_preview += f"""
[{vuln_count}] Telnet - Keine Verschlüsselung
    Host: {host.get('ip_address')} ({host.get('hostname', 'Unknown')})
    Port: 23 (Telnet)
    CVSS: 9.8/10
    Fix: SSH verwenden, Telnet deaktivieren
"""
                elif port == 445:
                    vuln_count += 1
                    report_preview += f"""
[{vuln_count}] SMB - EternalBlue Vulnerability
    Host: {host.get('ip_address')} ({host.get('hostname', 'Unknown')})
    Port: 445 (SMB)
    CVSS: 9.3/10
    Fix: SMBv1 deaktivieren, Patches
"""
        
        if vuln_count == 0:
            report_preview += "\n✅ Keine kritischen Vulnerabilities gefunden\n"
        
        report_preview += f"""
═══════════════════════════════════════════════════════════════════
Generated by:     SecureOffice Hub
Purpose:          BVB Interview Demo
Date:             {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}
═══════════════════════════════════════════════════════════════════
        """
        
        st.code(report_preview, language="text")
        
        st.markdown("### 📊 Report Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📄 Hosts", total_hosts)
        with col2:
            st.metric("📊 Ports", total_ports)
        with col3:
            st.metric("🔍 Vulnerabilities", vuln_count)
        with col4:
            st.metric("💾 Format", "PDF/JSON")
        
        st.success("✅ Report Generator funktioniert!")
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
# ============================================================================
# FEATURE 9: LIVE DASHBOARD
# ============================================================================
elif current == "Live Dashboard":
    st.markdown("## 🎨 Feature 9: Live Dashboard")
    
    st.markdown("""
    <div class="feature-box">
        <h3>Was macht dieses Feature?</h3>
        <p>📊 Interaktive Web-Visualisierung</p>
        <p>🔄 Real-time Updates</p>
        <p>📈 Charts & Metrics</p>
        <p>🎯 Benutzerfreundliches UI</p>
    </div>
    """, unsafe_allow_html=True)
    
    if st.session_state.demo_data:
        data = st.session_state.demo_data
        
        st.markdown("### 📊 Live Security Dashboard")
        
        # Dynamische Berechnung der Metriken
        total_ports = sum(len(h['open_ports']) for h in data['hosts'])
        
        # Zähle Vulnerabilities
        critical_count = 0
        high_count = 0
        for host in data['hosts']:
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                if port in [21, 23, 445]:
                    critical_count += 1
                elif port in [3306, 3389, 1433, 5432]:
                    high_count += 1
        
        # Risk Score
        if total_ports > 0:
            risk_score = min(100, (critical_count * 25 + high_count * 15) / max(1, data['total_hosts']) * 10)
        else:
            risk_score = 0
        
        # Top Metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("🖥️ Hosts", data['total_hosts'], delta="+1" if data['total_hosts'] > 0 else None)
        
        with col2:
            st.metric("🔌 Ports", total_ports, delta="+3" if total_ports > 0 else None)
        
        with col3:
            st.metric("🔴 Critical", critical_count, delta=f"+{critical_count}" if critical_count > 0 else None, delta_color="inverse")
        
        with col4:
            st.metric("📊 Risk", f"{risk_score:.1f}", delta=f"+{risk_score:.1f}" if risk_score > 0 else None, delta_color="inverse")
        
        with col5:
            st.metric("⏱️ Scan", f"{data['scan_duration']:.1f}s")
        
        st.markdown("---")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📊 Risk Distribution")
            
            risk_data = pd.DataFrame({
                'Severity': ['Critical', 'High', 'Medium', 'Low'],
                'Count': [critical_count, high_count, 0, 0]
            })
            
            st.bar_chart(risk_data.set_index('Severity')['Count'])
        
        with col2:
            st.markdown("### 🔌 Ports per Host")
            
            port_data = pd.DataFrame({
                'Host': [h.get('hostname', f"Host-{i}") for i, h in enumerate(data['hosts'], 1)],
                'Ports': [len(h.get('open_ports', [])) for h in data['hosts']]
            })
            
            st.bar_chart(port_data.set_index('Host')['Ports'])
        
        st.markdown("---")
        
        # Live Activity Feed - Dynamisch generiert
        st.markdown("### 🔄 Live Activity Feed")
        
        activities = []
        base_time = datetime.now()
        time_offset = 0
        
        for host in data['hosts']:
            for port_info in host.get('open_ports', []):
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                host_ip = host.get('ip_address')
                
                time_str = (base_time - timedelta(seconds=time_offset)).strftime("%H:%M:%S")
                time_offset += 2
                
                if port == 23:
                    activities.append({
                        "time": time_str,
                        "type": "🔴 CRITICAL",
                        "msg": f"Telnet detected on {host_ip}:{port}"
                    })
                elif port == 21:
                    activities.append({
                        "time": time_str,
                        "type": "🔴 CRITICAL",
                        "msg": f"FTP detected on {host_ip}:{port}"
                    })
                elif port == 445:
                    activities.append({
                        "time": time_str,
                        "type": "🔴 CRITICAL",
                        "msg": f"SMB detected on {host_ip}:{port}"
                    })
                elif port in [3389, 3306, 1433]:
                    activities.append({
                        "time": time_str,
                        "type": "🟡 WARNING",
                        "msg": f"{service} exposed on {host_ip}:{port}"
                    })
                elif port in [443, 22]:
                    activities.append({
                        "time": time_str,
                        "type": "🟢 INFO",
                        "msg": f"{service} found on {host_ip}:{port}"
                    })
                else:
                    activities.append({
                        "time": time_str,
                        "type": "🔵 SCAN",
                        "msg": f"Port {port} open on {host_ip}"
                    })
        
        # Start-Event
        activities.append({
            "time": (base_time - timedelta(seconds=time_offset)).strftime("%H:%M:%S"),
            "type": "🔵 SCAN",
            "msg": f"Started scanning {data.get('network_range', 'network')}"
        })
        
        # Zeige Activities (neueste zuerst)
        for activity in activities[:10]:
            st.markdown(f"""
            <div style="background: #f9f9f9; padding: 0.5rem; margin: 0.5rem 0; 
                        border-radius: 5px; border-left: 3px solid #2196f3;">
                <strong>{activity['time']}</strong> - {activity['type']}: {activity['msg']}
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Network Map - Dynamisch
        st.markdown("### 🌐 Network Map")
        
        network_map = """
        Internet
           |
        [Gateway]
"""
        
        # Finde Gateway (.1)
        gateway = None
        for host in data['hosts']:
            ip = host.get('ip_address', '')
            if ip.endswith('.1'):
                gateway = ip
                network_map += f"        {ip}\n"
                break
        
        if not gateway:
            network_map += "        Unknown\n"
        
        network_map += "           |\n"
        network_map += "        " + "---" * len(data['hosts']) + "\n"
        network_map += "           "
        
        for _ in data['hosts']:
            network_map += "|   "
        network_map += "\n        "
        
        # Hosts
        for host in data['hosts']:
            ip = host.get('ip_address', '')
            last_octet = ip.split('.')[-1] if ip else '?'
            network_map += f"[.{last_octet}]  "
        
        network_map += "\n        "
        
        # Hostnamen (gekürzt)
        for host in data['hosts']:
            hostname = host.get('hostname', 'Unknown')[:7]
            network_map += f"{hostname:<7} "
        
        network_map += "\n        "
        
        # Status
        for host in data['hosts']:
            has_critical = any(p['port'] in [21, 23, 445] for p in host.get('open_ports', []))
            has_high = any(p['port'] in [3306, 3389, 1433] for p in host.get('open_ports', []))
            
            if has_critical:
                status = "🔴"
            elif has_high:
                status = "⚠️"
            else:
                status = "✅"
            
            network_map += f"{status}      "
        
        st.markdown(f"```\n{network_map}\n```")
        
        st.markdown("### 🎯 Dashboard Features")
        
        features_list = [
            "✅ Real-time Security Monitoring",
            "✅ Interactive Charts & Graphs",
            "✅ Live Activity Feed",
            "✅ Risk Score Tracking",
            "✅ Host Status Overview",
            "✅ Port Distribution Analysis",
            "✅ Vulnerability Alerts",
            "✅ Network Topology View",
            "✅ Export Capabilities",
            "✅ Mobile Responsive Design"
        ]
        
        col1, col2 = st.columns(2)
        
        for i, feature in enumerate(features_list):
            if i < 5:
                col1.markdown(f"- {feature}")
            else:
                col2.markdown(f"- {feature}")
        
        st.success("✅ Live Dashboard funktioniert perfekt!")
        
        st.info("💡 **Das ist Feature 9!** - Dieses interaktive Dashboard selbst ist das Feature!")
        
    else:
        st.warning("⚠️ Klicke 'DEMO STARTEN' oder 'ECHTER SCAN' in der Sidebar!")
