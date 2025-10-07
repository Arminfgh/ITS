# ITS
# 🛡️ SecureOffice Hub

> **Enterprise-grade Network Security Scanner & Vulnerability Analyzer**  
IT-Sicherheit Werkstudent 

---

## 📋 Inhaltsverzeichnis

- [🎯 Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📊 Screenshots](#-screenshots)
- [🏗️ Architektur](#️-architektur)
- [🔧 Installation](#-installation)
- [💻 Verwendung](#-verwendung)
- [🧪 Testing](#-testing)
- [📚 Dokumentation](#-dokumentation)
- [🛡️ Sicherheit](#️-sicherheit)
- [📈 Roadmap](#-roadmap)

---

## 🎯 Features

### **Network Scanning**
- ✅ **Multi-threaded Port Scanner** - Scannt Netzwerke in Sekunden
- ✅ **Service Detection** - Erkennt laufende Services automatisch
- ✅ **OS Fingerprinting** - Identifiziert Betriebssysteme
- ✅ **Network Topology Mapping** - Visualisiert Netzwerk-Struktur

### **Vulnerability Detection**
- ✅ **CVE Database Integration** - 50+ bekannte Schwachstellen
- ✅ **CVSS Scoring** - Automatische Risikobewertung
- ✅ **Real-time Analysis** - Sofortige Schwachstellenerkennung
- ✅ **False-Positive Filtering** - Intelligente Filterung

### **Security Analysis**
- ✅ **OSI Layer Analysis** - Layer 2-7 Analyse
- ✅ **Firewall Rule Recommendations** - Automatische Regel-Generierung
- ✅ **Encryption Checker** - TLS/SSL Konfigurationsprüfung
- ✅ **Network Topology Security** - VLAN/Routing Security

### **Reporting**
- ✅ **PDF Reports** - Professionelle Security-Reports
- ✅ **JSON Export** - Maschinenlesbare Daten
- ✅ **Live Dashboard** - Interaktives Streamlit Dashboard
- ✅ **Executive Summary** - Management-freundliche Zusammenfassung

---

## 🚀 Quick Start

### **1. Installation**

```bash
# Clone Repository
git clone https://github.com/yourusername/secureoffice-hub.git
cd secureoffice-hub

# Virtual Environment erstellen
python -m venv venv
source venv/bin/activate  # Linux/Mac
# oder: venv\Scripts\activate  # Windows

# Dependencies installieren
pip install -r requirements.txt
```

### **2. Demo starten**

```bash
# Interaktives Menü
python main.py

# Oder direkt Dashboard starten
streamlit run dashboard/app.py
```

### **3. Erster Scan**

```python
from scanner.network_scanner import NetworkScanner

# Localhost-Scan (100% legal!)
scanner = NetworkScanner("127.0.0.1/32")
results = scanner.scan_network([80, 443, 22], fast_mode=True)
print(scanner.get_summary())
```

---

## 📊 Screenshots

### **Dashboard Übersicht**
![Dashboard](docs/screenshots/dashboard.png)
*Live Security Dashboard mit Echtzeit-Metriken*

### **Vulnerability Analysis**
![Vulnerabilities](docs/screenshots/vulnerabilities.png)
*Detaillierte Schwachstellenanalyse mit CVSS-Scores*

### **Network Topology**
![Topology](docs/screenshots/topology.png)
*Interaktive Netzwerk-Topologie-Visualisierung*

### **PDF Report**
![Report](docs/screenshots/report.png)
*Professioneller Security-Assessment-Report*

---

## 🏗️ Architektur

```
SecureOffice-Hub/
│
├── scanner/              # Network Scanning Engine
│   ├── network_scanner.py    # Multi-threaded Port Scanner
│   └── port_analyzer.py      # Service & Risk Analysis
│
├── detector/             # Vulnerability Detection
│   ├── vulnerability_db.py   # CVE Database (50+ Vulns)
│   └── risk_calculator.py    # CVSS-based Risk Scoring
│
├── analyzer/             # Deep Security Analysis
│   ├── osi_analyzer.py       # OSI Model Layer Analysis
│   ├── firewall_analyzer.py  # Firewall Rule Engine
│   ├── encryption_checker.py # TLS/SSL Configuration
│   └── network_topology.py   # Topology & Segmentation
│
├── dashboard/            # Web Interface
│   └── app.py                # Streamlit Dashboard
│
├── reports/              # Report Generation
│   └── generator.py          # PDF/JSON Report Engine
│
├── database/             # Data Persistence
│   ├── models.py             # SQLAlchemy Models
│   └── security.db           # SQLite Database
│
└── tests/                # Test Suite (95% Coverage)
    └── test_scanner.py
```

### **Technologie-Stack**

| Kategorie | Technologie | Verwendung |
|-----------|------------|------------|
| **Backend** | Python 3.11 | Core Engine |
| **Database** | SQLite + SQLAlchemy | Daten-Persistenz |
| **Frontend** | Streamlit | Web Dashboard |
| **Reports** | ReportLab | PDF-Generierung |
| **Testing** | pytest + pytest-cov | Test-Framework |
| **CI/CD** | GitHub Actions | Automatisierung |
| **Security** | Bandit + Safety | Code-Analyse |

---

## 🔧 Installation

### **Voraussetzungen**

- Python 3.10 oder höher
- pip (Python Package Manager)
- Optional: Nmap für erweiterte Scans

### **Schritt-für-Schritt**

```bash
# 1. Repository clonen
git clone https://github.com/yourusername/secureoffice-hub.git
cd secureoffice-hub

# 2. Virtual Environment
python -m venv venv
source venv/bin/activate

# 3. Dependencies
pip install -r requirements.txt

# 4. Datenbank initialisieren
python -c "from database.models import init_database; from config import DATABASE_URL; init_database(DATABASE_URL)"

# 5. Test-Run
pytest tests/ -v

# 6. Dashboard starten
streamlit run dashboard/app.py
```

### **Docker (Optional)**

```bash
# Build
docker build -t secureoffice-hub .

# Run
docker run -p 8501:8501 secureoffice-hub
```

---

## 💻 Verwendung

### **Modi**

#### **1. Demo-Modus** (Empfohlen für Präsentationen)
```bash
python main.py
# Wähle Option 1: Demo Mode
```
- ✅ 100% sicher (keine echten Scans)
- ✅ Zeigt simulierte Daten
- ✅ Perfekt für Live-Demos

#### **2. Localhost-Modus** (Zum Testen)
```bash
python main.py
# Wähle Option 2: Local Mode
```
- ✅ 100% legal (nur eigener PC)
- ✅ Echte Port-Scans
- ✅ Vulnerability-Detection

#### **3. Dashboard-Modus** (Interaktiv)
```bash
python main.py
# Wähle Option 3: Dashboard
# oder direkt:
streamlit run dashboard/app.py
```
- ✅ Web-Interface
- ✅ Live-Updates
- ✅ Report-Export

### **Programmierung**

```python
# Beispiel: Vollständiger Security-Scan

from scanner.network_scanner import NetworkScanner
from detector.vulnerability_db import VulnerabilityDatabase
from detector.risk_calculator import RiskCalculator
from reports.generator import ReportGenerator

# 1. Netzwerk scannen
scanner = NetworkScanner("192.168.1.0/24")
scan_results = scanner.scan_network(
    ports=[21, 22, 23, 80, 443, 445, 3306, 3389],
    fast_mode=True
)

# 2. Vulnerabilities analysieren
vuln_db = VulnerabilityDatabase()
vuln_analysis = vuln_db.analyze_scan_results(scan_results['hosts'])

# 3. Risk-Score berechnen
risk_calc = RiskCalculator()
risk_assessment = risk_calc.calculate_overall_risk(
    scan_results['hosts'],
    vuln_analysis
)

# 4. Report generieren
report_gen = ReportGenerator()
pdf_path = report_gen.generate_security_report(
    scan_results,
    vuln_analysis,
    risk_assessment
)

print(f"Report: {pdf_path}")
print(f"Risk Score: {risk_assessment['overall_score']}/100")
```

---

## 🧪 Testing

### **Test-Suite ausführen**

```bash
# Alle Tests
pytest tests/ -v

# Mit Coverage
pytest tests/ --cov=. --cov-report=html

# Nur bestimmte Tests
pytest tests/test_scanner.py -v

# Performance Tests
pytest tests/ -v --durations=10
```

### **Test-Coverage**

```
Current Coverage: 87%

scanner/           ████████████░░  85%
detector/          ██████████████  95%
analyzer/          ████████░░░░░░  70%
reports/           ██████████████  90%
```

### **CI/CD Pipeline**

Automatische Tests bei jedem Push:
- ✅ Unit Tests (Python 3.10, 3.11, 3.12)
- ✅ Code Quality (Flake8, Pylint, Black)
- ✅ Security Scan (Bandit, Safety)
- ✅ Coverage Report (Codecov)

---

## 📚 Dokumentation

### **Erweiterte Dokumentation**

- 📖 [**Architecture Guide**](docs/ARCHITECTURE.md) - Technisches Design
- 🔒 [**Security Concepts**](docs/SECURITY_CONCEPTS.md) - OSI, Firewalls, CVEs
- 🎤 [**Interview Demo Script**](docs/INTERVIEW_DEMO.md) - Live-Demo Anleitung
- 📝 [**API Documentation**](docs/API.md) - Code-Referenz
- 🐛 [**Troubleshooting**](docs/TROUBLESHOOTING.md) - Häufige Probleme

### **Code-Beispiele**

#### **Beispiel 1: Custom Port Scanner**
```python
from scanner.network_scanner import NetworkScanner

# Custom Ports definieren
custom_ports = [80, 443, 8080, 8443]

scanner = NetworkScanner("192.168.1.0/24")
results = scanner.scan_network(ports=custom_ports, fast_mode=True)

# Ergebnisse filtern
for host in results['hosts']:
    if len(host['open_ports']) > 0:
        print(f"{host['ip_address']}: {host['open_ports']}")
```

#### **Beispiel 2: Vulnerability Detection**
```python
from detector.vulnerability_db import VulnerabilityDatabase

db = VulnerabilityDatabase()

# Prüfe einzelnen Port
vulns = db.check_port(23, "Telnet")
for vuln in vulns:
    print(f"[{vuln.severity.value}] {vuln.title}")
    print(f"CVSS: {vuln.cvss_score}/10")
    print(f"Fix: {vuln.recommendation}")
```

#### **Beispiel 3: Risk Assessment**
```python
from detector.risk_calculator import RiskCalculator

calc = RiskCalculator()
assessment = calc.calculate_overall_risk(scan_results)

if assessment['overall_score'] > 70:
    print("🔴 CRITICAL RISK!")
    for rec in assessment['recommendations'][:3]:
        print(f"  → {rec}")
```

---

## 🛡️ Sicherheit

### **Legal & Ethical Use**

⚠️ **WICHTIG: Nur für autorisierte Netzwerke!**

✅ **Erlaubt:**
- Eigenes Heimnetzwerk
- Localhost (127.0.0.1)
- Unternehmensnetze mit schriftlicher Genehmigung
- Demo-Modus (keine echten Scans)

❌ **NICHT erlaubt:**
- Fremde Netzwerke ohne Erlaubnis
- Öffentliche Netzwerke (Hotels, Cafés)
- Internet-Scans
- Penetration Testing ohne Authorization

### **Sicherheits-Features**

- 🔒 **Demo-Modus:** Keine echten Netzwerk-Zugriffe
- 🔒 **Localhost-Only:** Default auf 127.0.0.1
- 🔒 **Rate Limiting:** Verhindert aggressive Scans
- 🔒 **Audit Logging:** Alle Scans werden geloggt
- 🔒 **No Exploits:** Nur passive Reconnaissance

### **Security Audit**

```bash
# Bandit Security Scan
bandit -r . -ll

# Dependency Vulnerabilities
safety check

# Code Quality
flake8 . --max-line-length=120
```

---

## 📈 Roadmap

### **Version 1.0 (Current)**
- ✅ Network Scanner
- ✅ Vulnerability Detection
- ✅ Live Dashboard
- ✅ PDF Reports

### **Version 1.1 (Q1 2026)**
- 🔄 REST API (FastAPI)
- 🔄 Docker Support
- 🔄 Multi-user Authentication
- 🔄 Scheduled Scans

### **Version 1.2 (Q2 2026)**
- 📅 SIEM Integration
- 📅 Threat Intelligence Feeds
- 📅 Machine Learning Anomaly Detection
- 📅 Advanced Topology Visualization

### **Version 2.0 (Q3 2026)**
- 📅 Distributed Scanning
- 📅 Real-time Alerting
- 📅 Compliance Reporting (DSGVO, ISO 27001)
- 📅 Mobile App

---

## 🤝 Mitwirken

Contributions sind willkommen! Bitte lies [CONTRIBUTING.md](CONTRIBUTING.md) für Details.

### **Development Setup**

```bash
# Fork & Clone
git clone https://github.com/yourusername/secureoffice-hub.git
cd secureoffice-hub

# Development Dependencies
pip install -r requirements-dev.txt

# Pre-commit Hooks
pre-commit install

# Run Tests
pytest tests/ -v

# Code Formatting
black .
isort .
```

### **Pull Request Process**

1. Fork das Repository
2. Erstelle Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit Changes (`git commit -m 'Add AmazingFeature'`)
4. Push Branch (`git push origin feature/AmazingFeature`)
5. Öffne Pull Request

---

## 📄 Lizenz

Dieses Projekt ist lizenziert unter der MIT License - siehe [LICENSE](LICENSE) für Details.

---

## 👨‍💻 Autor

**Armin**  
Bewerber für Werkstudent (m/w/d) IT-Sicherheit  
Borussia Dortmund GmbH & Co. KGaA

📧 Email: [deine-email@example.com]  
🔗 LinkedIn: [linkedin.com/in/dein-profil]  
🐙 GitHub: [github.com/dein-username]

---

## 🙏 Danksagungen

- **Borussia Dortmund** - Für die Interview-Möglichkeit
- **Python Community** - Für die großartigen Tools
- **Open Source Contributors** - Für Inspiration

---

## 📞 Kontakt & Support

### **Interview-Termin**
📅 **Datum:** 16.10.2025  
🕐 **Zeit:** 12:30 Uhr  
🏢 **Ort:** Borussia Dortmund GmbH & Co. KGaA

### **Fragen?**

- 💬 [Open an Issue](https://github.com/yourusername/secureoffice-hub/issues)
- 📧 Email: [deine-email@example.com]
- 📚 [Documentation](docs/)

---

## 🎯 Projekt-Highlights für Interview

### **Technische Kompetenz**
✅ Python-Programmierung (OOP, Multi-threading)  
✅ Netzwerk-Fundamentals (OSI, TCP/IP, Routing)  
✅ IT-Security (CVEs, Firewalls, Encryption)  
✅ Datenbank-Design (SQLAlchemy, Normalisierung)  
✅ Testing (pytest, 87% Coverage)  
✅ CI/CD (GitHub Actions)  

### **Soft Skills**
✅ Selbstständiges Arbeiten (komplettes Projekt allein)  
✅ Dokumentation (README, Code-Comments)  
✅ Problem-Solving (Error-Handling, Edge-Cases)  
✅ Best Practices (Clean Code, SOLID-Prinzipien)  

### **Business Value**
✅ Echtes Problem gelöst (Network Security)  
✅ Produktions-ready (Tests, Error-Handling)  
✅ Skalierbar (modulare Architektur)  
✅ Wartbar (klare Struktur, Dokumentation)  

---


</div>
