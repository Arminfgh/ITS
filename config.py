"""
SecureOffice Hub - Zentrale Konfiguration
Alle wichtigen Settings an einem Ort
"""

import os
from pathlib import Path

# Projekt-Pfade
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SCAN_RESULTS_DIR = DATA_DIR / "scan_results"
REPORTS_DIR = DATA_DIR / "reports"
DATABASE_DIR = BASE_DIR / "database"

# Erstelle Verzeichnisse wenn nicht vorhanden
for directory in [DATA_DIR, SCAN_RESULTS_DIR, REPORTS_DIR, DATABASE_DIR]:
    directory.mkdir(exist_ok=True)

# Datenbank
DATABASE_PATH = DATABASE_DIR / "security.db"
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Network Scanning Einstellungen
SCAN_CONFIG = {
    # Standard-Netzwerk (wird automatisch erkannt)
    "default_network": "10.248.126.0/24",
    
    # Welche Ports sollen gescannt werden?
    "common_ports": [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        80,    # HTTP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        8080,  # HTTP-Alt
    ],
    
    # Scan-Geschwindigkeit
    "scan_timeout": 2,  # Sekunden pro Port
    "max_threads": 10,  # Parallele Scans
}

# Vulnerability Database
VULNERABILITY_RULES = {
    # Port: (Risk-Level, Beschreibung, Empfehlung)
    21: ("CRITICAL", "FTP - Unencrypted file transfer", 
         "Use SFTP or FTPS instead"),
    
    23: ("CRITICAL", "Telnet - Unencrypted remote access",
         "Use SSH (Port 22) instead"),
    
    80: ("MEDIUM", "HTTP - Unencrypted web traffic",
         "Enforce HTTPS (Port 443)"),
    
    445: ("HIGH", "SMB - Vulnerable to EternalBlue exploits",
          "Apply latest Windows patches, restrict access"),
    
    3306: ("HIGH", "MySQL - Database exposed",
           "Bind to localhost only, use firewall"),
    
    3389: ("HIGH", "RDP - Remote Desktop vulnerable to attacks",
           "Use VPN, enable NLA, update regularly"),
}

# Risk Scoring
RISK_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

# Dashboard Settings
DASHBOARD_CONFIG = {
    "title": "🛡️ SecureOffice Security Hub",
    "refresh_interval": 30,  # Sekunden
    "theme": "dark",
    "show_demo_data": True,  # Für Demo: Zeige simulierte Daten
}

# Report Settings
REPORT_CONFIG = {
    "company_name": "SecureOffice Hub",
    "logo_path": None,  # Optional: Pfad zu Logo
    "template": "professional",
}

# Demo-Modus (für Interview!)
DEMO_MODE = True  # Zeigt zusätzliche simulierte Bedrohungen

# Logging
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file": BASE_DIR / "security_hub.log",
}