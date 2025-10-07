"""
SecureOffice Hub - Datenbank Models
Speichert alle Scan-Ergebnisse, Vulnerabilities, und Security Events
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import json

Base = declarative_base()


class ScanSession(Base):
    """
    Ein kompletter Netzwerk-Scan
    """
    __tablename__ = 'scan_sessions'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(50), unique=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)
    network_range = Column(String(50))
    duration = Column(Float)  # Sekunden
    total_hosts = Column(Integer, default=0)
    total_ports_scanned = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    status = Column(String(20), default='running')  # running, completed, failed
    
    # Relationships
    hosts = relationship("Host", back_populates="scan_session", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_session", cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat(),
            'network_range': self.network_range,
            'duration': self.duration,
            'total_hosts': self.total_hosts,
            'total_ports_scanned': self.total_ports_scanned,
            'vulnerabilities_found': self.vulnerabilities_found,
            'risk_score': self.risk_score,
            'status': self.status
        }


class Host(Base):
    """
    Ein gefundenes Gerät im Netzwerk
    """
    __tablename__ = 'hosts'
    
    id = Column(Integer, primary_key=True)
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'))
    ip_address = Column(String(15), nullable=False)
    hostname = Column(String(255))
    mac_address = Column(String(17))
    os_guess = Column(String(100))
    status = Column(String(20), default='up')  # up, down, unknown
    response_time = Column(Float)  # ms
    risk_level = Column(String(20), default='low')  # low, medium, high, critical
    
    # Relationships
    scan_session = relationship("ScanSession", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname or 'Unknown',
            'mac_address': self.mac_address,
            'os_guess': self.os_guess,
            'status': self.status,
            'response_time': self.response_time,
            'risk_level': self.risk_level,
            'open_ports': len([p for p in self.ports if p.state == 'open'])
        }


class Port(Base):
    """
    Ein gescannter Port auf einem Host
    """
    __tablename__ = 'ports'
    
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey('hosts.id'))
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default='tcp')  # tcp, udp
    state = Column(String(20))  # open, closed, filtered
    service_name = Column(String(50))
    service_version = Column(String(100))
    banner = Column(Text)
    is_vulnerable = Column(Boolean, default=False)
    risk_level = Column(String(20), default='low')
    
    # Relationships
    host = relationship("Host", back_populates="ports")
    
    def to_dict(self):
        return {
            'port': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service_name or 'unknown',
            'version': self.service_version or '',
            'is_vulnerable': self.is_vulnerable,
            'risk_level': self.risk_level
        }


class Vulnerability(Base):
    """
    Eine gefundene Sicherheitslücke
    """
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'))
    vuln_id = Column(String(50))  # z.B. CVE-2024-1234
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20))  # low, medium, high, critical
    cvss_score = Column(Float)
    affected_host = Column(String(15))
    affected_port = Column(Integer)
    affected_service = Column(String(50))
    exploit_available = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    recommendation = Column(Text)
    references = Column(Text)  # JSON string mit Links
    discovered_at = Column(DateTime, default=datetime.now)
    
    # Relationships
    scan_session = relationship("ScanSession", back_populates="vulnerabilities")
    
    def to_dict(self):
        return {
            'vuln_id': self.vuln_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'affected_host': self.affected_host,
            'affected_port': self.affected_port,
            'affected_service': self.affected_service,
            'exploit_available': self.exploit_available,
            'patch_available': self.patch_available,
            'recommendation': self.recommendation,
            'discovered_at': self.discovered_at.isoformat()
        }


class SecurityEvent(Base):
    """
    Security Events / Alerts (für Demo und echte Erkennung)
    """
    __tablename__ = 'security_events'
    
    id = Column(Integer, primary_key=True)
    event_id = Column(String(50), unique=True)
    timestamp = Column(DateTime, default=datetime.now)
    event_type = Column(String(50))  # port_scan, brute_force, anomaly, etc.
    severity = Column(String(20))
    source_ip = Column(String(15))
    destination_ip = Column(String(15))
    destination_port = Column(Integer)
    description = Column(Text)
    details = Column(Text)  # JSON string
    is_blocked = Column(Boolean, default=False)
    is_demo = Column(Boolean, default=False)  # Markiert simulierte Events
    
    def to_dict(self):
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'description': self.description,
            'is_blocked': self.is_blocked,
            'is_demo': self.is_demo
        }


# Database Helper Functions
class DatabaseManager:
    """
    Verwaltet Datenbank-Operationen
    """
    def __init__(self, database_url):
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)
        
    def create_tables(self):
        """Erstellt alle Tabellen"""
        Base.metadata.create_all(self.engine)
        print("✅ Datenbank-Tabellen erstellt")
    
    def get_session(self):
        """Gibt eine neue DB-Session zurück"""
        return self.SessionLocal()
    
    def save_scan_session(self, scan_data):
        """Speichert eine komplette Scan-Session"""
        session = self.get_session()
        try:
            scan_session = ScanSession(**scan_data)
            session.add(scan_session)
            session.commit()
            session.refresh(scan_session)
            return scan_session.id
        except Exception as e:
            session.rollback()
            print(f"❌ Fehler beim Speichern: {e}")
            return None
        finally:
            session.close()
    
    def get_latest_scan(self):
        """Holt den neuesten Scan"""
        session = self.get_session()
        try:
            scan = session.query(ScanSession).order_by(
                ScanSession.timestamp.desc()
            ).first()
            return scan
        finally:
            session.close()
    
    def get_all_scans(self, limit=10):
        """Holt die letzten N Scans"""
        session = self.get_session()
        try:
            scans = session.query(ScanSession).order_by(
                ScanSession.timestamp.desc()
            ).limit(limit).all()
            return [scan.to_dict() for scan in scans]
        finally:
            session.close()
    
    def get_all_vulnerabilities(self, severity=None):
        """Holt alle Vulnerabilities, optional gefiltert nach Severity"""
        session = self.get_session()
        try:
            query = session.query(Vulnerability)
            if severity:
                query = query.filter(Vulnerability.severity == severity)
            vulns = query.order_by(Vulnerability.cvss_score.desc()).all()
            return [vuln.to_dict() for vuln in vulns]
        finally:
            session.close()
    
    def get_security_events(self, limit=50, include_demo=True):
        """Holt Security Events"""
        session = self.get_session()
        try:
            query = session.query(SecurityEvent)
            if not include_demo:
                query = query.filter(SecurityEvent.is_demo == False)
            events = query.order_by(
                SecurityEvent.timestamp.desc()
            ).limit(limit).all()
            return [event.to_dict() for event in events]
        finally:
            session.close()
    
    def get_statistics(self):
        """Holt Statistiken für Dashboard"""
        session = self.get_session()
        try:
            stats = {
                'total_scans': session.query(ScanSession).count(),
                'total_hosts': session.query(Host).count(),
                'total_vulnerabilities': session.query(Vulnerability).count(),
                'critical_vulns': session.query(Vulnerability).filter(
                    Vulnerability.severity == 'CRITICAL'
                ).count(),
                'total_events': session.query(SecurityEvent).count(),
            }
            return stats
        finally:
            session.close()


# Initialisierung
def init_database(database_url):
    """
    Initialisiert die Datenbank
    """
    db_manager = DatabaseManager(database_url)
    db_manager.create_tables()
    return db_manager


if __name__ == "__main__":
    # Test der Datenbank
    from config import DATABASE_URL
    
    print("🔧 Initialisiere Datenbank...")
    db = init_database(DATABASE_URL)
    
    print("📊 Statistiken:")
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("✅ Datenbank bereit!")