"""
SecureOffice Hub - API Models
Pydantic models for request/response validation
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict
from datetime import datetime
from enum import Enum


# ============================================================================
# ENUMS
# ============================================================================

class ScanStatusEnum(str, Enum):
    """Scan status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityEnum(str, Enum):
    """Vulnerability severity"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevelEnum(str, Enum):
    """Risk assessment levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


# ============================================================================
# REQUEST MODELS
# ============================================================================

class ScanRequest(BaseModel):
    """Request model for creating a new scan"""
    
    network_range: str = Field(
        ...,
        description="Network range to scan (e.g., '192.168.1.0/24')",
        example="192.168.1.0/24"
    )
    
    ports: Optional[List[int]] = Field(
        None,
        description="List of ports to scan (default: common ports)",
        example=[21, 22, 23, 80, 443, 445, 3306, 3389]
    )
    
    fast_mode: bool = Field(
        True,
        description="Use fast scanning mode"
    )
    
    @validator('network_range')
    def validate_network_range(cls, v):
        """Validate network range format"""
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            raise ValueError(f"Invalid network range: {v}")
    
    @validator('ports')
    def validate_ports(cls, v):
        """Validate port numbers"""
        if v is not None:
            if not all(1 <= port <= 65535 for port in v):
                raise ValueError("Port numbers must be between 1 and 65535")
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "network_range": "192.168.1.0/24",
                "ports": [80, 443, 22, 3389],
                "fast_mode": True
            }
        }


class RiskAssessmentRequest(BaseModel):
    """Request model for risk assessment"""
    
    scan_id: str = Field(
        ...,
        description="Scan identifier",
        example="scan_abc123"
    )


class ReportRequest(BaseModel):
    """Request model for report generation"""
    
    scan_id: str = Field(..., description="Scan identifier")
    format: str = Field("pdf", description="Report format (pdf, json)")
    include_charts: bool = Field(True, description="Include visualizations")


# ============================================================================
# RESPONSE MODELS
# ============================================================================

class PortInfo(BaseModel):
    """Port information"""
    port: int
    state: str
    service: str
    version: Optional[str] = None


class HostInfo(BaseModel):
    """Host information"""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    status: str
    os_guess: Optional[str] = None
    open_ports: List[PortInfo] = []


class VulnerabilityInfo(BaseModel):
    """Vulnerability information"""
    vuln_id: str
    title: str
    description: str
    severity: SeverityEnum
    cvss_score: float = Field(..., ge=0, le=10)
    affected_host: Optional[str] = None
    affected_port: Optional[int] = None
    affected_service: Optional[str] = None
    cve_ids: List[str] = []
    recommendation: str
    exploit_available: bool = False
    patch_available: bool = False


class ScanResponse(BaseModel):
    """Response model for scan creation"""
    scan_id: str
    status: ScanStatusEnum
    network_range: str
    started_at: datetime
    estimated_duration: int = Field(..., description="Estimated duration in seconds")
    
    class Config:
        schema_extra = {
            "example": {
                "scan_id": "scan_abc123",
                "status": "running",
                "network_range": "192.168.1.0/24",
                "started_at": "2025-10-16T12:30:00",
                "estimated_duration": 30
            }
        }


class ScanResultsResponse(BaseModel):
    """Complete scan results"""
    scan_id: str
    status: ScanStatusEnum
    network_range: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None
    total_hosts: int
    hosts: List[HostInfo]
    
    class Config:
        schema_extra = {
            "example": {
                "scan_id": "scan_abc123",
                "status": "completed",
                "network_range": "192.168.1.0/24",
                "total_hosts": 5,
                "duration": 25.3,
                "hosts": []
            }
        }


class RiskAssessment(BaseModel):
    """Risk assessment response"""
    overall_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevelEnum
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int = 0
    recommendations: List[str]
    
    class Config:
        schema_extra = {
            "example": {
                "overall_score": 75.5,
                "risk_level": "HIGH",
                "critical_findings": 3,
                "high_findings": 5,
                "medium_findings": 8,
                "recommendations": [
                    "Disable Telnet immediately",
                    "Update SMB patches"
                ]
            }
        }


class HealthCheck(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str
    database: str


class ScanStatus(BaseModel):
    """Scan status information"""
    scan_id: str
    status: ScanStatusEnum
    progress: int = Field(..., ge=0, le=100)
    current_host: Optional[str] = None
    hosts_scanned: int = 0
    hosts_remaining: int = 0


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime


class StatisticsResponse(BaseModel):
    """Statistics response"""
    total_scans: int
    total_hosts: int
    total_vulnerabilities: int
    critical_vulns: int
    high_vulns: int
    last_scan: Optional[datetime] = None