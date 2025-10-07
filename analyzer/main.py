"""
SecureOffice Hub - REST API
FastAPI backend for network security scanning
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scanner.network_scanner import NetworkScanner
from detector.vulnerability_db import VulnerabilityDatabase
from detector.risk_calculator import RiskCalculator
from reports.generator import ReportGenerator
from api.models import (
    ScanRequest, ScanResponse, HostInfo, VulnerabilityInfo,
    RiskAssessment, HealthCheck, ScanStatus
)
from api.auth import verify_api_key
from database.models import DatabaseManager
from config import DATABASE_URL

# ============================================================================
# APP INITIALIZATION
# ============================================================================

app = FastAPI(
    title="🛡️ SecureOffice Hub API",
    description="Network Security Scanner & Vulnerability Analyzer",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Database
db_manager = DatabaseManager(DATABASE_URL)
db_manager.create_tables()

# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health", response_model=HealthCheck, tags=["System"])
async def health_check():
    """Health check endpoint for Docker/K8s"""
    return HealthCheck(
        status="healthy",
        timestamp=datetime.now(),
        version="1.0.0",
        database="connected" if db_manager else "disconnected"
    )

@app.get("/", tags=["System"])
async def root():
    """Root endpoint with API info"""
    return {
        "name": "SecureOffice Hub API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "description": "Network Security Scanner & Vulnerability Analyzer"
    }

# ============================================================================
# SCANNING ENDPOINTS
# ============================================================================

@app.post("/api/v1/scan", response_model=ScanResponse, tags=["Scanning"])
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Create a new network scan
    
    **Parameters:**
    - network_range: IP range to scan (e.g., "192.168.1.0/24")
    - ports: List of ports to scan
    - fast_mode: Use quick scan mode (default: true)
    
    **Returns:**
    - scan_id: Unique scan identifier
    - status: Scan status
    - estimated_duration: Expected scan time
    """
    # Verify API key
    verify_api_key(credentials)
    
    try:
        # Validate network range
        if not scan_request.network_range:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Network range is required"
            )
        
        # Create scanner
        scanner = NetworkScanner(scan_request.network_range)
        
        # Start scan in background
        scan_id = scanner.scan_id
        
        # Add to background tasks
        background_tasks.add_task(
            run_scan_task,
            scanner,
            scan_request.ports or [21, 22, 23, 80, 443, 445, 3306, 3389],
            scan_request.fast_mode
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="running",
            network_range=scan_request.network_range,
            started_at=datetime.now(),
            estimated_duration=30  # seconds
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )

@app.get("/api/v1/scan/{scan_id}", tags=["Scanning"])
async def get_scan_status(
    scan_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get scan status and results
    
    **Parameters:**
    - scan_id: Scan identifier
    
    **Returns:**
    - Scan status and results (if completed)
    """
    verify_api_key(credentials)
    
    # TODO: Implement proper status tracking
    # For now, return mock data
    
    return {
        "scan_id": scan_id,
        "status": "completed",
        "progress": 100,
        "results_available": True
    }

@app.get("/api/v1/scans", tags=["Scanning"])
async def list_scans(
    limit: int = 10,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    List recent scans
    
    **Parameters:**
    - limit: Maximum number of scans to return (default: 10)
    
    **Returns:**
    - List of recent scans
    """
    verify_api_key(credentials)
    
    scans = db_manager.get_all_scans(limit=limit)
    return {"scans": scans, "total": len(scans)}

# ============================================================================
# VULNERABILITY ENDPOINTS
# ============================================================================

@app.get("/api/v1/vulnerabilities", response_model=List[VulnerabilityInfo], tags=["Vulnerabilities"])
async def get_vulnerabilities(
    severity: Optional[str] = None,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get all detected vulnerabilities
    
    **Parameters:**
    - severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
    
    **Returns:**
    - List of vulnerabilities
    """
    verify_api_key(credentials)
    
    vulns = db_manager.get_all_vulnerabilities(severity=severity)
    return vulns

@app.get("/api/v1/vulnerabilities/port/{port}", tags=["Vulnerabilities"])
async def check_port_vulnerabilities(
    port: int,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Check vulnerabilities for a specific port
    
    **Parameters:**
    - port: Port number to check
    
    **Returns:**
    - List of known vulnerabilities for this port
    """
    verify_api_key(credentials)
    
    vuln_db = VulnerabilityDatabase()
    vulns = vuln_db.check_port(port)
    
    return {
        "port": port,
        "vulnerabilities_count": len(vulns),
        "vulnerabilities": [
            {
                "vuln_id": v.vuln_id,
                "title": v.title,
                "severity": v.severity.value,
                "cvss_score": v.cvss_score,
                "description": v.description,
                "recommendation": v.recommendation
            }
            for v in vulns
        ]
    }

# ============================================================================
# RISK ASSESSMENT ENDPOINTS
# ============================================================================

@app.post("/api/v1/risk-assessment", response_model=RiskAssessment, tags=["Risk"])
async def calculate_risk(
    scan_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Calculate risk assessment for a scan
    
    **Parameters:**
    - scan_id: Scan identifier
    
    **Returns:**
    - Risk assessment with score and recommendations
    """
    verify_api_key(credentials)
    
    # TODO: Load scan results from database
    # For now, return mock assessment
    
    return RiskAssessment(
        overall_score=75.5,
        risk_level="HIGH",
        critical_findings=3,
        high_findings=5,
        medium_findings=8,
        recommendations=[
            "Disable Telnet immediately",
            "Update SMB to latest version",
            "Enable firewall on all hosts"
        ]
    )

# ============================================================================
# REPORT ENDPOINTS
# ============================================================================

@app.post("/api/v1/reports/generate", tags=["Reports"])
async def generate_report(
    scan_id: str,
    format: str = "pdf",
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Generate security report
    
    **Parameters:**
    - scan_id: Scan identifier
    - format: Report format (pdf, json)
    
    **Returns:**
    - Report download URL
    """
    verify_api_key(credentials)
    
    # TODO: Load scan data and generate report
    
    return {
        "scan_id": scan_id,
        "format": format,
        "status": "generating",
        "download_url": f"/api/v1/reports/{scan_id}/download"
    }

# ============================================================================
# STATISTICS ENDPOINTS
# ============================================================================

@app.get("/api/v1/stats", tags=["Statistics"])
async def get_statistics(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Get overall statistics
    
    **Returns:**
    - Dashboard statistics
    """
    verify_api_key(credentials)
    
    stats = db_manager.get_statistics()
    return stats

# ============================================================================
# BACKGROUND TASKS
# ============================================================================

async def run_scan_task(scanner: NetworkScanner, ports: List[int], fast_mode: bool):
    """Background task for running scans"""
    try:
        results = scanner.scan_network(ports=ports, fast_mode=fast_mode)
        
        # Save to database
        # db_manager.save_scan_session(results)
        
        print(f"✅ Scan {scanner.scan_id} completed successfully")
        
    except Exception as e:
        print(f"❌ Scan {scanner.scan_id} failed: {e}")

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error",
            "detail": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# ============================================================================
# STARTUP / SHUTDOWN
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    print("🚀 SecureOffice Hub API starting...")
    print(f"📊 Database: {DATABASE_URL}")
    print(f"📚 Docs: http://localhost:8000/docs")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("👋 SecureOffice Hub API shutting down...")

# ============================================================================
# MAIN (for local development)
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
