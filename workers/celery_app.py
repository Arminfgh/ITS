"""
SecureOffice Hub - Celery Worker
Background tasks for scanning and enrichment
"""

from celery import Celery
from celery.schedules import crontab
import os
import sys
from pathlib import Path

# Add project root
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR))

from scanner.network_scanner import NetworkScanner
from detector.vulnerability_db import VulnerabilityDatabase
from threat_intelligence.feeds import ThreatIntelligence

# ============================================================================
# CELERY APP
# ============================================================================

app = Celery(
    'secureoffice',
    broker=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('REDIS_URL', 'redis://localhost:6379/0')
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Europe/Berlin',
    enable_utc=True,
)

# ============================================================================
# TASKS
# ============================================================================

@app.task(name='scan_network')
def scan_network_task(network_range: str, ports: list):
    """Background task for network scanning"""
    try:
        scanner = NetworkScanner(network_range)
        results = scanner.scan_network(ports=ports, fast_mode=True)
        
        return {
            'status': 'success',
            'scan_id': results['scan_id'],
            'hosts_found': results['total_hosts']
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

@app.task(name='enrich_with_threat_intel')
def enrich_threat_intel_task(scan_id: str):
    """Enrich scan results with threat intelligence"""
    try:
        ti = ThreatIntelligence()
        # Load scan results and enrich
        
        return {
            'status': 'success',
            'scan_id': scan_id
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

@app.task(name='daily_threat_update')
def daily_threat_update():
    """Daily task to update threat intelligence"""
    try:
        ti = ThreatIntelligence()
        pulses = ti.get_recent_pulses_otx(limit=50)
        
        return {
            'status': 'success',
            'pulses_updated': len(pulses)
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

# ============================================================================
# SCHEDULED TASKS
# ============================================================================

app.conf.beat_schedule = {
    'update-threat-intel-daily': {
        'task': 'daily_threat_update',
        'schedule': crontab(hour=2, minute=0),  # 2 AM daily
    },
}