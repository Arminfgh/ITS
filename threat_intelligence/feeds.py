"""
SecureOffice Hub - Threat Intelligence Feeds
Integrates with AlienVault OTX and Abuse.ch
"""

import requests
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import os


class ThreatIntelligence:
    """
    Aggregates threat intelligence from multiple sources
    """
    
    def __init__(self):
        self.otx_api_key = os.getenv("OTX_API_KEY", "")
        self.otx_base_url = "https://otx.alienvault.com/api/v1"
        self.abuse_ch_base_url = "https://urlhaus-api.abuse.ch/v1"
        
    # ========================================================================
    # ALIENVAULT OTX
    # ========================================================================
    
    def check_ip_reputation_otx(self, ip_address: str) -> Dict:
        """
        Check IP reputation via AlienVault OTX
        
        Args:
            ip_address: IP to check
            
        Returns:
            Threat intelligence data
        """
        if not self.otx_api_key:
            return {"error": "OTX API key not configured"}
        
        try:
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            url = f"{self.otx_base_url}/indicators/IPv4/{ip_address}/general"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    "ip": ip_address,
                    "reputation": data.get("reputation", 0),
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "is_malicious": data.get("reputation", 0) < -1,
                    "country": data.get("country_name", "Unknown"),
                    "asn": data.get("asn", "Unknown"),
                    "source": "AlienVault OTX"
                }
            else:
                return {
                    "ip": ip_address,
                    "error": f"API returned status {response.status_code}",
                    "source": "AlienVault OTX"
                }
                
        except Exception as e:
            return {
                "ip": ip_address,
                "error": str(e),
                "source": "AlienVault OTX"
            }
    
    def get_recent_pulses_otx(self, limit: int = 10) -> List[Dict]:
        """
        Get recent threat pulses from OTX
        
        Args:
            limit: Number of pulses to retrieve
            
        Returns:
            List of threat pulses
        """
        if not self.otx_api_key:
            return [{"error": "OTX API key not configured"}]
        
        try:
            headers = {"X-OTX-API-KEY": self.otx_api_key}
            url = f"{self.otx_base_url}/pulses/subscribed"
            params = {"limit": limit}
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                pulses = []
                
                for pulse in data.get("results", [])[:limit]:
                    pulses.append({
                        "id": pulse.get("id"),
                        "name": pulse.get("name"),
                        "description": pulse.get("description", "")[:200],
                        "created": pulse.get("created"),
                        "tlp": pulse.get("TLP", "unknown"),
                        "tags": pulse.get("tags", []),
                        "indicator_count": len(pulse.get("indicators", [])),
                        "source": "AlienVault OTX"
                    })
                
                return pulses
            else:
                return [{"error": f"API returned status {response.status_code}"}]
                
        except Exception as e:
            return [{"error": str(e)}]
    
    # ========================================================================
    # ABUSE.CH
    # ========================================================================
    
    def check_url_abuse_ch(self, url: str) -> Dict:
        """
        Check URL against Abuse.ch URLhaus
        
        Args:
            url: URL to check
            
        Returns:
            Threat intelligence data
        """
        try:
            api_url = f"{self.abuse_ch_base_url}/url/"
            data = {"url": url}
            
            response = requests.post(api_url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get("query_status") == "ok":
                    return {
                        "url": url,
                        "is_malicious": True,
                        "threat_type": result.get("threat", "Unknown"),
                        "tags": result.get("tags", []),
                        "first_seen": result.get("date_added"),
                        "last_seen": result.get("last_online"),
                        "source": "Abuse.ch URLhaus"
                    }
                else:
                    return {
                        "url": url,
                        "is_malicious": False,
                        "status": "clean",
                        "source": "Abuse.ch URLhaus"
                    }
            else:
                return {
                    "url": url,
                    "error": f"API returned status {response.status_code}",
                    "source": "Abuse.ch URLhaus"
                }
                
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
                "source": "Abuse.ch URLhaus"
            }
    
    def get_recent_malware_abuse_ch(self, limit: int = 10) -> List[Dict]:
        """
        Get recent malware samples from Abuse.ch
        
        Args:
            limit: Number of samples to retrieve
            
        Returns:
            List of malware samples
        """
        try:
            api_url = f"{self.abuse_ch_base_url}/urls/recent/"
            
            response = requests.get(api_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                samples = []
                
                for item in data.get("urls", [])[:limit]:
                    samples.append({
                        "id": item.get("id"),
                        "url": item.get("url"),
                        "threat": item.get("threat", "Unknown"),
                        "tags": item.get("tags", []),
                        "date_added": item.get("date_added"),
                        "urlhaus_link": item.get("urlhaus_reference"),
                        "source": "Abuse.ch URLhaus"
                    })
                
                return samples
            else:
                return [{"error": f"API returned status {response.status_code}"}]
                
        except Exception as e:
            return [{"error": str(e)}]
    
    # ========================================================================
    # AGGREGATION
    # ========================================================================
    
    def check_ip_reputation(self, ip_address: str) -> Dict:
        """
        Check IP reputation across all sources
        
        Args:
            ip_address: IP to check
            
        Returns:
            Aggregated threat intelligence
        """
        results = {
            "ip": ip_address,
            "checked_at": datetime.now().isoformat(),
            "sources": []
        }
        
        # Check OTX
        otx_result = self.check_ip_reputation_otx(ip_address)
        if "error" not in otx_result:
            results["sources"].append(otx_result)
        
        # Aggregate results
        is_malicious = any(
            source.get("is_malicious", False) 
            for source in results["sources"]
        )
        
        results["is_malicious"] = is_malicious
        results["threat_level"] = "HIGH" if is_malicious else "LOW"
        
        return results
    
    def enrich_scan_results(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Enrich scan results with threat intelligence
        
        Args:
            scan_results: List of scanned hosts
            
        Returns:
            Enriched scan results
        """
        enriched = []
        
        for host in scan_results:
            ip = host.get("ip_address")
            
            # Add threat intelligence
            threat_intel = self.check_ip_reputation(ip)
            
            host["threat_intelligence"] = {
                "is_malicious": threat_intel.get("is_malicious", False),
                "threat_level": threat_intel.get("threat_level", "UNKNOWN"),
                "sources_count": len(threat_intel.get("sources", [])),
                "checked_at": threat_intel.get("checked_at")
            }
            
            enriched.append(host)
        
        return enriched


# ============================================================================
# DEMO FUNCTIONS
# ============================================================================

def demo_threat_intelligence():
    """
    Demo der Threat Intelligence Integration
    """
    print("="*70)
    print("🔍 THREAT INTELLIGENCE DEMO")
    print("="*70)
    
    ti = ThreatIntelligence()
    
    # Test IP (known malicious for demo)
    test_ip = "8.8.8.8"  # Google DNS (clean)
    
    print(f"\n📊 Checking IP: {test_ip}")
    result = ti.check_ip_reputation(test_ip)
    
    print(f"\nIs Malicious: {result.get('is_malicious')}")
    print(f"Threat Level: {result.get('threat_level')}")
    print(f"Sources Checked: {len(result.get('sources', []))}")
    
    # Recent threats
    print("\n🚨 Recent Threat Pulses:")
    pulses = ti.get_recent_pulses_otx(limit=5)
    
    for i, pulse in enumerate(pulses[:3], 1):
        if "error" not in pulse:
            print(f"\n[{i}] {pulse.get('name')}")
            print(f"    Tags: {', '.join(pulse.get('tags', [])[:3])}")
            print(f"    Indicators: {pulse.get('indicator_count')}")
    
    print("\n✅ Threat Intelligence Demo Complete!")


if __name__ == "__main__":
    demo_threat_intelligence()