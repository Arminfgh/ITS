"""
SecureOffice Hub - API Authentication
Simple API Key authentication for demo
"""

from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
import os


# Default API key (change in production!)
DEFAULT_API_KEY = os.getenv("API_KEY", "secureoffice-demo-key-change-in-production")


def verify_api_key(credentials: HTTPAuthorizationCredentials) -> bool:
    """
    Verify API key from Bearer token
    
    Args:
        credentials: HTTP Authorization credentials
        
    Returns:
        True if valid
        
    Raises:
        HTTPException: If invalid
    """
    if credentials.credentials != DEFAULT_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return True


def get_api_key_header():
    """
    Returns the API key for documentation
    """
    return {
        "Authorization": f"Bearer {DEFAULT_API_KEY}"
    }
