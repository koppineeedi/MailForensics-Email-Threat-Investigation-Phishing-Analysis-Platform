from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
from app.schemas.schemas import ThreatIntelLookupRequest
from app.services.threat_intel_service import threat_intel_service
from app.api.deps import get_current_user

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

@router.get("/status")
def get_threat_intel_status(current_user = Depends(get_current_user)):
    """Return status of external threat intelligence providers (CONFIGURED vs NOT_CONFIGURED)."""
    return threat_intel_service.get_provider_status()

@router.post("/lookup")
async def lookup_ioc(req: ThreatIntelLookupRequest, current_user = Depends(get_current_user)):
    """
    On-demand threat intelligence lookup for SHA-256 hash or IP.
    Returns provider status and response.
    """
    if req.ioc_type == "HASH":
        res = await threat_intel_service.lookup_hash(req.ioc_value)
    elif req.ioc_type == "IP":
        res = await threat_intel_service.lookup_ip(req.ioc_value)
    else:
        res = {"status": "NOT_SUPPORTED", "message": f"IOC type {req.ioc_type} lookup not implemented."}
    
    return res
