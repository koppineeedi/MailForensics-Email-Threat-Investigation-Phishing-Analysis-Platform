"""URL Intelligence API — Standalone phishing URL analysis endpoint."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from typing import Optional

from ..services.url_intelligence import analyze_url
from .deps import get_current_user
from ..models.models import User

router = APIRouter(prefix="/api/url-intelligence", tags=["URL Intelligence"])


class URLAnalysisRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('URL cannot be empty')
        if len(v) > 2048:
            raise ValueError('URL exceeds maximum allowed length of 2048 characters')
        return v.strip()


class URLAnalysisResponse(BaseModel):
    url: str
    risk_score: int
    risk_category: str
    detections: list
    summary: str
    is_safe_to_display: bool
    parsed: Optional[dict] = None


@router.post("/analyze", response_model=URLAnalysisResponse)
async def analyze_url_endpoint(
    request: URLAnalysisRequest,
    _current_user: User = Depends(get_current_user),
):
    """
    Analyze a URL for phishing indicators using static heuristics only.
    NO network requests are made to the submitted URL (SSRF prevention by design).
    """
    result = analyze_url(request.url)
    return URLAnalysisResponse(**result)


@router.get("/health")
async def url_intelligence_health():
    """Health check for URL Intelligence module."""
    return {
        "status": "operational",
        "module": "URL Intelligence",
        "detectors": 12,
        "note": "Static analysis only — no network requests to analyzed URLs",
    }
