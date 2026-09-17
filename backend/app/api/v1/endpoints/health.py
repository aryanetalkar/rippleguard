from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service Health Check",
    description="Returns operational status of the RippleGuard backend service.",
)
def get_health() -> HealthResponse:
    """Return deterministic health status for monitoring and uptime probes."""
    return HealthResponse(
        status="ok",
        service="rippleguard-api",
    )
