from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints.health import HealthResponse, get_health
from app.api.v1.router import api_router
from app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
)

# Configure CORS Middleware
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Root-level health endpoint for uptime checks and load balancer probes
app.add_api_route(
    "/health",
    get_health,
    methods=["GET"],
    response_model=HealthResponse,
    tags=["Health"],
    summary="Root Health Check",
)

# Mount structured API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)
