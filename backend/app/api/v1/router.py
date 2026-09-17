from fastapi import APIRouter

from app.api.v1.endpoints import graph, health, projects, ripple, risk, sbom, vulnerabilities

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(projects.router, prefix="/projects", tags=["Projects"])
api_router.include_router(sbom.router, prefix="/projects", tags=["SBOM"])
api_router.include_router(graph.router, prefix="/projects", tags=["Graph"])
api_router.include_router(vulnerabilities.router, tags=["Vulnerabilities"])
api_router.include_router(ripple.router, prefix="/projects", tags=["Ripple Propagation"])
api_router.include_router(risk.router, prefix="/projects", tags=["Structural Risk & Priority"])
