from typing import List
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "RippleGuard"
    VERSION: str = "0.2.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str = "sqlite:///./rippleguard.db"

    # CORS configuration
    CORS_ORIGIN: str = "http://localhost:3000"

    # Security & Upload Controls
    MAX_SBOM_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB

    @computed_field
    @property
    def CORS_ORIGINS(self) -> List[str]:
        if not self.CORS_ORIGIN:
            return ["http://localhost:3000"]
        return [origin.strip() for origin in self.CORS_ORIGIN.split(",") if origin.strip()]

    # Phase 3 External Intelligence
    OSV_API_URL: str = "https://api.osv.dev/v1"

    # Phase 6 Gemini AI Explanation & Intelligence Configuration
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-3.8-flash"
    GEMINI_TIMEOUT_SECONDS: float = 30.0
    GEMINI_MAX_RETRIES: int = 2
    MAX_EXPLANATIONS_PER_REQUEST: int = 25

    # Phase 4 Ripple Propagation Safety Controls
    MAX_RIPPLE_DEPTH: int = 10
    MAX_RIPPLE_NODES: int = 500
    MAX_RIPPLE_PATHS: int = 100
    MAX_RIPPLE_RESULT_SIZE: int = 1000

    # Phase 5 Structural Risk & Centrality Controls
    CENTRALITY_EXACT_NODE_LIMIT: int = 2000
    MAX_CENTRALITY_NODES: int = 5000
    BETWEENNESS_SAMPLE_SIZE: int = 100
    BETWEENNESS_RANDOM_SEED: int = 42
    PAGERANK_ALPHA: float = 0.85
    PAGERANK_MAX_ITER: int = 200
    PAGERANK_TOLERANCE: float = 1e-8


settings = Settings()
