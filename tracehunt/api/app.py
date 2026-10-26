"""FastAPI Application Factory for TraceHunt Platform.

Configures OpenAPI metadata, lifespan database initialization, CORS,
domain exception handlers, and modular /api/v1 routes.
"""

from contextlib import asynccontextmanager
from typing import Any
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from tracehunt.api.routes.cases import router as cases_router
from tracehunt.api.routes.detections import router as detections_router
from tracehunt.api.routes.health import router as health_router
from tracehunt.api.routes.hosts import router as hosts_router
from tracehunt.api.routes.ingest import router as ingest_router
from tracehunt.api.routes.reports import router as reports_router
from tracehunt.config import settings
from tracehunt.database import init_db
from tracehunt.exceptions import (
    CaseManagementError,
    ConfigurationError,
    DatabaseError,
    IngestionError,
    NormalizationError,
    ReportExportError,
    RuleEvaluationError,
    TraceHuntError,
    ValidationError,
)
from tracehunt.logging_config import get_logger

logger = get_logger("api.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager initializing database tables and default rules."""
    logger.info("Initializing TraceHunt database and verifying detection rules on startup...")
    settings.ensure_directories()
    init_db(seed_rules=True)
    yield
    logger.info("TraceHunt API server shutting down cleanly.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="TraceHunt Threat Hunting Platform API",
        version="1.0.0",
        description=(
            "Enterprise Endpoint Threat-Hunting and Behavioral Investigation REST API. "
            "Ingests Windows Sysmon and Security telemetry, reconstructs parent-child process DAGs, "
            "evaluates explainable behavioral detection rules, manages investigation cases with "
            "immutable audit trails, and exports reproducible reports."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS configuration for local dashboard access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # Exception Handlers
    # -----------------------------------------------------------------------

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "ValidationError", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(CaseManagementError)
    async def case_management_error_handler(request: Request, exc: CaseManagementError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "CaseManagementError", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(IngestionError)
    async def ingestion_error_handler(request: Request, exc: IngestionError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "IngestionError", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(ReportExportError)
    async def report_export_error_handler(request: Request, exc: ReportExportError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "ReportExportError", "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(TraceHuntError)
    async def general_domain_error_handler(request: Request, exc: TraceHuntError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": exc.__class__.__name__, "message": exc.message, "details": exc.details},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error(f"Unhandled server error on {request.method} {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "message": "An internal server error occurred. Details have been logged securely.",
            },
        )

    # -----------------------------------------------------------------------
    # Route Registration under /api/v1
    # -----------------------------------------------------------------------

    api_v1_prefix = "/api/v1"
    app.include_router(health_router, prefix=api_v1_prefix)
    app.include_router(ingest_router, prefix=api_v1_prefix)
    app.include_router(hosts_router, prefix=api_v1_prefix)
    app.include_router(detections_router, prefix=api_v1_prefix)
    app.include_router(cases_router, prefix=api_v1_prefix)
    app.include_router(reports_router, prefix=api_v1_prefix)

    @app.get("/", include_in_schema=False)
    def root():
        """Redirect root path to interactive OpenAPI documentation."""
        return RedirectResponse(url="/docs")

    return app


# Application singleton for ASGI servers (uvicorn tracehunt.api.app:app)
app = create_app()
