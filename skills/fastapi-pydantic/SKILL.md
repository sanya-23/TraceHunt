# Skill: FastAPI & Pydantic REST API Development

## 1. Purpose
Build robust, typed REST endpoints for telemetry upload, graph query, timeline, cases, and reporting.

## 2. When to Use
During Stage 6 backend API development.

## 3. Prerequisites
FastAPI, Pydantic v2, and Uvicorn installed; database models ready.

## 4. Implementation Steps
1. Create FastAPI application in tracehunt/api/main.py with lifespan context for database init.
2. Define request/response Pydantic models in tracehunt/schemas/.
3. Implement routes: /api/ingest (upload), /api/hosts, /api/events, /api/tree, /api/findings, /api/cases, /api/reports.
4. Include OpenAPI metadata, descriptive tags, and standard error response schemas.
5. Add CORS middleware for frontend/dashboard communication if separated.

## 5. Expected Outputs
tracehunt/api/main.py, tracehunt/api/routes/*.py.

## 6. Verification Criteria
Execute pytest using httpx.AsyncClient / TestClient verifying 200 OK and 422 Unprocessable Entity responses.

## 7. Common Failures & Troubleshooting
Returning raw database models instead of Pydantic response models; leaking stack traces on 500 errors.

## 8. Safety & Ethical Considerations
Validate all upload payloads with Pydantic; enforce rate limiting or size limits.

## 9. Documentation Updates
Document API endpoints in README.md.
