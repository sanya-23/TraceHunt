# Skill: Python Architecture & Package Design

## 1. Purpose
Maintain clean, modular, typed Python architecture following enterprise clean architecture patterns.

## 2. When to Use
When structuring new packages, classes, models, or service layers in TraceHunt.

## 3. Prerequisites
Python 3.11+ installed; familiarity with tracehunt package layout.

## 4. Implementation Steps
1. Organize code under tracehunt/: models, schemas, ingestion, graph, detection, investigation, reporting, dashboard.
2. Use explicit type hints (PEP 484/585) across all function signatures.
3. Separate business logic from framework code (FastAPI routes call services; services call models/repos).
4. Avoid circular imports using proper dependency injection and layered imports.
5. Keep classes cohesive and functions under 50 lines where practical.

## 5. Expected Outputs
Maintainable, lint-clean, typed Python codebase.

## 6. Verification Criteria
Run python -m pytest and static analysis without syntax or import errors.

## 7. Common Failures & Troubleshooting
Monolithic files; coupling UI logic with detection engine; missing type hints.

## 8. Safety & Ethical Considerations
Prevent code injection by isolating dynamic evaluations.

## 9. Documentation Updates
Document new architectural decisions in docs/DECISIONS.md.
