# Skill: Configuration, Logging, and Error Handling

## 1. Purpose
Provide unified environment configuration, structured logging, and robust non-fatal error isolation.

## 2. When to Use
During Stage 1 foundation setup and whenever adding configurable services or log events.

## 3. Prerequisites
Pydantic v2 Settings or standard library configuration.

## 4. Implementation Steps
1. Define Settings class in tracehunt/config.py inheriting from pydantic_settings.BaseSettings.
2. Read .env file automatically with fallback defaults for DATABASE_URL, LOG_LEVEL, etc.
3. Configure structured logging in tracehunt/logging_config.py supporting JSON and readable console formats.
4. Define domain-specific exceptions inheriting from TraceHuntError.
5. Catch and log errors with appropriate severity (ERROR for unexpected, WARNING for handled malformed inputs).

## 5. Expected Outputs
tracehunt/config.py, tracehunt/logging_config.py, tracehunt/exceptions.py.

## 6. Verification Criteria
Test configuration overrides via environment variables; verify structured log emission.

## 7. Common Failures & Troubleshooting
Hardcoded credentials or paths; print() statements in production code; unhandled crashes on bad inputs.

## 8. Safety & Ethical Considerations
Never log sensitive credentials, raw passwords, or authorization tokens.

## 9. Documentation Updates
Document configuration options in .env.example and README.md.
