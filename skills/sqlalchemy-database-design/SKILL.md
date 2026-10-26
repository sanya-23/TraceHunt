# Skill: SQLAlchemy Database Design & Integrity

## 1. Purpose
Implement relational schema supporting SQLite and PostgreSQL with foreign keys, indexes, and transactions.

## 2. When to Use
When creating or altering database models according to R&D Proposal Section 7.

## 3. Prerequisites
SQLAlchemy 2.0+ installed; docs/RND_PROPOSAL.md Section 7 referenced.

## 4. Implementation Steps
1. Create declarative base and engine factory in tracehunt/database.py.
2. Implement models: RawEvent, EndpointEvent, ProcessRelationship, DetectionRule, Finding, Investigation, InvestigationEvidence, AnalystAudit, IngestionError.
3. Apply foreign key constraints and cascade rules.
4. Add compound indexes on high-cardinality search fields: (host, event_time), (process_id, parent_process_id).
5. Implement transactional session helper with automatic rollback on error.
6. Ensure datetime fields default to datetime.now(timezone.utc).

## 5. Expected Outputs
tracehunt/models/*.py and database creation scripts.

## 6. Verification Criteria
Run pytest verifying table creation, foreign key enforcement, and relationship cascades.

## 7. Common Failures & Troubleshooting
Missing foreign keys; timezone-naive timestamps; SQLite-specific non-portable SQL dialect.

## 8. Safety & Ethical Considerations
Ensure data isolation and enforce ACID transactions.

## 9. Documentation Updates
Record schema design decisions in docs/DECISIONS.md.
