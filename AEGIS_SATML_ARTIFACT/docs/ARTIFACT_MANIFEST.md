# Artifact Manifest — AEGIS v3.2 SaTML 2027

## Recovery Source

All artifacts were recovered from the authoritative evaluated system (`ARTIFACT_DB.AEGIS_REPRO` after anonymization). Recovery methods:

| Artifact | Source | Method |
|----------|--------|--------|
| 690-case evaluation corpus | `AEGIS_TEST_CASE` table | Direct extraction (690 active rows) |
| 15 threat attributes | `AEGIS_THREAT_ATTRIBUTE` table | Direct extraction (15 active rows) |
| Ontology dimension values | `ONTOLOGY_*` tables (4 tables) | Direct extraction (25 values across 4 dimensions) |
| Core procedures (5) | Snowflake `GET_DDL()` | Exact DDL recovery from live database |
| Comparative benchmark results | `AEGIS_COMPARATIVE_BENCHMARK_690` table | Direct extraction (5 conditions) |
| Governance snapshot | `AEGIS_EVALUATION_GOVERNANCE` table | Direct extraction (frozen lock record) |

## Frozen Configuration (v3.2)

| Parameter | Value |
|-----------|-------|
| Threat attributes | 15 (9 original + 6 from Fix 1 + Fix 4) |
| Matching logic | `INTENT_AND_CORROBORATE_OR_SCOPED_INDEPENDENT` |
| τ₁ (RESTRICT threshold) | 0.50 |
| τ₂ (BLOCK threshold) | 0.85 |
| Corpus version | v3.2-690 |
| TA version | v3.2-15TA |
| Governance label | `P3-STEP14-GOVERNANCE-LOCK` |

## Artifact Inventory

### SQL Files

| File | Purpose | Lines | Anonymized |
|------|---------|-------|------------|
| `01_schema_and_tables.sql` | Schema DDL for all evaluation tables | Yes | Yes |
| `02_threat_attributes.sql` | 15 governed threat attribute definitions | Yes | Yes |
| `03_ontology_tables.sql` | 4 ontology dimension tables (25 values) | Yes | Yes |
| `04_core_procedures.sql` | 5 frozen v3.2 pipeline procedures | Yes | Yes |
| `05_comparative_benchmark.sql` | 5-condition benchmark automation | Yes | Yes |
| `06_metric_recomputation.sql` | Independent metric validation queries | Yes | Yes |

### Data Files

| File | Rows | Columns | Sanitized |
|------|------|---------|-----------|
| `corpus_690_sanitized.csv` | 690 | 9 (payload redacted) | Yes — adversarial payloads replaced |
| `threat_attributes_15.csv` | 15 | 12 | No redaction needed |
| `comparative_benchmark.csv` | 5 | 16 | No redaction needed |

### Documentation Files

| File | Purpose |
|------|---------|
| `README.md` | Package overview and quick start |
| `ARTIFACT_MANIFEST.md` | This file |
| `REPRODUCTION.md` | Step-by-step reproduction instructions |
| `CLAIMS_TO_ARTIFACTS.md` | Scientific claims → artifact evidence mapping |
| `ANONYMIZATION_AUDIT.md` | Anonymization log |
| `LIMITATIONS.md` | Known limitations and boundaries |
| `ARTIFACT_VALIDATION_REPORT.md` | Independent recomputation results |
