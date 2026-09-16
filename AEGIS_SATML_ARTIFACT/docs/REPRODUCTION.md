# Reproduction Instructions — AEGIS v3.2 SaTML 2027

## Prerequisites

- Snowflake account (any edition)
- Warehouse (XS is sufficient; all evaluation completes in seconds)
- Role with CREATE DATABASE, CREATE SCHEMA, CREATE TABLE, CREATE PROCEDURE privileges

## Level 1 — Inspection Reproduction

Inspect architecture, schema, ontology, threat attributes, scoring thresholds, and decision lineage.

1. Read `02_threat_attributes.sql` — 15 governed threat attributes with severity weights, expected decisions, detection methods
2. Read `03_ontology_tables.sql` — 4 semantic dimensions (25 ontology values)
3. Read `04_core_procedures.sql` — frozen v3.2 pipeline: MAP → MATCH → SCORE → AUTHORIZE → EVALUATE
4. Verify matching logic: `INTENT_AND_CORROBORATE_OR_SCOPED_INDEPENDENT` in `AEGIS_MATCH_THREAT_ATTRIBUTES`
5. Verify scoring constants: τ₁ = 0.50 (RESTRICT), τ₂ = 0.85 (BLOCK) in `AEGIS_AUTHORIZE_RETRIEVAL_PLAN`

## Level 2 — Metric Reproduction

Independently recompute all published metrics from case-level evaluation data.

### Setup

```sql
-- Execute in order
-- 1. Create schema
SOURCE 01_schema_and_tables.sql

-- 2. Load threat attributes
SOURCE 02_threat_attributes.sql

-- 3. Load ontology
SOURCE 03_ontology_tables.sql

-- 4. Create procedures
SOURCE 04_core_procedures.sql

-- 5. Load 690-case corpus into AEGIS_TEST_CASE from corpus_690_sanitized.csv

-- 6. Run metric recomputation
SOURCE 06_metric_recomputation.sql
```

### Expected Metric Outputs

**AEGIS v3.2 Full (15 TA)**

| Metric | Expected Value |
|--------|---------------|
| Total cases | 690 |
| Hostile cases | 581 |
| Benign cases | 109 |
| BLOCK decisions | 418 |
| RESTRICT decisions | 73 |
| PERMIT decisions | 199 |
| Hostile BLOCK | 413 |
| Hostile PERMIT (residual) | 95 |
| Benign PERMIT | 104 |
| Benign BLOCK (false positive) | 5 |
| ASR | 16.35% |
| CPR | 83.65% |
| FPR | 4.59% |
| RPR | 95.41% |

**5-Condition Comparative Benchmark**

| Condition | ASR | CPR | FPR | RPR |
|-----------|-----|-----|-----|-----|
| RAW_RETRIEVAL | 100.00% | 0.00% | 0.00% | 100.00% |
| PROMPT_FILTER | 61.27% | 38.73% | 0.00% | 100.00% |
| POST_RETRIEVAL_INSPECTION | 54.04% | 45.96% | 0.00% | 100.00% |
| AEGIS_NO_ONTOLOGY | 52.50% | 47.50% | 4.59% | 95.41% |
| AEGIS_V3_FULL | 16.35% | 83.65% | 4.59% | 95.41% |

**Ablation (9 TA → 15 TA)**

| Configuration | Hostile PERMIT | ASR | Delta |
|---------------|---------------|-----|-------|
| 9-TA (without Fix 1+4) | 145 | 24.96% | — |
| 15-TA (with Fix 1+4) | 95 | 16.35% | −50 cases |

**Residual Decomposition (95 hostile PERMITs)**

| Gap Category | Count |
|-------------|-------|
| TOOL_PARAM_MANIP | 42 |
| CROSS_DOMAIN_MISMATCH | 15 |
| PAYLOAD_MISMATCH | 13 |
| NO_CORROBORATION | 9 |
| INTENT_NONE | 7 |
| ROLE_IMPERSONATION_UNCOVERED | 4 |
| HIDDEN_INSTR_UNCOVERED | 3 |
| OTHER | 2 |

## Level 3 — Execution Reproduction

Execute the frozen v3.2 pipeline against the 690-case corpus.

### Setup

Complete Level 2 setup, then execute the 5-condition benchmark:

```sql
SOURCE 05_comparative_benchmark.sql
CALL AEGIS_RUN_COMPARATIVE_BENCHMARK('REPRO-VALIDATION');
```

### Notes

- The single-pass SQL evaluation model (used in `06_metric_recomputation.sql`) independently reproduces the same decisions as the stored-procedure pipeline, confirming that the matching, scoring, and authorization logic is equivalent.
- Execution reproduction requires a Snowflake account. The SQL is standard Snowflake SQL with no external dependencies.
- All procedures use `EXECUTE AS OWNER` semantics. The executing role needs ownership of the schema.
