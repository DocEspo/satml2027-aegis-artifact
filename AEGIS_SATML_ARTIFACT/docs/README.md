# AEGIS v3.2 — SaTML 2027 Anonymous Artifact Package

## Overview

This artifact package supports the reproducibility evaluation for the AEGIS v3.2 submission to IEEE SaTML 2027. AEGIS is a semantic-compiler-attached pre-retrieval adversarial security architecture that enforces authorization decisions on retrieval requests before they reach the knowledge retrieval layer.

## Artifact Contents

```
AEGIS_SATML_ARTIFACT/
├── docs/
│   ├── README.md                      (this file)
│   ├── ARTIFACT_MANIFEST.md           artifact inventory
│   ├── REPRODUCTION.md                reproduction instructions
│   ├── CLAIMS_TO_ARTIFACTS.md         claim → evidence mapping
│   ├── ANONYMIZATION_AUDIT.md         anonymization log
│   ├── LIMITATIONS.md                 known limitations and boundaries
│   └── ARTIFACT_VALIDATION_REPORT.md  independent validation results
├── sql/
│   ├── 01_schema_and_tables.sql       schema DDL (anonymized)
│   ├── 02_threat_attributes.sql       15 governed threat attributes
│   ├── 03_ontology_tables.sql         ontology dimension values
│   ├── 04_core_procedures.sql         frozen v3.2 pipeline procedures
│   ├── 05_comparative_benchmark.sql   5-condition benchmark automation
│   └── 06_metric_recomputation.sql    independent metric validation
└── data/
    ├── corpus_690_sanitized.csv       690-case evaluation corpus (payloads redacted)
    ├── threat_attributes_15.csv       15 governed threat attributes
    └── comparative_benchmark.csv      5-condition benchmark results
```

## Reproduction Levels

| Level | Status | Description |
|-------|--------|-------------|
| Level 1 — Inspection | SUPPORTED | Architecture, schema, ontology, threat attributes, scoring, thresholds, decisions, lineage |
| Level 2 — Metric Reproduction | SUPPORTED | All published metrics independently recomputed from case-level outputs |
| Level 3 — Execution Reproduction | SUPPORTED | Frozen v3.2 procedures executable on any Snowflake account |

## Quick Start

1. Create a Snowflake database and schema: `CREATE DATABASE ARTIFACT_DB; CREATE SCHEMA ARTIFACT_DB.AEGIS_REPRO;`
2. Execute SQL files in order: `01_schema_and_tables.sql` through `06_metric_recomputation.sql`
3. Load CSV data files into the corresponding tables
4. Run `06_metric_recomputation.sql` to independently verify all published metrics

## Anonymization

All identifying references (database names, schema names, account identifiers, usernames, roles, warehouse names) have been replaced with neutral placeholders. See `ANONYMIZATION_AUDIT.md` for details.

## Dual-Use Sanitization

Adversarial request payloads have been replaced with structural descriptions preserving evaluation semantics while removing attack utility. See `LIMITATIONS.md` for details on what was withheld.
