# Claims to Artifacts — AEGIS v3.2 SaTML 2027

This document maps each scientific claim in the manuscript to the specific artifact(s) that support it.

## Claim 1: AEGIS achieves 83.65% Correct Prevention Rate across 690 adversarial test cases

| Artifact | Evidence |
|----------|----------|
| `data/corpus_690_sanitized.csv` | 690 cases: 581 hostile, 109 benign |
| `data/comparative_benchmark.csv` | AEGIS_V3_FULL row: CPR = 83.65% |
| `sql/06_metric_recomputation.sql` | Independent recomputation produces identical values |
| `docs/ARTIFACT_VALIDATION_REPORT.md` | Validated: all counts match |

## Claim 2: AEGIS reduces ASR from 100% (raw retrieval) to 16.35% (v3.2 full)

| Artifact | Evidence |
|----------|----------|
| `data/comparative_benchmark.csv` | RAW_RETRIEVAL ASR=100%, AEGIS_V3_FULL ASR=16.35% |
| `sql/05_comparative_benchmark.sql` | 5-condition benchmark automation |
| `sql/06_metric_recomputation.sql` | Independent validation |

## Claim 3: Fix 1 (ROLE_IMPERSONATION) + Fix 4 (HIDDEN_INSTRUCTION) reduce residual hostile PERMITs by 50 cases (145 → 95)

| Artifact | Evidence |
|----------|----------|
| `sql/02_threat_attributes.sql` | TA-010..012 (ROLE_IMPERSONATION), TA-017..019 (CONCEALMENT) |
| `sql/06_metric_recomputation.sql` | Ablation query: 9-TA=145, 15-TA=95, delta=50 |
| `docs/ARTIFACT_VALIDATION_REPORT.md` | Independently validated |

## Claim 4: Matching logic uses intent-and-corroborate-or-scoped-independent

| Artifact | Evidence |
|----------|----------|
| `sql/04_core_procedures.sql` | `AEGIS_MATCH_THREAT_ATTRIBUTES` — intent match AND (instruction OR retrieval OR payload) corroboration, OR scoped independent triggers |
| Governance snapshot | `MATCHING_LOGIC_VERSION = 'INTENT_AND_CORROBORATE_OR_SCOPED_INDEPENDENT'` |

## Claim 5: Scoring uses τ₁=0.50 (RESTRICT) and τ₂=0.85 (BLOCK)

| Artifact | Evidence |
|----------|----------|
| `sql/04_core_procedures.sql` | `AEGIS_AUTHORIZE_RETRIEVAL_PLAN` — `WHEN :v_score >= 0.85 THEN 'BLOCK'`, `WHEN :v_score >= 0.50 THEN 'RESTRICT'` |
| `sql/04_core_procedures.sql` | `AEGIS_SCORE_RETRIEVAL_RISK` — risk class: HIGH ≥ 0.85, MEDIUM ≥ 0.50 |
| Governance snapshot | `SCORING_THRESHOLD_RESTRICT = 0.5, SCORING_THRESHOLD_BLOCK = 0.85` |

## Claim 6: 15 governed threat attributes span 7 intent classes, 6 instruction classes, 6 retrieval classes, 6 payload classes

| Artifact | Evidence |
|----------|----------|
| `sql/02_threat_attributes.sql` | 15 TA rows with all dimension values |
| `sql/03_ontology_tables.sql` | 4 ontology tables: 7+6+6+6 = 25 values |
| `data/threat_attributes_15.csv` | Direct data file |

## Claim 7: 95 residual hostile PERMITs decompose into 8 gap categories

| Artifact | Evidence |
|----------|----------|
| `sql/06_metric_recomputation.sql` | Residual decomposition query: TOOL_PARAM_MANIP(42), CROSS_DOMAIN_MISMATCH(15), PAYLOAD_MISMATCH(13), NO_CORROBORATION(9), INTENT_NONE(7), ROLE_IMPERSONATION_UNCOVERED(4), HIDDEN_INSTR_UNCOVERED(3), OTHER(2) |
| `docs/ARTIFACT_VALIDATION_REPORT.md` | Sum = 95 validated |

## Claim 8: Evaluation is deterministic — zero variance across repeated trials

| Artifact | Evidence |
|----------|----------|
| `sql/06_metric_recomputation.sql` | Recomputation produces identical values on every execution |
| `sql/04_core_procedures.sql` | All procedures are deterministic SQL with no stochastic elements |

## Claim 9: Benign false positive rate is 4.59% (5/109)

| Artifact | Evidence |
|----------|----------|
| `data/comparative_benchmark.csv` | AEGIS_V3_FULL: benign_blocked=5, benign_tests=109, FPR=4.59% |
| `sql/06_metric_recomputation.sql` | Independent recomputation confirms 5 benign BLOCK |
