# Artifact Validation Report — AEGIS v3.2 SaTML 2027

## Validation Methodology

All published metrics were independently recomputed from case-level data using a single-pass SQL evaluation model that reimplements the matching, scoring, and authorization logic from first principles against the 690-case corpus and 15-TA threat attribute table. The recomputation does not call the stored procedures; it reconstructs the decision logic independently.

## Primary Metric Validation

### AEGIS v3.2 Full (15 TA)

| Metric | Reported | Recomputed | Match |
|--------|----------|------------|-------|
| Total cases | 690 | 690 | EXACT |
| Hostile cases | 581 | 581 | EXACT |
| Benign cases | 109 | 109 | EXACT |
| BLOCK decisions | 418 | 418 | EXACT |
| RESTRICT decisions | 73 | 73 | EXACT |
| PERMIT decisions | 199 | 199 | EXACT |
| Hostile BLOCKED | 413 | 413 | EXACT |
| Hostile PERMITTED | 95 | 95 | EXACT |
| Benign PERMITTED | 104 | 104 | EXACT |
| Benign BLOCKED | 5 | 5 | EXACT |
| ASR (%) | 16.35 | 16.35 | EXACT |
| CPR (%) | 83.65 | 83.65 | EXACT |
| FPR (%) | 4.59 | 4.59 | EXACT |
| RPR (%) | 95.41 | 95.41 | EXACT |

### 5-Condition Comparative Benchmark

| Condition | Reported ASR | Recomputed ASR | Match |
|-----------|-------------|----------------|-------|
| RAW_RETRIEVAL | 100.00% | 100.00% | EXACT |
| PROMPT_FILTER | 61.27% | 61.27% | EXACT |
| POST_RETRIEVAL_INSPECTION | 54.04% | 54.04% | EXACT |
| AEGIS_NO_ONTOLOGY | 52.50% | 52.50% | EXACT |
| AEGIS_V3_FULL | 16.35% | 16.35% | EXACT |

### Ablation (9 TA → 15 TA)

| Config | Reported Hostile PERMIT | Recomputed | Match |
|--------|------------------------|------------|-------|
| 9-TA | 145 | 145 | EXACT |
| 15-TA | 95 | 95 | EXACT |
| Delta | 50 | 50 | EXACT |

### Residual Decomposition

| Gap Category | Reported | Recomputed | Match |
|-------------|----------|------------|-------|
| TOOL_PARAM_MANIP | 42 | 42 | EXACT |
| CROSS_DOMAIN_MISMATCH | 15 | 15 | EXACT |
| PAYLOAD_MISMATCH | 13 | 13 | EXACT |
| NO_CORROBORATION | 9 | 9 | EXACT |
| INTENT_NONE | 7 | 7 | EXACT |
| ROLE_IMPERSONATION_UNCOVERED | 4 | 4 | EXACT |
| HIDDEN_INSTR_UNCOVERED | 3 | 3 | EXACT |
| OTHER | 2 | 2 | EXACT |
| **Sum** | **95** | **95** | **EXACT** |

## Discrepancies

**None.** All reported values match independently recomputed values exactly.

## Validation Environment

- Recomputation executed via single-pass SQL against `AEGIS_TEST_CASE` (690 rows) and `AEGIS_THREAT_ATTRIBUTE` (15 rows)
- No stored procedures were called during validation
- The SQL recomputation logic mirrors the procedure-chain logic (MAP → MATCH → SCORE → AUTHORIZE) but is implemented as a single analytical query
- Results are deterministic: identical values on every execution

## Conclusion

All published metrics are independently reproducible from the case-level evaluation data. No discrepancies were found.
