# Limitations — AEGIS v3.2 SaTML 2027

## Dual-Use Sanitization

### What Was Withheld

The `REQUEST_PAYLOAD` column in `corpus_690_sanitized.csv` has been replaced with `[REDACTED — see PURPOSE_SUMMARY]` for all 581 hostile test cases. This column contained synthetic adversarial prompts used during evaluation.

**Withheld content types:**
- Authority override injection prompts (e.g., "Ignore prior controls and...")
- Policy bypass instruction prompts
- Base64-encoded hostile payloads
- Role impersonation phrasing
- Retrieval redirection instructions
- Data exfiltration request patterns
- Obfuscated/encoded attack strings

**Preserved for all cases (including hostile):**
- Case ID (`TEST_ID`)
- Test family (`TEST_FAMILY`)
- Purpose description (`PURPOSE_SUMMARY`)
- Expected decision (`EXPECTED_DECISION`)
- All 4 ontology dimension labels (intent, instruction, retrieval, payload)
- Threat class (BENIGN/HOSTILE)

Benign test case payloads (109 cases) are included verbatim, as they contain no adversarial content.

### Rationale

Adversarial payloads were designed to test retrieval-security bypass and could be adapted for operational attacks against RAG systems. The evaluation semantics (which dimensions were triggered, what decision was expected, what decision was produced) are fully preserved through the ontology labels and purpose summaries. Metric reproduction does not require the raw payloads.

## Architectural Boundaries

### 95 Residual Hostile PERMITs

The frozen v3.2 evaluation reports 95 hostile test cases that received PERMIT decisions. These are documented as residual gaps, not as system failures that were concealed. The decomposition:

- 42: TOOL_PARAMETER_MANIPULATION — no corresponding TA exists (approved scope for Fix 2, not implemented)
- 15: CROSS_DOMAIN_REDIRECT payload mismatch — TA-009 requires USER_ASSERTED_AUTHORITY payload
- 13: Payload class mismatch — intent + instruction match but payload doesn't corroborate
- 9: No corroboration — intent alone insufficient under tightened matching
- 7: INTENT_NONE hostile — adversarial dimension values but NONE intent
- 4: ROLE_IMPERSONATION with uncovered intent classes
- 3: HIDDEN_INSTRUCTION with uncovered intent classes
- 2: Other boundary cases

Of these, 79 are fixable without architectural compromise. 16 represent irreducible architectural boundaries (corroboration requirement + compiler ownership).

## Metadata

### Evaluation Environment

The evaluated system ran on Snowflake (specific account anonymized). All SQL is standard Snowflake SQL. No external dependencies, no ML models, no embeddings, no API calls. The mechanism is purely deterministic SQL.

### Corpus Scope

The 690-case corpus is synthetic, generated to cover the full ontology value space across 22 test families. It was not sampled from production attack logs. Production validation is identified as future work.

## Reproduction Boundaries

- **Level 3 execution** requires a Snowflake account. There is no local/SQLite alternative.
- **The `AEGIS_EVALUATE_RETRIEVAL_RISK` procedure** writes to `AEGIS_DECISION_LOG`. The table must exist before execution.
- **Benchmark automation** (`05_comparative_benchmark.sql`) produces results that should match `data/comparative_benchmark.csv` exactly, confirming Level 3 execution reproduction.
