# Anonymization Audit — AEGIS v3.2 SaTML 2027

## Anonymization Policy

All identifying implementation namespace references were replaced with neutral placeholders. No original identifying values were preserved in comments, audit logs, or artifact documentation.

## Substitution Table

| Original Pattern | Replacement | Scope |
|-----------------|-------------|-------|
| `DEV_TEST.GARGSV1_AEGISV3` | `ARTIFACT_DB.AEGIS_REPRO` | All SQL files, documentation |
| `DEV_TEST` (database) | `ARTIFACT_DB` | All SQL files |
| `GARGSV1_AEGISV3` (schema) | `AEGIS_REPRO` | All SQL files |
| `GARGSV1` (system identifier) | Removed | All files |
| `DEV_WH` (warehouse) | `EVAL_WH` | All SQL files, documentation |
| `COMPUTE_WH` (warehouse) | `EVAL_WH` | All SQL files, documentation |
| `DATA_SCIENTIST` (role) | `EVAL_ROLE` | All documentation |
| `PUBLIC` (role) | `EVAL_ROLE` | All documentation |
| Account identifier | Removed | All files |
| Username | Removed | All files |
| Workspace paths | Removed | All files |
| `snow://workspace/*` URIs | Removed | All files |

## Search Patterns Applied

The following regex patterns were applied across all artifact files to ensure completeness:

- `DEV_TEST` → `ARTIFACT_DB`
- `GARGSV1_AEGISV3` → `AEGIS_REPRO`
- `GARGSV1` → (removed)
- `DEV_WH|COMPUTE_WH` → `EVAL_WH`
- `DATA_SCIENTIST|PUBLIC` (as role references) → `EVAL_ROLE`
- `vva29578` → (removed)
- `JEFFREYESPOSITO` → (removed)
- `USER\$\.PUBLIC\.GARGS` → (removed)
- `snow://workspace/` → (removed)

## Verification

After substitution, all artifact files were scanned for residual identifying patterns. No identifying values remain.

## Scope

Anonymization was applied to:
- All 6 SQL files in `sql/`
- All 3 CSV files in `data/`
- All 7 documentation files in `docs/`

Anonymization does not affect evaluation semantics, metric values, procedure logic, ontology values, threat attribute definitions, or test case labels.
