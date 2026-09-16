-- AEGIS v3.2 SaTML 2027 — Anonymous Artifact
-- 04_core_procedures.sql
-- Frozen v3.2 pipeline: MAP > MATCH > SCORE > AUTHORIZE > EVALUATE
-- Recovered via GET_DDL() from the authoritative evaluated system.
-- Namespace anonymized: ARTIFACT_DB.AEGIS_REPRO

USE SCHEMA ARTIFACT_DB.AEGIS_REPRO;

-- Procedure 1: MAP — Constructs retrieval risk JSON from parse snapshot
CREATE OR REPLACE PROCEDURE AEGIS_MAP_RETRIEVAL_RISK_JSON(
    P_REQUEST_ID VARCHAR, P_PARSE_SNAPSHOT VARIANT,
    P_POLICY_RESOLUTION_RESULT VARIANT, P_RESTRICTION_ENVELOPE VARIANT)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS '
DECLARE v_result VARIANT;
BEGIN
    SELECT OBJECT_CONSTRUCT(
        ''request_id'', :P_REQUEST_ID,
        ''retrieval_intent_risk'',
            IFF(:P_PARSE_SNAPSHOT:action_class::STRING IN (''EXECUTE'',''TRANSFER'',''APPROVE''), ''HIGH'', ''LOW''),
        ''retrieval_target_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:target_class::STRING IN (''CUSTOMER_PII'',''CREDENTIALS'',''SECRETS'') THEN ''HIGH''
                 WHEN :P_PARSE_SNAPSHOT:target_class::STRING = ''UNKNOWN'' THEN ''MEDIUM'' ELSE ''LOW'' END,
        ''domain_boundary_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:data_domain::STRING IN (''CUSTOMER_RECORDS'',''ALL_INTERNAL_RECORDS'') THEN ''HIGH'' ELSE ''LOW'' END,
        ''scope_expansion_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:scope_class::STRING IN (''UNRESTRICTED'',''GLOBAL'',''CROSS_DOMAIN'') THEN ''HIGH'' ELSE ''LOW'' END,
        ''sensitive_retrieval_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:sensitivity_class::STRING IN (''RESTRICTED'',''CONFIDENTIAL'',''PII'',''SECRET'') THEN ''HIGH'' ELSE ''LOW'' END,
        ''operational_consequence_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:consequence_class::STRING IN (''HIGH_OPERATIONAL'',''FINANCIAL_ACTION'') THEN ''HIGH'' ELSE ''LOW'' END,
        ''policy_alignment_risk'',
            CASE WHEN COALESCE(:P_POLICY_RESOLUTION_RESULT:policy_changed::STRING,''FALSE'') = ''TRUE'' THEN ''MEDIUM'' ELSE ''LOW'' END,
        ''ambiguity_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:ambiguity_class::STRING = ''HIGH'' THEN ''HIGH'' ELSE ''LOW'' END,
        ''confidence_risk'',
            CASE WHEN COALESCE(:P_PARSE_SNAPSHOT:intent_confidence::NUMBER(10,4),0) < 0.60 THEN ''HIGH''
                 WHEN COALESCE(:P_PARSE_SNAPSHOT:intent_confidence::NUMBER(10,4),0) < 0.80 THEN ''MEDIUM'' ELSE ''LOW'' END,
        ''adversarial_intent_risk'',
            IFF(:P_PARSE_SNAPSHOT:adversarial_intent_class::STRING = ''NONE'',''LOW'',''HIGH''),
        ''instruction_manipulation_risk'',
            IFF(:P_PARSE_SNAPSHOT:instruction_manipulation_class::STRING = ''NONE'',''LOW'',''HIGH''),
        ''retrieval_manipulation_risk'',
            IFF(:P_PARSE_SNAPSHOT:retrieval_manipulation_class::STRING = ''NONE'',''LOW'',''HIGH''),
        ''payload_trust_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:payload_trust_class::STRING IN (''HOSTILE_INSTRUCTION'',''OBFUSCATED'',''UNKNOWN'') THEN ''HIGH''
                 WHEN :P_PARSE_SNAPSHOT:payload_trust_class::STRING = ''USER_ASSERTED_AUTHORITY'' THEN ''MEDIUM'' ELSE ''LOW'' END,
        ''semantic_normalization_risk'',
            CASE WHEN :P_PARSE_SNAPSHOT:adversarial_intent_class::STRING != ''NONE''
                      AND :P_PARSE_SNAPSHOT:scope_class::STRING = ''POLICY_LEVEL'' THEN ''MEDIUM'' ELSE ''LOW'' END,
        ''policy_overlay_risk'',
            IFF(COALESCE(:P_POLICY_RESOLUTION_RESULT:overlay_attempted::STRING,''FALSE'') = ''TRUE'',''MEDIUM'',''LOW''),
        ''allowed_retrieval_modes'', :P_RESTRICTION_ENVELOPE:allowed_modes,
        ''forbidden_retrieval_modes'', :P_RESTRICTION_ENVELOPE:forbidden_modes
    ) INTO :v_result;
    RETURN v_result;
END;
';

-- Procedure 2: MATCH — Matches parse snapshot against governed threat attributes
-- Matching logic: INTENT_AND_CORROBORATE_OR_SCOPED_INDEPENDENT
CREATE OR REPLACE PROCEDURE AEGIS_MATCH_THREAT_ATTRIBUTES(
    P_PARSE_SNAPSHOT VARIANT, P_RETRIEVAL_RISK_JSON VARIANT)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS '
DECLARE v_matches VARIANT;
BEGIN
    SELECT COALESCE(
        ARRAY_AGG(
            OBJECT_CONSTRUCT(
                ''threat_attribute_id'', threat_attribute_id,
                ''threat_category'', threat_category,
                ''threat_name'', threat_name,
                ''severity_weight'', severity_weight,
                ''expected_decision'', expected_decision,
                ''retrieval_risk_type'', retrieval_risk_type
            )
        ),
        ARRAY_CONSTRUCT()
    )
    INTO :v_matches
    FROM ARTIFACT_DB.AEGIS_REPRO.AEGIS_THREAT_ATTRIBUTE
    WHERE is_active = TRUE
      AND (
          (
              COALESCE(adversarial_intent_class,'''') = COALESCE(:P_PARSE_SNAPSHOT:adversarial_intent_class::STRING,'''')
              AND (
                  COALESCE(instruction_manipulation_class,'''') = COALESCE(:P_PARSE_SNAPSHOT:instruction_manipulation_class::STRING,'''')
                  OR COALESCE(retrieval_manipulation_class,'''') = COALESCE(:P_PARSE_SNAPSHOT:retrieval_manipulation_class::STRING,'''')
                  OR COALESCE(payload_trust_class,'''') = COALESCE(:P_PARSE_SNAPSHOT:payload_trust_class::STRING,'''')
              )
          )
          OR (
              :P_RETRIEVAL_RISK_JSON:scope_expansion_risk::STRING = ''HIGH''
              AND retrieval_risk_type IN (''SCOPE_EXPANSION'', ''RETRIEVAL_PATH'')
          )
          OR (
              :P_RETRIEVAL_RISK_JSON:sensitive_retrieval_risk::STRING = ''HIGH''
              AND retrieval_risk_type = ''SENSITIVE_RETRIEVAL''
          )
      )
      AND NOT (
          :P_PARSE_SNAPSHOT:payload_trust_class::STRING = ''BENIGN_SECURITY_DISCUSSION''
          AND threat_category != ''UNKNOWN_RISK''
      );
    RETURN v_matches;
END;
';

-- Procedure 3: SCORE — Computes retrieval risk score from matched TAs and field risks
CREATE OR REPLACE PROCEDURE AEGIS_SCORE_RETRIEVAL_RISK(
    P_RETRIEVAL_RISK_JSON VARIANT, P_MATCHED_THREAT_ATTRIBUTES VARIANT)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS '
DECLARE
    v_threat_score NUMBER(10,4);
    v_field_score NUMBER(10,4);
    v_total_score NUMBER(10,4);
    v_risk_class STRING;
    v_result VARIANT;
BEGIN
    SELECT COALESCE(MAX(value:severity_weight::NUMBER(10,4)),0)
    INTO :v_threat_score
    FROM TABLE(FLATTEN(INPUT => :P_MATCHED_THREAT_ATTRIBUTES));

    v_field_score :=
        IFF(:P_RETRIEVAL_RISK_JSON:retrieval_target_risk::STRING=''HIGH'',0.10,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:scope_expansion_risk::STRING=''HIGH'',0.15,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:sensitive_retrieval_risk::STRING=''HIGH'',0.10,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:operational_consequence_risk::STRING=''HIGH'',0.10,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:ambiguity_risk::STRING=''HIGH'',0.10,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:confidence_risk::STRING=''HIGH'',0.10,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:adversarial_intent_risk::STRING=''HIGH'',0.20,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:instruction_manipulation_risk::STRING=''HIGH'',0.15,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:retrieval_manipulation_risk::STRING=''HIGH'',0.15,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:payload_trust_risk::STRING=''HIGH'',0.15,0) +
        IFF(:P_RETRIEVAL_RISK_JSON:semantic_normalization_risk::STRING=''MEDIUM'',0.05,0);

    v_total_score := LEAST(1.0000, GREATEST(:v_threat_score, :v_field_score));

    v_risk_class := CASE
        WHEN :v_total_score >= 0.85 THEN ''HIGH''
        WHEN :v_total_score >= 0.50 THEN ''MEDIUM''
        ELSE ''LOW''
    END;

    SELECT OBJECT_CONSTRUCT(
        ''retrieval_risk_score'', :v_total_score,
        ''risk_class'', :v_risk_class,
        ''threat_score'', :v_threat_score,
        ''field_score'', :v_field_score
    ) INTO :v_result;
    RETURN v_result;
END;
';

-- Procedure 4: AUTHORIZE — Makes BLOCK/RESTRICT/PERMIT decision
CREATE OR REPLACE PROCEDURE AEGIS_AUTHORIZE_RETRIEVAL_PLAN(
    P_MATCHED_THREAT_ATTRIBUTES VARIANT, P_SCORE_JSON VARIANT)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS '
DECLARE
    v_score NUMBER(10,4);
    v_has_block NUMBER;
    v_has_restrict NUMBER;
    v_decision STRING;
    v_reason STRING;
    v_result VARIANT;
BEGIN
    v_score := :P_SCORE_JSON:retrieval_risk_score::NUMBER(10,4);

    SELECT COUNT(*) INTO :v_has_block
    FROM TABLE(FLATTEN(INPUT => :P_MATCHED_THREAT_ATTRIBUTES))
    WHERE value:expected_decision::STRING = ''BLOCK'';

    SELECT COUNT(*) INTO :v_has_restrict
    FROM TABLE(FLATTEN(INPUT => :P_MATCHED_THREAT_ATTRIBUTES))
    WHERE value:expected_decision::STRING = ''RESTRICT'';

    v_decision := CASE
        WHEN :v_has_block > 0 THEN ''BLOCK''
        WHEN :v_score >= 0.85 THEN ''BLOCK''
        WHEN :v_has_restrict > 0 THEN ''RESTRICT''
        WHEN :v_score >= 0.50 THEN ''RESTRICT''
        ELSE ''PERMIT''
    END;

    v_reason := CASE
        WHEN :v_decision = ''BLOCK'' THEN ''Blocked: high retrieval-risk score or blocking threat attribute matched.''
        WHEN :v_decision = ''RESTRICT'' THEN ''Restricted: elevated or uncertain retrieval-execution risk.''
        ELSE ''Permitted: semantic and retrieval-risk indicators within governed bounds.''
    END;

    SELECT OBJECT_CONSTRUCT(
        ''authorization_decision'', :v_decision,
        ''decision_reason'', :v_reason
    ) INTO :v_result;
    RETURN v_result;
END;
';

-- Procedure 5: EVALUATE — Orchestrates full pipeline: MAP > MATCH > SCORE > AUTHORIZE
CREATE OR REPLACE PROCEDURE AEGIS_EVALUATE_RETRIEVAL_RISK(
    P_REQUEST_ID VARCHAR, P_TEST_ID VARCHAR, P_PARSE_SNAPSHOT VARIANT,
    P_POLICY_RESOLUTION_RESULT VARIANT, P_RESTRICTION_ENVELOPE VARIANT)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS OWNER AS '
DECLARE
    v_start TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP();
    v_end TIMESTAMP_NTZ;
    v_latency NUMBER(18,3);
    v_decision_id STRING;
    v_risk_json VARIANT;
    v_matches VARIANT;
    v_score_json VARIANT;
    v_auth_json VARIANT;
    v_result VARIANT;
BEGIN
    SELECT UUID_STRING() INTO :v_decision_id;

    CALL AEGIS_MAP_RETRIEVAL_RISK_JSON(:P_REQUEST_ID, :P_PARSE_SNAPSHOT, :P_POLICY_RESOLUTION_RESULT, :P_RESTRICTION_ENVELOPE);
    SELECT $1 INTO :v_risk_json FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

    CALL AEGIS_MATCH_THREAT_ATTRIBUTES(:P_PARSE_SNAPSHOT, :v_risk_json);
    SELECT $1 INTO :v_matches FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

    CALL AEGIS_SCORE_RETRIEVAL_RISK(:v_risk_json, :v_matches);
    SELECT $1 INTO :v_score_json FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

    CALL AEGIS_AUTHORIZE_RETRIEVAL_PLAN(:v_matches, :v_score_json);
    SELECT $1 INTO :v_auth_json FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));

    v_end := CURRENT_TIMESTAMP();
    v_latency := DATEDIFF(''millisecond'', :v_start, :v_end);

    INSERT INTO ARTIFACT_DB.AEGIS_REPRO.AEGIS_DECISION_LOG
    SELECT :v_decision_id, :P_REQUEST_ID, :P_TEST_ID,
        PARSE_JSON(:P_PARSE_SNAPSHOT), PARSE_JSON(:P_POLICY_RESOLUTION_RESULT),
        PARSE_JSON(:P_RESTRICTION_ENVELOPE), PARSE_JSON(:v_risk_json),
        PARSE_JSON(:v_matches),
        :v_score_json:retrieval_risk_score::NUMBER(10,4),
        :v_score_json:risk_class::STRING,
        :v_auth_json:authorization_decision::STRING,
        :v_auth_json:decision_reason::STRING,
        NULL, NULL, :v_latency, CURRENT_TIMESTAMP();

    SELECT OBJECT_CONSTRUCT(
        ''aegis_decision_id'', :v_decision_id,
        ''request_id'', :P_REQUEST_ID,
        ''test_id'', :P_TEST_ID,
        ''retrieval_risk_json'', :v_risk_json,
        ''matched_threat_attributes'', :v_matches,
        ''score'', :v_score_json,
        ''authorization'', :v_auth_json,
        ''latency_ms'', :v_latency
    ) INTO :v_result;
    RETURN v_result;
END;
';
