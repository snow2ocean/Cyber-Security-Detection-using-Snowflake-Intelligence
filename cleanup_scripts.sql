-- ========================================
-- Parameters (must match the setup script)
-- ========================================
SET v_db            = 'SI_CYBERSECURITY_DB';
SET v_schema        = 'PUBLIC';
SET v_wh            = 'SI_CYBERSECURITY_WH';
SET v_role          = 'SI_CYBERSECURITY_ROLE';
SET v_nr            = 'SI_CYBERSECURITY_GITHUB_NR';
SET v_eai           = 'SI_CYBERSECURITY_GITHUB_EAI';
SET v_secret_name   = 'SI_GITHUB_PAT';          -- optional
SET v_sem_view_name = 'SI_CYBERSECURITY';       -- created via SYSTEM$CREATE_SEMANTIC_VIEW_FROM_YAML
SET v_user          = (SELECT CURRENT_USER());

-- Choose an admin role for cleanup; ACCOUNTADMIN can drop integrations & change ownership.
USE ROLE IDENTIFIER($v_role);

-- Set working context (if DB/SCHEMA still exist)
-- These USE statements are resilient; if DB/SCHEMA are gone, subsequent DDL will still work where fully qualified names are used.
USE DATABASE IDENTIFIER($v_db);
USE SCHEMA   IDENTIFIER($v_schema);

-- ========================================
-- STEP 1: Drop application objects
-- ========================================

-- 1a. Stored Procedure
DROP PROCEDURE IF EXISTS load_si_cybersecurity_data_from_github();

-- 1b. Semantic View (created via the system SP; it is a normal schema object named $v_sem_view_name)
-- Requires CREATE SEMANTIC VIEW or OWNERSHIP on the semantic view / schema. [3](https://docs.snowflake.com/en/user-guide/network-rules)
DROP SEMANTIC VIEW IF EXISTS IDENTIFIER($v_sem_view_name);

-- 1c. Tables
DROP TABLE IF EXISTS NETWORK_LOGS;
DROP TABLE IF EXISTS QUERY_LOGS;
DROP TABLE IF EXISTS SYSTEM_LOGS;

-- ========================================
-- STEP 2: Drop integrations, network rule, and secret
-- ========================================

-- 2a. External Access Integration (account-level object)
-- Allows outbound HTTP from UDF/SP; we drop it now. [2](https://docs.dataops.live/docs/sole/reference-guide/objects/external-access-integration/)
DROP INTEGRATION IF EXISTS IDENTIFIER($v_eai);

-- 2b. Network Rule (schema-level object used by external access integration)
-- The rule groups allowed egress domains; drop it after the integration. [1](https://stackoverflow.com/questions/73146121/how-to-grant-create-integration-to-role-sysadmin)
DROP NETWORK RULE IF EXISTS IDENTIFIER($v_nr);

-- 2c. Secret (optional)
-- If you created a PASSWORD/GNERIC_STRING secret for GitHub PAT, drop it.
DROP SECRET IF EXISTS IDENTIFIER($v_secret_name);



-- ========================================
-- STEP 3: Drop warehouse, schema, database (in order)
-- ========================================



-- Schema next (if you prefer, you can drop cascade at DB level)
DROP SCHEMA IF EXISTS IDENTIFIER($v_schema);

-- Database last
DROP DATABASE IF EXISTS IDENTIFIER($v_db);

-- Warehouse first (it is independent but safe to drop early)
DROP WAREHOUSE IF EXISTS IDENTIFIER($v_wh);
-- ========================================
-- STEP 4: Remove role grants & drop the role
-- ========================================
USE ROLE SECURITYADMIN;
-- Finally, drop the custom role
DROP ROLE IF EXISTS IDENTIFIER($v_role);
