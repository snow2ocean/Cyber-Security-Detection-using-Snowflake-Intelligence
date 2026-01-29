-- ========================================
-- Parameterize objects for reusability
-- ========================================
SET v_db            = 'SI_CYBERSECURITY_DB';
SET v_schema        = 'PUBLIC';
SET v_wh            = 'SI_CYBERSECURITY_WH';
SET v_role          = 'SI_CYBERSECURITY_ROLE';
SET v_nr            = 'SI_CYBERSECURITY_GITHUB_NR';
SET v_eai           = 'SI_CYBERSECURITY_GITHUB_EAI';
SET v_secret_name   = 'SI_GITHUB_PAT';                  -- optional (for private repos / rate limits)
SET v_user          = (SELECT CURRENT_USER());

-- Hosts for GitHub access (raw content + API)
-- SET v_hosts         = ARRAY_CONSTRUCT('raw.githubusercontent.com', 'api.github.com');


-- ========================================
-- STEP 0: Bootstrap (DB/WH)
-- ========================================
USE ROLE SYSADMIN;

CREATE DATABASE IF NOT EXISTS IDENTIFIER($v_db)
  COMMENT = 'CTF Intelligence Database';

CREATE WAREHOUSE IF NOT EXISTS IDENTIFIER($v_wh)
  WAREHOUSE_SIZE = 'X-SMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE
  COMMENT = 'Warehouse for CTF data operations';

-- ========================================
-- STEP 1: Role & Privileges
-- ========================================
USE ROLE SECURITYADMIN;

CREATE ROLE IF NOT EXISTS IDENTIFIER($v_role);

-- grant the runtime role to current user (for immediate use)
GRANT ROLE IDENTIFIER($v_role) TO USER IDENTIFIER($v_user);

-- give the role ownership of DB & PUBLIC schema (single owner)
GRANT OWNERSHIP ON DATABASE IDENTIFIER($v_db)           TO ROLE IDENTIFIER($v_role);
USE DATABASE IDENTIFIER($v_db);
GRANT OWNERSHIP ON SCHEMA   IDENTIFIER($v_schema) TO ROLE IDENTIFIER($v_role);

-- warehouse usage
GRANT USAGE ON WAREHOUSE IDENTIFIER($v_wh)              TO ROLE IDENTIFIER($v_role);

-- account-level privilege needed to create integrations
USE ROLE ACCOUNTADMIN;
GRANT CREATE INTEGRATION ON ACCOUNT TO ROLE IDENTIFIER($v_role);  -- required for creating EXTERNAL ACCESS INTEGRATION [1](https://docs.snowflake.com/en/sql-reference/sql/create-external-access-integration)

-- allow AccountAdmin to switch to the runtime role if needed
GRANT ROLE IDENTIFIER($v_role) TO ROLE ACCOUNTADMIN;

-- working context
USE ROLE IDENTIFIER($v_role);
USE DATABASE IDENTIFIER($v_db);
USE SCHEMA   IDENTIFIER($v_schema);
USE WAREHOUSE IDENTIFIER($v_wh);

-- ========================================
-- STEP 2: Network Rule for External Access
-- ========================================
-- EGRESS + HOST_PORT is the correct pairing for outbound access to domains. [3](https://docs.snowflake.com/en/sql-reference/sql/create-network-rule)
CREATE OR REPLACE NETWORK RULE IDENTIFIER($v_nr)
  MODE       = EGRESS
  TYPE       = HOST_PORT
  VALUE_LIST = ( 'raw.githubusercontent.com', 'api.github.com' );

-- ========================================
-- STEP 3: (Optional) Secret for GitHub PAT (private repos or higher rate limits)
-- ========================================
-- Uncomment and set your PAT if needed; then include it in the EAI below. Secrets are schema-level objects referenced by EAI. [1](https://docs.snowflake.com/en/sql-reference/sql/create-external-access-integration)[2](https://docs.snowflake.cn/en/developer-guide/external-network-access/creating-using-external-network-access)
-- CREATE OR REPLACE SECRET IDENTIFIER($v_db)||'.'||IDENTIFIER($v_schema)||'.'||IDENTIFIER($v_secret_name)
--   TYPE = PASSWORD
--   PASSWORD = '<your_personal_access_token>';

-- ========================================
-- STEP 4: External Access Integration (attach rule [+ secret])
-- ========================================
-- External access integrations aggregate allowed network rules (and optionally secrets) for UDF/Procedures. [1](https://docs.snowflake.com/en/sql-reference/sql/create-external-access-integration)
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION IDENTIFIER($v_eai)
  ALLOWED_NETWORK_RULES = ( $v_nr)
  -- ALLOWED_AUTHENTICATION_SECRETS = ( IDENTIFIER($v_db)||'.'||IDENTIFIER($v_schema)||'.'||IDENTIFIER($v_secret_name) )  -- uncomment if secret created
  ENABLED = TRUE;

-- ensure the runtime role can reference the integration at run time (good hygiene)
GRANT USAGE ON INTEGRATION IDENTIFIER($v_eai) TO ROLE IDENTIFIER($v_role);

-- ========================================
-- STEP 5: Tables
-- ========================================
CREATE OR REPLACE TABLE NETWORK_LOGS (
  LOG_ID            VARCHAR(100),
  TIMESTAMP         TIMESTAMP_NTZ,
  SOURCE_IP         VARCHAR(50),
  DESTINATION_IP    VARCHAR(50),
  PORT              INTEGER,
  PROTOCOL          VARCHAR(20),
  BYTES_TRANSFERRED INTEGER,
  USER_ID           VARCHAR(100),
  STATUS            VARCHAR(20)
);

CREATE OR REPLACE TABLE QUERY_LOGS (
  QUERY_ID       VARCHAR(100),
  TIMESTAMP      TIMESTAMP_NTZ,
  USER_ID        VARCHAR(100),
  USERNAME       VARCHAR(100),
  WAREHOUSE      VARCHAR(50),
  QUERY          VARCHAR(5000),
  DURATION_SECS  FLOAT,
  BYTES_SCANNED  INTEGER,
  STATUS         VARCHAR(20),
  ERROR_MESSAGE  VARCHAR(5000)
);

CREATE OR REPLACE TABLE SYSTEM_LOGS (
  LOG_ID      VARCHAR(100),
  TIMESTAMP   TIMESTAMP_NTZ,
  USER_ID     VARCHAR(100),
  USERNAME    VARCHAR(100),
  ACTION      VARCHAR(100),
  DETAILS     VARCHAR(5000),
  STATUS      VARCHAR(20)
);

-- ========================================
-- STEP 6: Python Stored Procedure (pandas + requests)
-- ========================================
-- Uses Snowpark Session.write_pandas to bulk load DataFrames (overwrite table). [4](https://docs.snowflake.com/en/developer-guide/snowpark/reference/python/latest/snowpark/api/snowflake.snowpark.Session.write_pandas)[5](https://docs.snowflake.cn/en/developer-guide/snowpark/reference/python/latest/snowpark/api/snowflake.snowpark.Session.write_pandas)
CREATE OR REPLACE PROCEDURE load_si_cybersecurity_data_from_github()
RETURNS STRING
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'pandas')
HANDLER = 'load_data'
EXTERNAL_ACCESS_INTEGRATIONS = ($v_eai)
EXECUTE AS CALLER
AS
$$
import pandas as pd

def load_data(session):
    """
    Loads network_logs, query_logs, and system_logs from GitHub raw URLs into Snowflake tables using pandas bulk loading
    """
    
    # GitHub raw URLs for the CSV files
    network_logs_url = "https://raw.githubusercontent.com/snow2ocean/Cyber-Security-Detection-using-Snowflake-Intelligence/main/data/network_logs.csv"
    query_logs_url = "https://raw.githubusercontent.com/snow2ocean/Cyber-Security-Detection-using-Snowflake-Intelligence/main/data/query_logs.csv"
    system_logs_url = "https://raw.githubusercontent.com/snow2ocean/Cyber-Security-Detection-using-Snowflake-Intelligence/main/data/system_logs.csv"
    # network_logs.csv
    results = []
    
    try:
        # Load Network Logs using pandas bulk loading
        results.append("Fetching and loading network_logs.csv from GitHub...")
        
        # Read CSV directly from URL into DataFrame (keep timestamp as string)
        df_network = pd.read_csv(network_logs_url, dtype={'timestamp': 'str'})
        
        # Ensure column names match table schema (uppercase)
        df_network.columns = df_network.columns.str.upper()
        
        # Bulk load entire DataFrame into Snowflake
        # Snowflake will handle the timestamp conversion from string
        session.write_pandas(
            df=df_network,
            table_name='NETWORK_LOGS',
            auto_create_table=False,
            overwrite=True,
            quote_identifiers=False
        )
        
        results.append(f"Successfully loaded {len(df_network)} records into NETWORK_LOGS")
        
    except Exception as e:
        results.append(f"Error loading network logs: {str(e)}")
        return "\n".join(results)
    
    try:
        # Load Query Logs using pandas bulk loading
        results.append("Fetching and loading query_logs.csv from GitHub...")
        
        # Read CSV directly from URL into DataFrame (keep timestamp as string)
        df_query = pd.read_csv(query_logs_url, dtype={'timestamp': 'str'})
        
        # Ensure column names match table schema (uppercase)
        df_query.columns = df_query.columns.str.upper()
        
        # Bulk load entire DataFrame into Snowflake
        # Snowflake will handle the timestamp conversion from string
        session.write_pandas(
            df=df_query,
            table_name='QUERY_LOGS',
            auto_create_table=False,
            overwrite=True,
            quote_identifiers=False
        )
        
        results.append(f"Successfully loaded {len(df_query)} records into QUERY_LOGS")
        
    except Exception as e:
        results.append(f"Error loading query logs: {str(e)}")
    
    try:
        # Load System Logs using pandas bulk loading
        results.append("Fetching and loading system_logs.csv from GitHub...")
        
        # Read CSV directly from URL into DataFrame (keep timestamp as string)
        df_system = pd.read_csv(system_logs_url, dtype={'timestamp': 'str'})
        
        # Ensure column names match table schema (uppercase)
        df_system.columns = df_system.columns.str.upper()
        
        # Bulk load entire DataFrame into Snowflake
        # Snowflake will handle the timestamp conversion from string
        session.write_pandas(
            df=df_system,
            table_name='SYSTEM_LOGS',
            auto_create_table=False,
            overwrite=True,
            quote_identifiers=False
        )
        
        results.append(f"Successfully loaded {len(df_system)} records into SYSTEM_LOGS")
        
    except Exception as e:
        results.append(f"Error loading system logs: {str(e)}")
    
    results.append("Data load complete!")
    return "\n".join(results)
$$;

-- execute the loader
CALL load_si_cybersecurity_data_from_github();

-- ========================================
-- STEP 7: Semantic View (YAML)
-- ========================================
-- Grant semantic view creation privilege (minimum) and SELECT on sources. [6](https://docs.snowflake.com/en/sql-reference/stored-procedures/system_create_semantic_view_from_yaml)


-- Create semantic view from YAML (use dollar-quoted string for YAML) [6](https://docs.snowflake.com/en/sql-reference/stored-procedures/system_create_semantic_view_from_yaml)
CALL SYSTEM$CREATE_SEMANTIC_VIEW_FROM_YAML(
  'SI_CYBERSECURITY_DB.PUBLIC',
  $$
name: SI_CYBERSECURITY
tables:
  - name: NETWORK_LOGS
    base_table:
      database: SI_CYBERSECURITY_DB
      schema: PUBLIC
      table: NETWORK_LOGS
    dimensions:
      - name: DESTINATION_IP
        description: The IP address of the destination server or device that the network request was sent to.
        expr: DESTINATION_IP
        data_type: VARCHAR(15)
        sample_values:
          - 205.65.73.9
          - 219.49.219.76
          - 186.127.23.240
      - name: LOG_ID
        description: Unique identifier for each network log entry.
        expr: LOG_ID
        data_type: VARCHAR(36)
        sample_values:
          - 726312e9-32d6-4b22-9c5e-ca4418727a53
          - 04ee05f8-3333-4d3a-b7c2-a5c0f038c364
          - b78fb2e6-836b-4549-a8b9-65932d733a36
      - name: PROTOCOL
        description: The protocol used for network communication, such as HTTP for web traffic, HTTPS for secure web traffic, or TCP for general network communication.
        expr: PROTOCOL
        data_type: VARCHAR(10)
        sample_values:
          - HTTP
          - HTTPS
          - TCP
      - name: SOURCE_IP
        description: The IP address of the device or system that initiated the network activity.
        expr: SOURCE_IP
        data_type: VARCHAR(15)
        sample_values:
          - 10.0.0.1
      - name: STATUS
        description: The status of the network log entry, indicating whether the network activity was successful or not.
        expr: STATUS
        data_type: VARCHAR(50)
        sample_values:
          - SUCCESS
      - name: USER_ID
        description: Unique identifier for the user who performed the network activity.
        expr: USER_ID
        data_type: VARCHAR(36)
        sample_values:
          - f0c2cfac-cf3b-4053-9e79-a6a4c6bbd187
          - cea2e75f-1ee1-4b1d-90f5-242f82a02bed
          - 57eba2d7-a4fe-48aa-aa7b-ad0e6f1296b7
    time_dimensions:
      - name: TIMESTAMP
        description: The date and time when a network event occurred, in ISO 8601 format with millisecond precision and UTC timezone offset.
        expr: TIMESTAMP
        data_type: TIMESTAMP_NTZ(9)
        sample_values:
          - 2025-09-03T01:20:00.000+0000
          - 2025-09-03T15:38:00.000+0000
          - 2025-09-04T05:48:00.000+0000
    facts:
      - name: BYTES_TRANSFERRED
        description: The total number of bytes transferred over the network.
        expr: BYTES_TRANSFERRED
        data_type: NUMBER(38,0)
        access_modifier: public_access
        sample_values:
          - '92411'
          - '26958'
          - '84574'
      - name: PORT
        description: The port number used for network communication, indicating the specific process or service that the network activity is associated with.
        expr: PORT
        data_type: NUMBER(38,0)
        access_modifier: public_access
        sample_values:
          - '22'
          - '8080'
          - '80'
  - name: QUERY_LOGS
    base_table:
      database: SI_CYBERSECURITY_DB
      schema: PUBLIC
      table: QUERY_LOGS
    dimensions:
      - name: ERROR_MESSAGE
        description: The error message associated with a query log entry, providing details about the nature of the error that occurred during query execution.
        expr: ERROR_MESSAGE
        data_type: VARCHAR(500)
      - name: QUERY
        description: A log of SQL queries executed on the database, capturing the actual query text, typically used for auditing, performance monitoring, and debugging purposes.
        expr: QUERY
        data_type: VARCHAR(16777216)
        sample_values:
          - SELECT * FROM USER_ACTIVITY_LOGS WHERE created_at >= dateadd('day', -7, current_date())
          - SELECT COUNT(*) FROM CUSTOMER_DATA GROUP BY date_trunc('day', created_at)
          - SELECT * FROM SALES_TRANSACTIONS LIMIT 1000
      - name: QUERY_ID
        description: Unique identifier for each query executed, used for tracking and logging purposes.
        expr: QUERY_ID
        data_type: VARCHAR(36)
        sample_values:
          - e13f4f76-de57-47a7-a80b-6fffa923e0d6
          - f7425137-916a-4ebe-b842-8afc61daf004
          - 75876282-e7ec-46aa-9617-bd86b0b95543
      - name: STATUS
        description: The status of the query execution, indicating whether it was successful or not.
        expr: STATUS
        data_type: VARCHAR(50)
        sample_values:
          - SUCCESS
      - name: USER_ID
        description: Unique identifier for the user who executed the query.
        expr: USER_ID
        data_type: VARCHAR(36)
        sample_values:
          - f0c2cfac-cf3b-4053-9e79-a6a4c6bbd187
          - 3d8cc43f-0f00-40bd-b8b2-34ac61fc0360
          - 859c34dd-4540-49a3-b26d-f82b1455d905
      - name: USERNAME
        description: The username of the user who executed the query.
        expr: USERNAME
        data_type: VARCHAR(100)
        sample_values:
          - jose46
          - oatkinson
          - rwilliams
      - name: WAREHOUSE
        description: The warehouse where the query was executed, indicating the size and type of warehouse used for the query.
        expr: WAREHOUSE
        data_type: VARCHAR(100)
        sample_values:
          - DEV_WH_SMALL
          - DEV_WH_X-SMALL
          - ETL_WH_SMALL
    time_dimensions:
      - name: TIMESTAMP
        description: The date and time when a query was executed, in ISO 8601 format with millisecond precision and UTC timezone offset.
        expr: TIMESTAMP
        data_type: TIMESTAMP_NTZ(9)
        sample_values:
          - 2025-09-03T01:20:00.000+0000
          - 2025-09-03T15:38:00.000+0000
          - 2025-09-04T05:48:00.000+0000
    facts:
      - name: BYTES_SCANNED
        description: The total number of bytes scanned by the query from storage.
        expr: BYTES_SCANNED
        data_type: NUMBER(38,0)
        access_modifier: public_access
        sample_values:
          - '464603'
          - '546651'
          - '627575'
      - name: DURATION_SECS
        description: The time it takes to execute a query, measured in seconds.
        expr: DURATION_SECS
        data_type: FLOAT
        access_modifier: public_access
        sample_values:
          - '3.208440651'
          - '2.139619616'
          - '0.5347266118'
  - name: SYSTEM_LOGS
    base_table:
      database: SI_CYBERSECURITY_DB
      schema: PUBLIC
      table: SYSTEM_LOGS
    dimensions:
      - name: ACTION
        description: The ACTION column captures the type of system event that triggered the log entry, such as a user logging in or out, or the start of a query.
        expr: ACTION
        data_type: VARCHAR(100)
        sample_values:
          - LOGOUT
          - QUERY_START
          - LOGIN
      - name: DETAILS
        description: This column captures the specific actions or events that occur within the system, providing a detailed description of the type of activity that took place, such as starting a query, logging in, or logging out.
        expr: DETAILS
        data_type: VARCHAR(16777216)
        sample_values:
          - Regular query_start activity
          - Regular logout activity
          - Regular login activity
      - name: LOG_ID
        description: Unique identifier for each log entry in the system logs table.
        expr: LOG_ID
        data_type: VARCHAR(36)
        sample_values:
          - f109412b-d93b-4fe3-9070-8b39b3c9a016
          - e01befd5-185c-4f0d-bc83-1e569c3c8616
          - f6f92b63-d7b6-4aef-99f8-9555c9057895
      - name: STATUS
        description: Indicates the outcome of a system event or transaction, with "SUCCESS" denoting a completed or executed event without errors.
        expr: STATUS
        data_type: VARCHAR(50)
        sample_values:
          - SUCCESS
      - name: USER_ID
        description: Unique identifier for the user who performed the action that triggered the log entry.
        expr: USER_ID
        data_type: VARCHAR(36)
        sample_values:
          - da0f0f7a-8d2c-4ca9-b82e-cda33fba6610
          - 859c34dd-4540-49a3-b26d-f82b1455d905
          - 4663d48b-596a-4f39-b714-8d69ac9a7d2a
      - name: USERNAME
        description: The username of the system user who performed the action that triggered the log entry.
        expr: USERNAME
        data_type: VARCHAR(100)
        sample_values:
          - robert93
          - codyoconnor
          - lliu
    time_dimensions:
      - name: TIMESTAMP
        description: The date and time when a system event occurred, in ISO 8601 format with millisecond precision and UTC timezone offset.
        expr: TIMESTAMP
        data_type: TIMESTAMP_NTZ(9)
        sample_values:
          - 2025-09-03T01:20:00.000+0000
          - 2025-09-03T15:38:00.000+0000
          - 2025-09-04T05:48:00.000+0000
  $$
);
