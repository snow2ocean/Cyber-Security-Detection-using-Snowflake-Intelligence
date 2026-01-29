"""
Copyright 2025 Snowflake Inc. 
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


Snowflake Python Stored Procedure to Load CTF Data from GitHub
This script fetches CSV files from GitHub and loads them into Snowflake tables
"""

import requests
import csv
from io import StringIO
from snowflake.snowpark import Session

def load_ctf_data(session: Session) -> str:
    """
    Loads network_logs and query_logs from GitHub raw URLs into Snowflake tables
    """
    
    # GitHub raw URLs for the CSV files
    network_logs_url = "https://github.com/snow2ocean/Cyber-Security-Detection-using-Snowflake-Intelligence/blob/main/data/network_logs.csv"
    query_logs_url = "https://github.com/snow2ocean/Cyber-Security-Detection-using-Snowflake-Intelligence/blob/main/data/query_logs.csv"
    
    results = []
    
    try:
        # Load Network Logs
        results.append("Fetching network_logs.csv from GitHub...")
        response = requests.get(network_logs_url)
        response.raise_for_status()
        
        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)
        
        network_logs = []
        for row in reader:
            network_logs.append((
                row['log_id'],
                row['timestamp'],
                row['source_ip'],
                row['destination_ip'],
                int(row['port']),
                row['protocol'],
                int(row['bytes_transferred']),
                row['user_id'],
                row['status']
            ))
        
        results.append(f"Fetched {len(network_logs)} network log records")
        
        # Insert network logs in batches
        session.sql("TRUNCATE TABLE NETWORK_LOGS").collect()
        
        batch_size = 1000
        for i in range(0, len(network_logs), batch_size):
            batch = network_logs[i:i+batch_size]
            for record in batch:
                session.sql("""
                    INSERT INTO NETWORK_LOGS 
                    (LOG_ID, TIMESTAMP, SOURCE_IP, DESTINATION_IP, PORT, PROTOCOL, BYTES_TRANSFERRED, USER_ID, STATUS)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, params=record).collect()
        
        results.append(f"Loaded {len(network_logs)} records into NETWORK_LOGS")
        
    except Exception as e:
        results.append(f"Error loading network logs: {str(e)}")
        return "\n".join(results)
    
    try:
        # Load Query Logs
        results.append("Fetching query_logs.csv from GitHub...")
        response = requests.get(query_logs_url)
        response.raise_for_status()
        
        csv_data = StringIO(response.text)
        reader = csv.DictReader(csv_data)
        
        query_logs = []
        for row in reader:
            query_logs.append((
                row['query_id'],
                row['timestamp'],
                row['user_id'],
                row['username'],
                row['warehouse'],
                row['query'],
                float(row['duration_secs']),
                int(row['bytes_scanned']),
                row['status'],
                row.get('error_message', '')
            ))
        
        results.append(f"Fetched {len(query_logs)} query log records")
        
        # Insert query logs in batches
        session.sql("TRUNCATE TABLE QUERY_LOGS").collect()
        
        batch_size = 1000
        for i in range(0, len(query_logs), batch_size):
            batch = query_logs[i:i+batch_size]
            for record in batch:
                session.sql("""
                    INSERT INTO QUERY_LOGS 
                    (QUERY_ID, TIMESTAMP, USER_ID, USERNAME, WAREHOUSE, QUERY, DURATION_SECS, BYTES_SCANNED, STATUS, ERROR_MESSAGE)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, params=record).collect()
        
        results.append(f"Loaded {len(query_logs)} records into QUERY_LOGS")
        
    except Exception as e:
        results.append(f"Error loading query logs: {str(e)}")
    
    results.append("Data load complete!")
    return "\n".join(results)

