import os
import time
import pandas as pd 
from sqlalchemy import create_engine
from dotenv import load_dotenv

print("=== Tableau BI Analytics Engine Started ===")
load_dotenv(override=True)

DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB") or "cyber_threat_db"

# Connecting to a database inside Docker-network
engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@postgres_db:5432/{DB_NAME}")

while True: 
    try:
        #Downloading of raw data
        df = pd.read_sql("SELECT * FROM threat_logs WHERE source_ip = 'OSINT (Web RSS)'", con=engine)
        if df.empty:
            print("[*] Waiting for real OSINT data...")
            time.sleep(30)
            continue
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
        
        # Dynamic Risk Score
        df['dynamic_risk_score'] = df['severity'] * (df['confidence'] / 100.0)
        df['dynamic_risk_score'] = df['dynamic_risk_score'].round(2)
        
        #Model Confidence Drift
        df['confidence_drift_ma'] = df['confidence'].rolling(window=10, min_periods = 1).mean().round(1)
        
        # Threat_velocity
        df.set_index('timestamp', inplace=True)
        df['threat_velocity_24h'] = df.assign(count=1)['count'].rolling('24h', min_periods=1).sum()
        df.reset_index(inplace=True)
        
        #Downloading to a Data Mart
        df.to_sql("tableau_mart", con=engine, if_exists="replace", index=False)
        print(f"[+] Successfully transformed {len(df)} records into 'tableau_mart' for Executive Dashboard")
    except Exception as e:
        print(f"[-] BI Engine Error: {e}")
        
    time.sleep(300)
    