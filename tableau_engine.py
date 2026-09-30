import os
import time
import pandas as pd 
from sqalchemy import create_engine
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
        if df.enpty:
            print("[*] Waiting for real OSINT data...")
            time.sleep(30)
            continue
        df['timestamp'] = pd.to_datetime(df['timestamp'])
            