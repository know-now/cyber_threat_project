import pandas as pd
from sqlalchemy import create_engine

#Block Extract(E): creation of raw test data about threats

raw data = {
    "timestamp": [
        "2026-09-14 10:00:00",
        "2026-09-14 10:05:00",
        "2026-09-14 10:10:00",
        "2026-09-14 10:15:00"    
    ],
    "source_ip": [
        "192.168.1.15",
        "10.0.0.42",
        "172.16.0.8",
        "192.168.1.100"    
    ],
    "attack_type": [
        "DDoS",
        "SQL Injection",
        "Phishing",
        "Brute Force"    
    ],
    "attack_type": [
        "DDoS",
        "SQL Injection",
        "Phishing",
        "Brute Force"    
    ],
    "severity":[2, 3, 10, 14]
}

df = pd.DataFrame(raw_data)

# Block Transform (T):Convert data types
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Block Load (L): connection to PostgreSQL and data writing

DB_USER = os.getenv.("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = "localhost"
DB_PORT = "5432"
DB_NAME = os.getenv("POSTGRES_DB", "cyber_threat_db")

# Connection
connection_url = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

#SQLAlchemy
engine = create_engine(connection_url)

# Writing DataFrame in a data base (threat_logs)
df.to_sql("threat_logs", con = engine, if_exists = "replace", index = False)

print("Success! Data is added to PostgreSQL in a table 'threat_logs'.")