import os
import sys
import time
from dotenv import load_dotenv
load_dotenv(override = True)
import pandas as pd
from sqlalchemy import create_engine
import chromadb



#Block Extract(E): creation of raw test data about threats

raw_data = {
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
    "severity":[2, 3, 10, 14]
}

df = pd.DataFrame(raw_data)

# Block Transform (T):Convert data types
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Block Load (L): connection to PostgreSQL and data writing

DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = "postgres_db"
DB_PORT = "5432"
DB_NAME = os.getenv("POSTGRES_DB") or "cyber_threat_db"

# Guard Clause
if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise ValueError("CRITICAL: Змінні середовища не завантажені! Перевірте наявність файлу .env та його вміст.")


# Connection postgreSQL
connection_url = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

#SQLAlchemy
engine = create_engine(connection_url)

#Connecting to Chroma in Docker
chroma_client = chromadb.HttpClient(host='chroma_app', port=8000)
collection = chroma_client.get_or_create_collection(name="threat_logs_vectors")

# Writing DataFrame in a data base (threat_logs)
df.to_sql("threat_logs", con = engine, if_exists = "replace", index = False)

#Create mock OSINT-data
collection.add(
    documents = ["A zero-day exploit compromised the cloud infrastructure of a major logistics firm.", "State-sponsored hackers deployed ransomware across municipal power grids.", "A sophisticated spear-phishing attack breached the internal corporate database.", "Botnets executed a massive DDoS campaign, disrupting financial trading platforms." ],
    ids = ["doc1", "doc2", "doc3", "doc4"]
)
results = collection.query(
    query_texts = ["How do hackers steal bank credentials?"], 
    n_results = 1
)
print("Result of the search in Chroma DB:", results)

print("Success! Data is added to PostgreSQL in a table 'threat_logs'.")