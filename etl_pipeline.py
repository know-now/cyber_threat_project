import os
import sys
import time
from dotenv import load_dotenv
load_dotenv(override = True)
import pandas as pd
from sqlalchemy import create_engine
import chromadb



#Block Extract(E): creation of raw test data about threats
# reading knowledge base from the text file
with open("kb.txt", "r", encoding="utf-8") as f:
    historic_documents = [line.strip() for line in f.readlines() if line.strip()]

raw_data = {"timestamp": pd.date_range(start="2026-09-14 10:00:00", periods=19, freq="5min").astype(str).tolist(),
    "source_ip": [
        "192.168.1.15", "192.168.1.16", "192.168.1.17", "192.168.1.18",  # Phishing
        "10.0.0.42", "10.0.0.43", "10.0.0.44", "10.0.0.45",              # Ransomware
        "172.16.0.8", "172.16.0.9", "172.16.0.10", "172.16.0.11",        # DDoS
        "192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.103",# SQL Injection
        "10.1.1.5", "10.1.1.6", "10.1.1.7"                               # Insider Threat
    ],
    "attack_type": [
        "Phishing", "Phishing", "Phishing", "Phishing",
        "Ransomware", "Ransomware", "Ransomware", "Ransomware",
        "DDoS", "DDoS", "DDoS", "DDoS",
        "SQL Injection", "SQL Injection", "SQL Injection", "SQL Injection",
        "Insider Threat", "Insider Threat", "Insider Threat"
    ],
    "severity": [
        10, 10, 10, 10,  # Phishing
        14, 14, 14, 14,  # Ransomware
        3, 3, 3, 3,      # DDoS
        12, 12, 12, 12,  # SQL Injection
        8, 8, 8          # Insider
    ]
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

#Writing DataFrame into a database (threat_logs)
df.to_sql("threat_logs", con = engine, if_exists = "replace", index = False)
print("[+] Data is successfully uploaded into PostgreSQL in a table 'threat_logs'.")

#Connecting to Chroma in Docker
chroma_client = chromadb.HttpClient(host='chroma_app', port=8000)
collection = chroma_client.get_or_create_collection(name="threat_logs_vectors")

#Sync writing texts to a vector database
collection.add(
    documents=historic_documents,
    metadatas=[{"type":t} for t in raw_data['attack_type']],
    ids=[f"doc{i}" for i in range(len(historic_documents))]
)
print("[+] Vector database Chroma DB is successfully updated with data from kb.txt")

# Writing DataFrame in a data base (threat_logs)


results = collection.query(
    query_texts = ["How do hackers steal bank credentials?"], 
    n_results = 1
)
print("Result of the search in Chroma DB:", results)

print("Success! Data is added to PostgreSQL in a table 'threat_logs'.")