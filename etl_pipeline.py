import os
import sys
import time
from dotenv import load_dotenv
load_dotenv(override = True)
import pandas as pd
from sqlalchemy import create_engine
import chromadb



#Block Extract(E): creation of raw test data about threats

df = pd.read_csv("baseline.csv")
# Block Transform (T):Convert data types
df["timestamp"] = pd.date_range(start="2026-09-14 10:00:00", periods=len(df), freq="5min")

# Block Load (L): connection to PostgreSQL and data writing
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = "postgres_db"
DB_PORT = "5432"
DB_NAME = os.getenv("POSTGRES_DB") or "cyber_threat_db"

# Guard Clause
if not all([DB_USER, DB_PASSWORD, DB_NAME]):
    raise ValueError("CRITICAL: Variables are not found, check .env.")


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