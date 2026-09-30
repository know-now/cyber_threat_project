import os
import sys
import time
from dotenv import load_dotenv
load_dotenv(override = True)
import pandas as pd
from sqlalchemy import create_engine
import chromadb


print("=== Extract, Transform, Load (ETL) Started ===")

try:
    #Block Extract(E): creation of raw test data about threats

    df = pd.read_csv("baseline.csv")
    #delete NaN lines
    df = df.dropna()
    #convert to text, neutralise NaN
    df['threat_summary'] = df['threat_summary'].fillna("").astype(str)
    df['attack_type'] = df['attack_type'].fillna("Unknown").astype(str)
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
    df_sql = df.drop(columns=['threat_summary'])
    df_sql.to_sql("threat_logs", con = engine, if_exists = "replace", index = False)
    print("[+] Data is successfully uploaded into PostgreSQL in a table 'threat_logs'.")

    #Connecting to Chroma in Docker
    chroma_client = chromadb.HttpClient(host='chroma_app', port=8000)
    try:
        chroma_client.delete_collection(name="threat_logs_vectors")
    except:
        pass
    collection = chroma_client.get_or_create_collection(name="threat_logs_vectors")

    # Taking data from a dataFrame
    collection.add(
        documents=df['threat_summary'].tolist(),
        metadatas=[{"type":str(t)} for t in df['attack_type']],
        ids=[f"doc{i}" for i in range(len(df))]
    )
    print("[+] Chroma DB updated with {len(df)} semantic vectors!")
except Exception as e:
    print(f"[-] CRITICAL ETL ERROR: {e}")
    exit(1)