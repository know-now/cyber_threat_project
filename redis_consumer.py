import os
import time
import json
import redis
from datetime import datetime
from dotenv import load_dotenv
load_dotenv(override = True)
import pandas as pd
from sqlalchemy import create_engine
import chromadb
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder

print("===CTI AI Consumer Started===")
time.sleep(5)

# 1. Connection to a database and rapid learning of the model
DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_NAME = os.getenv("POSTGRES_DB") or "cyber_threat_db"
engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@postgres_db:5432/{DB_NAME}")

try:
    df = pd.read_sql("threat_logs", con = engine)
    train_df = df[~df['source_ip'].str.contains("OSINT")].copy()
    
    encoder = LabelEncoder()
    train_df['attack_encoded'] = encoder.fit_transform(train_df['attack_type'])
    
    model = DecisionTreeClassifier(max_depth=5)
    model.fit(train_df[['attack_encoded']], train_df['severity'])
    print(f"[+] AI model (Decision Tree) is successfully trained on {len(train_df)} baseline records.")
except Exception as e:
    print(f"[-] Error of access to PostgreSQL. Details: {e}")
    exit(1)

#2. Connection to Chroma DB (NLP extracting items)
print("[*] Connection to vector database Chroma DB...")
chroma_client = chromadb.HttpClient(host='chroma_app', port =8000)
collection = chroma_client.get_or_create_collection(name = "threat_logs_vectors")

# 3.Redis connection.
cache = redis.Redis(host = "redis_db", port = 6379, decode_responses = True)
print("[*] Waiting of new items in 'threat_queue' (real time)...")

#The Event Loop
while True:
    try:
        # Method brpop is preventing actions and is waiting for new data
        raw_json = cache.lpop("threat_queue")
        
        if not raw_json:
            time.sleep(3)
            continue
        try:
            article = json.loads(raw_json)
            threat_title = article.get("title", "")
            threat_summary = article.get("summary", "")
        except:
            print("[-] Got old format of data, I will not consider it...")
            continue
            
        print(f"\n[!] Analysis of the new threat: {threat_title}")
        
        # RAG: semantic search using the whole article with a check of halucinations
        # Sending text to ChromaDB network, to find similar historical data
        results = collection.query(query_texts=[threat_summary], n_results = 1)
        
        if results['documents'] and results['documents'][0]:
            semantic_distance = results['distances'][0][0]
            
            #Taking class from the matadata of example
            detected_type = results['metadatas'][0][0]['type']
            
            # Adaptation of maths to a geometry of space MiniLM
            DISTANCE_MAX = 2.0
            rag_confidence_raw = max(0.0, ((DISTANCE_MAX - semantic_distance) / DISTANCE_MAX))
            calculated_confidence = round(rag_confidence_raw * 100.0, 1)
            
            MIN_CONFIDENCE = 15.0
            if calculated_confidence < MIN_CONFIDENCE: 
                print(f'[?] ATTENTION: conficence {calculated_confidence}% is below threshold {MIN_CONFIDENCE}%. Marked for Manual Review.')
                detected_type = "Unknown / Review Needed"
                final_severity = 0.0
            else:
                encoded_val = encoder.transform([detected_type])[0]
                new_data = pd.DataFrame({'attack_encoded':[encoded_val]})
                base_severity = float(model.predict(new_data)[0])
            
                # Calculations of dynamic severity = Historical severity * coeficient RAG
                final_severity = round(base_severity * rag_confidence_raw, 1)
                final_severity = max(1.0, final_severity)
        
            print(f" > Classificatior detected type: {detected_type} RAG distance: {semantic_distance:2f}")
            print(f" > Prognostic Severity: {final_severity}/14 (Base: {base_severity})")
            print(f" > Calculated Accuracy: {calculated_confidence}%")
        else:
            detected_type = "Unknown / Review Needed"
            final_severity = 0.0
            calculated_confidence = 0.0
        # Writing a new threat to PostgreSQL
        new_record = pd.DataFrame({
            "timestamp": [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            "source_ip": ["OSINT (Web RSS)"],
            "threat_title": [threat_title],
            "attack_type": [detected_type],
            "severity": [final_severity],
            "confidence": [calculated_confidence]
        })
        new_record.to_sql("threat_logs", con=engine, if_exists="append", index=False)
        print(" [*] Live data appended to PostgreSQL for Reports!")
        
        print("[*] Continue to monitor...")
    except Exception as e:
        print(f"[-] Network pause or error. Retrying...{e}")
        time.sleep(3)
        


