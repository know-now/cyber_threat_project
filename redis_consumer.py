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
    df = pd.read_sql("SELECT * FROM threat_logs WHERE source_ip NOT LIKE 'OSINT%", engine)
    encoder = LabelEncoder()
    df['attack_encoded'] = encoder.fit_transform(df['attack_type'])
    
    model = DecisionTreeClassifier()
    model.fit(df[['attack_encoded']], df['severity'])
    print("[+] AI model (Decision Tree) is successfully trained only historical baseline.")
except Exception as e:
    print(f"[-] Error of access to PostgreSQL. Check if etl_app is working correctly. Details: {e}")
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
            print("[-] Got old format of dsta, I will not consider it...")
            continue
            
        print(f"\n[!] Analysis of the new threat: {threat_title}")
        
        # RAG: semantic search using the whole article with a check of halucinations
        # Sending text to ChromaDB network, to find similar historical data
        results = collection.query(query_texts=[threat_summary], n_results = 1)
        
        if results['documents'] and results['documents'][0]:
            closest_historic_doc = results['documents'][0][0].lower()
            semantic_distance = results['distances'][0][0]
            
            #Protection if the text is too far from cybersecurity topic
            DISTANCE_THRESHOLD = 1.5
            
            if semantic_distance > DISTANCE_THRESHOLD:
                print(f"[?] ATTENTION: text is not recognised as a cybersecurity topic")
                detected_type = "Unknown / Review Needed"
            else:
                #mapping on the basis of found semantic context
                if "phishing" in closest_historic_doc or "email" in closest_historic_doc:
                    detected_type = "Phishing"
                elif "sql" in closest_historic_doc or "database" in closest_historic_doc:
                    detected_type = "SQL Injection"
                elif "ddos" in closest_historic_doc or "server" in closest_historic_doc:
                    detected_type = "DDoS"
                else:
                    detected_type = "Ransomware"
        else:
            detected_type = "Unknown / Review Needed"
                
            #=== ML: Prognosis by Desision Tree with a Confidence Score ===
            if detected_type == "Unknown / Review Needed":
                print(" > Classifying: no automatic prognosis (not enough data)")
                print(" > Prognostic level of threat: attention of tht specialist is needed")
                final_severity = 0.0
                calculated_confidence = 0.0
            else:
                encoded_val = encoder.transform([detected_type])[0]
                new_data = pd.DataFrame({'attack_encoded':[encoded_val]})
                base_severity = float(model.predict(new_data)[0])
                
                # Calculating RAG confidence (0 to 1)
                rag_confidence = max(0, ((DISTANCE_THRESHOLD - semantic_distance)/DISTANCE_THRESHOLD))
                
                # Calculations of dynamic severity = Historical severity * coeficient RAG
                final_severity = round(base_severity * rag_confidence, 1)
                final_severity = max(1.0, final_severity)
                
                # Precisiness is based on the semantic distance (0 distance = 100%, 1.5 distance = 0%)
                calculated_confidence = max(0, ((DISTANCE_THRESHOLD - semantic_distance) / DISTANCE_THRESHOLD))
                
                print(f" > Classificatior detected type: {detected_type} RAG distance: {semantic_distance:2f}")
                print(f" > Prognostic Severity: {final_severity}/14 (Base: {base_severity})")
                print(f" > Calculated Accuracy: {calculated_confidence}%")
            # Writing a new threat to PostgreSQL
            new_record = pd.DataFrame({
                "timestamp": [datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                "source_ip": ["OSINT (Web RSS)"],
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
        


