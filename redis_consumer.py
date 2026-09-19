import os
import time
import json
import redis
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
    df = pd.read_sql("SELECT * FROM threat_logs", engine)
    encoder = LabelEncoder()
    df['attack_encoded'] = encoder.fit_transform(df['attack_type'])
    
    model = DecisionTreeClassifier()
    model.fit(df[['attack_encoded']], df['severity'])
    print("[+] AI model (Decision Tree) is successfully trained in the memory")
except Exception as e:
    print(f"[-] Error of access to PostgreSQL. Check is etl_app is working correctly. Details: {e}")
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
        task = cache.brpop("threat_queue", timeout = 5)
        
        if task:
            queue_name, raw_json = task
            # Unpacking JSON
            try:
                article = json.loads(raw_json)
                threat_title = article.get("title", "")
                threat_summary = article.get("summary", "")
            except:
                print("[-] Got old format of dsta, I will not consider it...")
                continue
            
            print(f"\n[!] Analysis of the new threat: {threat_title}")
            
            # RAG: semantic search using the whole article
            # Sending text to ChromaDB network, to find similar historical data
            results = collection.query(query_texts=[threat_summary], n_results = 1)
            
            if results['documents'] and results['documents'][0]:
                closest_historic_doc = results['documents'][0][0].lower()
                
                #mapping on the basis of found semantic context
                if "phishing" in closest_historic_doc or "email" in closest_historic_doc:
                    detected_type = "Phishing"
                elif "sql" in closest_historic_doc or "database" in closest_historic_doc:
                    detected_type = "SQL Injection"
                elif "ddos" in closest_historic_doc or "server" in closest_historic_doc:
                    detected_type = "DDoS"
                else:
                    detected_type = "Brute Force"
            else:
                detected_type = "Brute Force"
                
            #=== ML: Prognosis by Desision Tree ===
            encoded_val = encoder.transform([detected_type])[0]
            new_data = pd.DataFrame({'attack_encoded':[encoded_val]})
            prediction = model.predict(new_data)
            
            print(f" > Classificatior detected type: {detected_type} ")
            print(f" > Prognostic range of threat (Severity): {prediction[0]}/14")
            print("[*] Continue to monitor...")
    except Exception as e:
        print(f"[-] Network pause or error. Retrying...{e}")
        time.sleep(3)
        


