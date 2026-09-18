import os
import time
import redis
from dotenv import load_dotenv
load_dotenv(override = True)
import pandas as pd
from sqlalchemy import create_engine
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
    
#Redis connection.
cache = redis.Redis(host = "redis_db", port = 6379, decode_responses = True)
print("[*] Waiting of new items in 'threat_queue' (real time)...")

#The Event Loop
while True:
    try:
        # Method brpop is preventing actions and is waiting for new data
        task = cache.brpop("threat_queue", timeout = 5)
        
        if task:
            queue_name, threat_title = task
            print(f"/n[!] Signal from REDIS: {threat_title}")
            
            # RAG Baseline
            title_lower = threat_title.lower()
            if "phishing" in title_lower or "email" in title_lower:
                detected_type = "Phishing"
            elif "sql" in title_lower or "database" in title_lower:
                detected_type = "SQL Injection"
            elif "ddos" in title_lower or "botnet" in title_lower:
                detected_type = "DDoS"
            else:
                detected_type = "Brute Force"
            # Text transformation into numbers and prognosis
            encoded_val = encoder.transform([detected_type])[0]
            new_data = pd.DataFrame({'attack_encoded': [encoded_val]})
            prediction = model.predict(new_data)
            
            print(f" > Classificatior detected type: {detected_type} ")
            print(f" > Prognostic range of threat (Severity): {prediction[0]}/14")
            print("[*] Continue to monitor...")
    except Exception as e:
        print(f"[-] Network pause or error. Retrying...{e}")
        time.sleep(3)
        


