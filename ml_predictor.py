import os
import time
import pandas as pd
from sqlalchemy import create_engine
from sklearn.preprocessing import LabelEncoder
from sklearn import DecisionTreeClassifier


print("===Analytical Laboratory (ML Predictor) is running.===")
print("Wait time 3sec.")
time.sleep(3)

DB_USER = os.getenv("POSTGRES_USER")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD")
DB_HOST = "postgres_db"
DB_PORT = "5432"
DB_NAME = os.getenv("POSTGRES_DB") or "cyber_threat_db"

connection_url = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(connection_url)

try:
    # 1.Reading raw data in PostgreSQL
    df = pd.read_sql("SELECT * FROM threat_logs", engine)
    print("\n[+] Data is successfully uploaded from database.")
    print(df)
    
    # 2. Preparing for ML (Scikit-Learn)
    encoder = LabelEncoder()
    df['attack_encoded'] = encoder.fit_transform(df['attack_type'])
    
    print("\n[+] Data is transformed for ML-models (Label Encoding):")
    
    #Showing just columns to show transformation of text into numbers
    print(df[['attack_type', 'attack_encoded', 'severity']])
    print("\n=== Ready for training of the predictive model===")
except Exception as e:
    print(f"Error of the ML-module: {e}")