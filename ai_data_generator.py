import os
import time
import pandas as pd 
import requests
from dotenv import load_dotenv
import io

print("=== AI Data Augmentation Pipeline Started ===")
load_dotenv(override=True)
api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("[-] CRITICAL: GEMINI_API_KEY is missing in .env file.")

# Autodetection of gemini model
print("[*] Discovering avaliable models for your API key...")
models_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
try:
    models_response = requests.get(models_url)
    if models_response.status_code != 200:
        print(f"[-] Failed to fetch models. Check your API key. Error: {models_response.text}")
        exit(1)
    avaliable_models = models_response.json().get('models', [])
    valid_models = [
        m['name'] for m in avaliable_models
        if 'generateContent' in m.get('supportedGenerationMethods', []) and 'gemini' in m.get('name', '').lower()
    ]
    if not valid_models:
        print("[-] Vo compftible Gemini models found for this key.")
        exit(1)
        
    print(f"[+] Found {len(valid_models)} compatible models.")
    
    #Searching Flash or taking first appropriate
    chosen_model = valid_models[0]
    for vm in valid_models:
        if 'flash' in vm.lower():
            chosen_model = vm
            break
    print(f"[*] Automatically selected model: {chosen_model}")
except Exception as e:
    print(f"[-] Error during auto-discovery: {e}")
    exit(1)
    
    
#Generation of data
URL = f"https://generativelanguage.googleapis.com/v1beta/{chosen_model}:generateContent?key={api_key}"
HEADERS = {'Content-Type': 'application/json'}
base_prompt = """You are a Senior Cyber Threat Intelligence (CTI) Analyst.
Generate 500 rows of realistic synthetic data for a RAG system in CSV format.

Structure: threat_summary,source_ip,threat_title,attack_type,severity,confidence

Generation rules:
threat_summary: 1-2 realistic sentences (news style, CISA reports, technical jargon, known vulnerabilities/CVEs). NO repetitions.
attack_type and severity (strict exact match): Phishing (10.0), Ransomware (14.0), DDoS (3.0), SQL Injection (12.0), Insider Threat (8.0), RCE (15.0), Infostealer (11.0), Web Shell (13.0), CSRF (7.0), Informational (0.0).
Informational (0.0) means legitimate news about patches, software updates, and conferences.
threat_title: ALWAYS "Historical Baseline Record".
confidence: ALWAYS 100.0.
source_ip: Random valid IPv4 addresses.

OUTPUT ONLY CLEAN RAW CSV (with column headers). NO markdown formatting (do not use ```csv). NO intro or outro text."""

all_dataframes = []
for batch in range(1, 6):
    print(f"[*] Requesting Batch {batch}/5 via Direct REST API...")
    payload= {
        "contents": [{"parts": [{"text": base_prompt}]}]
    }
    success = False
    try:
        response = requests.post(URL, headers=HEADERS, json=payload)
        response_data = response.json()
        if response.status_code == 200:
            raw_csv = response_data['candidates'][0]['content']['parts'][0]['text'].strip()
        
            #Cleaning possible markdown presence
            if raw_csv.startswith("```csv"): raw_csv = raw_csv[6:]
            if raw_csv.startswith("```"): raw_csv = raw_csv[3:]
            if raw_csv.endswith("```"): raw_csv = raw_csv[:-3]
        
            df_batch = pd.read_csv(io.StringIO(raw_csv.strip()))
            all_dataframes.append(df_batch)
            print(f" [+] Model {model_name} generated Batch {batch} successfuly, ({len(df_batch)} rows).")
        else:
            print(f"[!] API Error: {response_data}")
    except Exception as e:
        print(f"[-] Error in batch {batch}: {e}")
    time.sleep(3)
        
if all_dataframes:
    final_df = pd.concat(all_dataframes, ignore_index=True)
    final_df.to_csv("baseline.csv", index=False)
    print(f"\n=== Success! Generated {len(final_df)} highly contextual rows and saved to baseline.csv ===")
else:
    print("[-] Failed to generate data.")


