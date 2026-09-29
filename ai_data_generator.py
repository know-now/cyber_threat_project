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

URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
HEADERS = {'Content-Type': 'application/json'}

base_prompt = """You are a Senior Cyber Threat Intelligence (CTI) Analyst.
Generate 100 rows of realistic synthetic data for a RAG system in CSV format.

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
    try:
        response = requests.post(URL, headers=HEADERS, json=payload)
        response_data = response.json()
        if response.status_code != 200:
            print(f"[-] API Error: {response_data}")
            continue
        
        raw_csv = response_data['candidates'][0]['content']['parts'][0]['text'].strip()
        
        #Cleaning possible markdown presence
        if raw_csv.startswith("```csv"): raw_csv = raw_csv[6:]
        if raw_csv.startswith("```"): raw_csv = raw_csv[3:]
        if raw_csv.endswith("```"): raw_csv = raw_csv[:-3]
        
        df_batch = pd.read_csv(io.StringIO(raw_csv.strip()))
        all_dataframes.append(df_batch)
        print(f" [+] Batch {batch} successful ({len(df_batch)} rows).")
        time.sleep(3)
    except Exception as e:
        print(f"[-] Error in batch {batch}: {e}")
        
if all_dataframes:
    final_df = pd.concat(all_dataframes, ignore_index=True)

    #Saving file
    final_df.to_csv("baseline.csv", index=False)
    print(f"=== Success! Generated {len(final_df)} highly contextual rows and saved to baseline.csv ===")
else:
    print("[-] Failed to generate data.")


