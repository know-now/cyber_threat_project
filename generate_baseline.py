import pandas as pd
import random
import ipaddress

print("=== Generating 500 rows for baseline.csv ===")

data = []
classes = [
    ("Phishing", 10.0, ["phishing emails", "fake login portals", "social engineering", "spear-phishing", "smishing attacks", "malicious attachments", "deceptive links", "credential harvesting", "CEO fraud", "invoice scams"]),
    ("Ransomware", 14.0, ["Ryuk ransomware", "Conti variant", "LockBit encryption", "crypto-locker", "double extortion", "file encryption", "RaaS payload", "AES-256 locker", "malicious encryptor", "network locker"]),
    ("DDoS", 3.0, ["UDP flood", "TCP SYN flood", "botnet swarm", "volumetric attack", "HTTP flood", "DNS amplification", "IoT botnet attack", "Mirai variant", "Layer 7 DDoS", "ping of death"]),
    ("SQL Injection", 12.0, ["UNION-based SQLi", "blind SQL injection", "error-based SQLi", "database dump via SQLi", "malicious SQL queries", "SQL payload in login", "backend SQL manipulation", "unauthorized DB access via SQL", "time-based SQLi", "SQL injection flaw"]),
    ("Insider Threat", 8.0, ["rogue employee", "unauthorized USB drive", "exfiltration by admin", "disgruntled worker", "hardcoded credentials leak", "internal data theft", "misconfigured permissions", "privilege abuse", "stolen VPN keys", "internal sabotage"]),
    ("RCE", 15.0, ["remote code execution", "arbitrary code execution", "zero-day RCE", "unauthenticated command injection", "buffer overflow RCE", "deserialization RCE", "kernel level RCE", "heap spray attack", "RCE in Apache", "RCE via vulnerable plugin"]),
    ("Infostealer", 11.0, ["RedLine stealer", "Raccoon infostealer", "Vidar malware", "credential stealer", "browser cookie theft", "crypto wallet stealer", "keylogger deployment", "infostealer trojan", "clipboard hijacking", "spyware infection"]),
    ("Web Shell", 13.0, ["PHP web shell", "ASPX backdoor", "stealthy web shell", "China Chopper variant", "persistent web shell", "uploaded malicious script", "C2 web interface", "hidden shell in image directory", "webshell backdoor", "IIS compromised shell"]),
    ("CSRF", 7.0, ["cross-site request forgery", "session riding", "unauthorized state change via CSRF", "forged HTTP request", "CSRF in admin panel", "malicious state-changing link", "bypassed anti-CSRF token", "CSRF vulnerability", "DOM-based CSRF", "one-click attack"]),
    ("Informational", 0.0, ["Microsoft Patch Tuesday", "new cybersecurity webinar", "company announces AI update", "NIST guidelines released", "iOS security patch", "software version update", "conference announcement", "new compliance laws", "vendor acquisition", "zero trust architecture paper"])
]

contexts = [
    "was detected on the main server.",
    "caused significant disruption.",
    "was mitigated by the security team.",
    "targeted the financial department.",
    "exploited a known vulnerability.",
    "compromised cloud infrastructure.",
    "was discovered during a routine audit.",
    "affected multiple internal systems.",
    "was reported by threat intelligence.",
    "triggered automated alerts."
]

for _ in range(500):
    cls_name, sev, keywords = random.choice(classes)
    keyword = random.choice(keywords)
    context = random.choice(contexts)
    
    summary = f"A {keyword} {context}".capitalize()
    if cls_name == "Informational":
        summary = f"News: {keyword.capitalize()}{context}"
        
    # Generating of random realistic IP-addresses
    ip = str(ipaddress.IPv4Address(random.randint(0, (2**32)-1)))
    
    data.append({
        "threat_summary": summary, 
        "source_ip": ip,
        "threat_title": "Historical Baseline Record",
        "attack_type": cls_name,
        "severity": sev,
        "confidence": 100.0
    })
    
df = pd.DataFrame(data)
df.to_csv("baseline.csv", index= False)
print("[+] baseline.csv successfully generated with 500 robust records!")