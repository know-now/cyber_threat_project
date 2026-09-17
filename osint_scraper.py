import requests
from bs4 import BeautifulSoup
import redis

print("===OSINT Scraper (Collector) is running.===")

# Redis connection.
cache = redis.Redis(host='redis_db', port=6379, decode_responses=True)

url = "https://thehackernews.com/"
print(f"[*] Collecting raw data from: {url}")

try:
    # 1.Loading the page
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    
    #2. Parsing HTML-code
    soup = BeautifulSoup(response.text, 'html.parser')
    
    #Searching for headlines of the articles
    headlines = soup.find_all('h2', class_='story-title')
    
    if not headlines:
        print("[-] Headlines are not found. Possibly the website has changed.")
    
    # 3. Writing first 5 news to the Redis
    print("\n[+] Found attacks:")
    for headline in headlines[:5]:
        title = headline.text.strip()
        cache.lpush('threat_queue', title)
        print(f"- {title}")
        
    queue_length = cache.llen('threat_queue')
    print(f"\===Success! In Redis now {queue_length} raw OSINT-info")
except Exception as e:
    print(f"Error of the parsing: {e}")