import requests
import redis
import feedparser
import json

print("===OSINT Scraper (Collector) is running.===")

# Redis connection.
cache = redis.Redis(host='redis_db', port=6379, decode_responses=True)
url = "https://feeds.feedburner.com/TheHackersNews"

print(f"[*] Collecting raw data from: {url}")

try:
    # 1.Loading the page through RSS
    feed = feedparser.parse(url)
    if not feed.entries:
        print("[-] Headlines are not found. Feed might be unavaliable.")
    else:
        print("[+] Found attacks:")
        for entry in feed.entries[:3]:
            title = entry.title
            summary =  entry.summary if 'summary' in entry else title
            # packing into JSON object
            threat_data = json.dumps({"title":title, "summary":summary})
            cache.lpush('threat_queue', threat_data)
            print(f" - {title}")
            
    queue_length = cache.llen('threat_queue')
    print(f"\===Success! In Redis now {queue_length} raw OSINT-info")
except Exception as e:
    print(f"Error of the parsing: {e}")