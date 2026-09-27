import os
import time
import json
import redis
import requests
import feedparser
from apscheduler.schedulers.background import BackgroundScheduler

print("===OSINT Scraper (Collector) is running.===")

# Redis connection.
cache = redis.Redis(host='redis_db', port=6379, decode_responses=True)
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/"
    ]
def fetch_news():
    print(f"\n===[Basic cycle] Running OSINT-collection data: {time.strftime('%Y-%n-%d %H:%M:%S')}===")
    total_added = 0
    
    for url in RSS_FEEDS:
        print(f"[*] Checking the resources: {url}")
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:5]:
                article_link = entry.link
                
                #check for duplicates: if URL is already in Redis - skip
                if not cache.exists(f"seen:{article_link}"):
                    article = {
                        "title": entry.title,
                        "summary": entry.get('summary', entry.title),
                        "link": article_link
                    }
                    #Sending to a queue for a consumer
                    cache.lpush("threat_queue", json.dumps(article))
                    # Writing URL in a "memory" for 24 hours (86400 seconds)
                    cache.set(f"seen:{article_link}", "1", ex = 86400)
                    
                    total_added += 1
                    print(f" [+] New threat:{entry.title}")
        except Exception as e:
            print(f" [-] Error of parsing {url}: {e}")
            
    print(f"===Collection of data is finished. Added new threats into a queue: {total_added} ===")
if __name__ == "__main__":
    print("===CTI OSINT Scraper is running in a background")
    # First run when starting a container
    fetch_news()
    
    # Settings of a planner (running every 60 minutes)
    scheduler = BackgroundScheduler()
    scheduler.add_job(fetch_news, 'interval', minutes = 60)
    scheduler.start()
    
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        print("[-] Scheduler is stopped.")
        






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