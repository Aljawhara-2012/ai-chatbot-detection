"""Build tools/urls.csv for the load test: 20 legitimate URLs and 20 current phishing URLs.

Phishing URLs are taken, as text only, from the public OpenPhish community feed (https://openphish.com/feed.txt);
no page is opened by this script. Run it on the day of the load test, because phishing pages go offline quickly.
    python tools\\make_urls.py
"""
import csv, datetime, os, random
import requests

LEGIT = ["https://www.wikipedia.org", "https://www.python.org", "https://www.bbc.com", "https://www.apu.edu.my",
         "https://www.github.com", "https://www.microsoft.com", "https://www.apple.com", "https://www.amazon.com",
         "https://www.nytimes.com", "https://www.reuters.com", "https://www.stackoverflow.com", "https://www.mozilla.org",
         "https://www.w3.org", "https://www.ieee.org", "https://www.springer.com", "https://www.nature.com",
         "https://www.who.int", "https://www.un.org", "https://www.linkedin.com", "https://www.oracle.com"]

feed = requests.get("https://openphish.com/feed.txt", timeout=30).text.split()
phish = [u.strip() for u in feed if u.startswith("http")]
random.Random(42).shuffle(phish)
phish = phish[:20]
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "urls.csv")
with open(out, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    for u in LEGIT:
        w.writerow([u, "Benign"])
    for u in phish:
        w.writerow([u, "Malicious"])
print(f"{out}: {len(LEGIT)} legitimate + {len(phish)} phishing URLs (OpenPhish feed, {datetime.date.today()})")
