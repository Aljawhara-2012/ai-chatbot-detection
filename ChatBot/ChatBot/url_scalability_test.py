import requests
import threading
import time

URL = "http://127.0.0.1:5000/test_url"  # Endpoint from above

# List of URLs to test
urls_to_test = [
    "http://example.com",
    "http://malicious-site.com/fake",
    "https://secure-login.com/login",
] * 50  # repeat to simulate load

NUM_USERS = len(urls_to_test)

def send_url(url_text):
    start = time.time()
    response = requests.post(URL, json={"url": url_text})
    end = time.time()
    duration = end - start
    print(f"[{threading.current_thread().name}] {url_text} -> {response.status_code} in {duration:.2f}s, {response.json().get('status')}")

threads = []
start_time = time.time()

for i, url in enumerate(urls_to_test):
    t = threading.Thread(target=send_url, args=(url,), name=f"User-{i+1}")
    threads.append(t)
    t.start()

for t in threads:
    t.join()

total_time = time.time() - start_time
print(f"\n✅ Completed {NUM_USERS} URL tests in {total_time:.2f}s total.")
