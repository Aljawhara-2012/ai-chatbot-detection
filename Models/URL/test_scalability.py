import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define endpoints and test samples
endpoints = {
    "URL Detection": ("http://127.0.0.1:5000/predict_url", {"url": "http://malicious-example.com"}),
    "PDF Detection": ("http://127.0.0.1:5000/upload", "test_sample.pdf"),
    "EXE Detection": ("http://127.0.0.1:5000/upload", "test_sample.exe"),
}

# Number of concurrent threads (simulated users)
NUM_THREADS = 10
REQUESTS_PER_ENDPOINT = 10

# --- Helper functions ---
def test_url_detection(url, payload):
    """Send URL detection requests."""
    start = time.time()
    try:
        response = requests.post(url, json=payload)
        latency = time.time() - start
        return latency, response.status_code
    except Exception as e:
        return None, str(e)

def test_file_detection(url, filepath):
    """Send file upload requests."""
    start = time.time()
    try:
        with open(filepath, "rb") as f:
            response = requests.post(url, files={"file": f})
        latency = time.time() - start
        return latency, response.status_code
    except Exception as e:
        return None, str(e)

# --- Concurrent testing ---
def run_concurrent_tests():
    results = []

    with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
        futures = []

        # URL Detection
        url, payload = endpoints["URL Detection"]
        for _ in range(REQUESTS_PER_ENDPOINT):
            futures.append(executor.submit(test_url_detection, url, payload))

        # File Detection (PDF + EXE)
        for name in ["PDF Detection", "EXE Detection"]:
            url, filepath = endpoints[name]
            for _ in range(REQUESTS_PER_ENDPOINT):
                futures.append(executor.submit(test_file_detection, url, filepath))

        # Gather results
        for future in as_completed(futures):
            results.append(future.result())

    return results

# --- Run test ---
print(f"Running scalability test with {NUM_THREADS} concurrent threads...")
start_total = time.time()
results = run_concurrent_tests()
total_time = time.time() - start_total

# --- Process results ---
latencies = [r[0] for r in results if r[0] is not None]
avg_latency = sum(latencies) / len(latencies) if latencies else 0

print("\n--- Scalability Test Results ---")
print(f"Total requests sent: {len(results)}")
print(f"Average latency per request: {avg_latency:.4f} seconds")
print(f"Total test duration: {total_time:.2f} seconds")

failures = [r for r in results if isinstance(r[1], str)]
if failures:
    print(f"\n⚠️ {len(failures)} requests failed:")
    for f in failures[:5]:
        print(f"  Error: {f[1]}")
else:
    print("\n✅ All requests completed successfully!")
