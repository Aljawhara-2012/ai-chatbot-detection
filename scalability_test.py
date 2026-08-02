import requests
import threading
import time
import os

# 🔹 Adjust this to your running Flask app address
URL = "http://127.0.0.1:5000/upload"

# 🔹 Folder containing test files to upload
TEST_FILES_DIR = "test_files"  # create this folder with a few sample .exe, .pdf, etc.

# 🔹 Number of users (threads) to simulate
NUM_USERS = 10

# Make sure test files exist
files_list = [os.path.join(TEST_FILES_DIR, f) for f in os.listdir(TEST_FILES_DIR) if os.path.isfile(os.path.join(TEST_FILES_DIR, f))]
if not files_list:
    raise FileNotFoundError("⚠️ No test files found in 'test_files' folder!")

# Function to send file to /upload
def send_file(file_path):
    try:
        start = time.time()
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(URL, files=files)
        end = time.time()
        duration = end - start
        print(f"[{threading.current_thread().name}] {os.path.basename(file_path)} -> {response.status_code} in {duration:.2f}s")
    except Exception as e:
        print(f"Error: {e}")

# Create and start threads
threads = []
start_time = time.time()

for i in range(NUM_USERS):
    file_path = files_list[i % len(files_list)]
    t = threading.Thread(target=send_file, args=(file_path,), name=f"User-{i+1}")
    threads.append(t)
    t.start()

# Wait for all to finish
for t in threads:
    t.join()

total_time = time.time() - start_time
print(f"\n✅ Completed {NUM_USERS} concurrent uploads in {total_time:.2f}s total.")
