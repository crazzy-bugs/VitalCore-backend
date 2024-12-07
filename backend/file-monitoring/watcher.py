import os
import time
import sqlite3
import hashlib
from threading import Timer
from collections import defaultdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from clamdVM import test_file

WATCH_FOLDER = "target"
QUARANTINE_FOLDER = "D:/Test/isolate"
DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'scan_results.db')

# Ensure the watch and quarantine folders exist
os.makedirs(WATCH_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def initialize_database():
    """
    Initialize the SQLite database and create the files table if it doesn't exist.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE,
                    file_hash TEXT,
                    scan_status TEXT,
                    virus_name TEXT,
                    av_name TEXT,
                    scan_timestamp TEXT
                )
            ''')
            conn.commit()
            print("[INFO] Database initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize database: {e}")

initialize_database()

def compute_file_hash(file_path, chunk_size=65536, retries=3):
    for attempt in range(retries):
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"[WARNING] Hash computation failed for {file_path} (Attempt {attempt + 1}/{retries}): {e}")
            time.sleep(1)  # Wait before retrying
    print(f"[ERROR] Unable to compute hash after {retries} attempts for: {file_path}")
    return None

def log_scan_result(file_path, file_hash, scan_status, virus_name, av_name):
    """
    Log the scan results into the database.
    """
    try:
        scan_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO files 
                (file_path, file_hash, scan_status, virus_name, av_name, scan_timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_path, file_hash, scan_status, virus_name or "Not a virus", av_name, scan_timestamp))
            conn.commit()
            print(f"[INFO] Scan result logged successfully for {file_path}")
    except Exception as e:
        print(f"[ERROR] Failed to log scan result: {e}")

def parse_clamdscan_output(output):
    """
    Parse the output of clamdscan to extract scan results.
    """
    try:
        if not output:
            return "error", "No output received"
        
        for line in output.splitlines():
            if ": " in line:
                file_path, result = line.split(": ", 1)
                if "FOUND" in result:
                    virus_name = result.replace("FOUND", "").strip()
                    return "infected", virus_name
                elif "OK" in result:
                    return "clean", None
        
        return "error", "Unknown scan result"
        
    except Exception as e:
        print(f"[ERROR] Failed to parse scan output: {e}")
        return "error", str(e)

class WatcherHandler(FileSystemEventHandler):
    def __init__(self, username, ip, password):
        self.username = username
        self.ip = ip
        self.password = password
        self.processed_files = set()
        super().__init__()

    def process_event(self, file_path):
        if file_path in self.processed_files:
            return
        self.processed_files.add(file_path)
        process_file(file_path, self.username, self.ip, self.password)

    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

def process_file(file_path, username, ip, password):
    """
    Send a file to the VM for scanning and handle results.
    """
    print(f"[INFO] Processing file: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"[INFO] File no longer exists: {file_path}")
        return
        
    try:
        file_hash = compute_file_hash(file_path)
        if not file_hash:
            print(f"[ERROR] Could not compute hash for {file_path}")
            return

        # Check if file has already been scanned with same hash
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT scan_status FROM files WHERE file_hash = ?", (file_hash,))
            record = cursor.fetchone()
            
            if record:
                print(f"[INFO] File already scanned: {file_path}")
                return

        # Perform the scan
        output = test_file(username, ip, password, file_path)
        scan_status, virus_name = parse_clamdscan_output(output)
        
        # Log results
        log_scan_result(file_path, file_hash, scan_status, virus_name, "ClamAV")
        
        # Handle infected files
        if scan_status == "infected":
            try:
                quarantine_path = os.path.join(QUARANTINE_FOLDER, os.path.basename(file_path))
                os.rename(file_path, quarantine_path)
                print(f"[INFO] Infected file moved to quarantine: {quarantine_path}")
            except Exception as e:
                print(f"[ERROR] Failed to quarantine file: {e}")
        else:
            print(f"[INFO] File is clean: {file_path}")

    except Exception as e:
        print(f"[ERROR] Failed to process file {file_path}: {e}")

def watch_directory():
    """
    Monitor the target folder for new files or folders and process them sequentially.
    """
    ip = "192.168.26.129"
    username = "mint"
    password = "ubuntu"

    # Process existing files first
    print("[INFO] Processing existing files...")
    for item in os.listdir(WATCH_FOLDER):
        file_path = os.path.join(WATCH_FOLDER, item)
        if os.path.isfile(file_path):
            process_file(file_path, username, ip, password)

    # Start watching for new files
    event_handler = WatcherHandler(username, ip, password)
    observer = Observer()
    observer.schedule(event_handler, path=WATCH_FOLDER, recursive=False)
    observer.start()

    print(f"[INFO] Watching directory: {WATCH_FOLDER}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[INFO] Monitoring stopped.")
    observer.join()

if __name__ == "__main__":
    watch_directory()
