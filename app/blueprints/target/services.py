import os
import time
import json
import threading
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fabric import Connection
from app.database import get_db
from concurrent.futures import ThreadPoolExecutor
from flask import current_app, jsonify

class FolderScanTracker:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(FolderScanTracker, cls).__new__(cls)
                    cls._instance.total_files = 0
                    cls._instance.scanned_files = 0
                    cls._instance.current_scan_files = 0
                    cls._instance.scan_results = {}
        return cls._instance

    def add_total_files(self, count):
        with self._lock:
            self.total_files += count

    def reset_current_scan(self):
        with self._lock:
            self.current_scan_files = 0
            self.scan_results = {}

    def update_scan_progress(self, file_path, av_results):
        with self._lock:
            if file_path not in self.scan_results:
                self.current_scan_files += 1
                self.scanned_files += 1
                self.scan_results[file_path] = av_results

            # Check if this file has been scanned by all AV
            if len(av_results) == len(fetch_latest_credentials()):
                # Determine final result
                final_result = self.determine_final_result(av_results)
                
                # Update database with comprehensive results
                self.insert_comprehensive_scan_results(
                    file_path, 
                    json.dumps(av_results),  # Store AV results as JSON string
                    final_result
                )

                # Optionally, trigger a frontend notification here
                notify_frontend_scan_progress()

    def determine_final_result(self, av_results):
        # Logic to determine final result based on AV scans
        if any(result.lower() == "scan completed: threats detected!" for result in av_results.values()):
            return "Unsafe"
        return "Safe"

    def insert_comprehensive_scan_results(self, file_path, av_results_json, final_result):
        """
        Inserts comprehensive scan results into the database.
        """
        from app import create_app
        app = create_app()
        with app.app_context():
            db = get_db()
            cursor = db.cursor()

            query = '''
            INSERT INTO scans (
                filename, 
                filepath, 
                timestamp, 
                av_results, 
                final_result
            ) VALUES (?, ?, ?, ?, ?)
            '''
            cursor.execute(query, (
                os.path.basename(file_path),
                file_path,
                int(time.time()),
                av_results_json,  # JSON string of AV results
                final_result
            ))
            db.commit()

def changed_target(data):
    target_folder = data.get('target_folder')
    quarantine_folder = data.get('quarantine_folder')
    unsafe_file_action = data.get('unsafe_file_action')    

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE settings
            SET target_folder = ?, 
                quarantine_folder = ?, 
                unsafe_file_action = ?
            WHERE id = 1
        ''', (target_folder, quarantine_folder, unsafe_file_action))

def fetch_target_details():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM settings WHERE id = 1')
        result = cursor.fetchone()
        
        if result:
            data = {
                "id": result[0],
                "target_folder": result[1],
                "quarantine_folder": result[2],
                "unsafe_file_action": result[3],
                "created_at": result[4]
            }
            return jsonify(data), 200
        else:
            return jsonify({"error": "No target added"}), 404

def create_target(data):
    target_folder = data.get('target_folder')
    quarantine_folder = data.get('quarantine_folder')
    unsafe_file_action = data.get('unsafe_file_action')

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO settings (target_folder, quarantine_folder, unsafe_file_action) 
            VALUES (?, ?, ?)
        """, (target_folder, quarantine_folder, unsafe_file_action))
        conn.commit()
        return {"message": "Target created", "id": cursor.lastrowid}

def test_file(path, username, password, ip, avname):
    try:
        conn = Connection(
            host=ip,
            user=username,
            connect_kwargs={"password": password},
        )
        # Use os.path.basename and properly quote the path
        file = os.path.basename(path)
        quoted_local_path = f'"{path}"'
        # quoted_remote_file = f'"{os.path.join("C:/Users", username, file)}"'
        print("Connected to system")

        # Send the file to the remote system with proper quoting
        conn.put(path, file)
        print("Sent the file")

        av_commands = {
            'defender': fr'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\{username}\{file}',
            'eset': fr'"C:\Program Files\ESET\ESET Security\ecls.exe" C:\Users\{username}\{file}',
            'clamav': f'clamdscan "{file}" --fdpass',
            'avg': f'docker run --rm -v "/home/{username}":/malware malice/avg /malware/"{file}"',
            'fsecure': fr'"C:\Program Files\F-Secure\TOTAL\fsscan.exe" C:\Users\{username}\{file}'
        }

        command = av_commands[avname]
        result = conn.run(command)
        print("Scan Completed")
        output = result.stdout.strip()

        # AVG JSON parsing
        if output.startswith('{') and output.endswith('}'):
            parsed_result = parse_avg_output(output)
            return {avname: parsed_result}

        # Parse and return the result
        parsed_result = parse_output(result)
        return {avname: parsed_result}

    except Exception as e:
        print(f"[ERROR] Exception occurred while scanning file {path}: {e}")
        return {avname: ("error", str(e))}

def parse_output(result):
    output = result.stdout.strip().lower()
    clam_output = result.stdout.strip().splitlines()
    if ("found no threats" in output) or ("detected: files - 0" in output and "objects 0" in output) or ("Infected files: 0" in output and "OK" in output):
        print("Scan completed: No threats detected.")
        return "Scan completed: No threats detected."
    elif ("found" in output and "threats" in output) or ("detected: files -" in output or "result=" in output) or ("Infected files" in output):
        print("Scan completed: Threats detected!")
        return "Scan completed: Threats detected!"
    
    for line in clam_output:
        if line.endswith("OK"):
            return "Scan completed: No threats detected."
        if "FOUND" in line:
            return "Scan completed: Threats detected!"
    
    for line in clam_output:
        if "detected: files -" in line or "cleaned: files -" in line:
            if not line.endswith("0"):
                print("Scan completed: Threats detected!")
                return "Scan completed: Threats detected!"

    return "Scan completed: No threats detected."

def parse_avg_output(output):
    try:
        import json
        avg_result = json.loads(output)
        if not avg_result.get('avg', {}).get('infected', False):
            return "Scan completed: No threats detected."
    except json.JSONDecodeError:
        infected_pattern = r'Found\s+.*'
        if re.search(infected_pattern, output):
            return "Scan completed: Threats detected!"
        return "Scan completed: No threats detected."

class FileHandler(FileSystemEventHandler):
    def __init__(self, credentials, executor):
        self.credentials = credentials
        self.executor = executor
        self.scan_tracker = FolderScanTracker()

    def on_created(self, event):
        if not event.is_directory:
            # Ensure full path is used, handling spaces correctly
            self.process_file(os.path.abspath(event.src_path))
        elif event.is_directory:
            # When a new directory is added, count its files with proper path handling
            total_files = count_files_recursively(os.path.abspath(event.src_path))
            self.scan_tracker.add_total_files(total_files)
            notify_frontend_total_files(total_files)

    def process_file(self, file_path):
        # Ensure file_path is absolute and handles spaces
        file_path = os.path.abspath(file_path)
        
        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(test_file, file_path, cred["username"], cred["password"], cred["ipaddress"], cred["avname"])
                for cred in self.credentials
            ]
            av_results = {}
            for future, cred in zip(futures, self.credentials):
                result = future.result()
                for avname, scan_result in result.items():
                    print(f"Scan Result for {file_path} ({avname}): {scan_result}")
                    av_results[avname] = scan_result

            # Update scan progress
            self.scan_tracker.update_scan_progress(file_path, av_results)

def count_files_recursively(folder_path):
    total_files = 0
    # Use os.walk with proper handling of paths with spaces
    for root, dirs, files in os.walk(folder_path):
        # Handle files with spaces
        total_files += len(files)
    return total_files

def process_existing_files(folder_path, credentials):
    scan_tracker = FolderScanTracker()
    scan_tracker.reset_current_scan()

    # Count total files with proper path handling
    total_files = count_files_recursively(folder_path)
    scan_tracker.add_total_files(total_files)
    notify_frontend_total_files(total_files)

    for root, dirs, files in os.walk(folder_path):
        for file_name in files:
            # Use os.path.join to handle paths with spaces correctly
            file_path = os.path.join(root, file_name)
            if os.path.isfile(file_path):
                FileHandler(credentials, None).process_file(file_path)

def monitor_folder(folder_path, credentials):
    print("Checking existing files...")
    process_existing_files(folder_path, credentials)

    event_handler = FileHandler(credentials, None)
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=True)
    observer.start()
    print(f"Monitoring folder: {folder_path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("\nStopped monitoring.")

def notify_frontend_total_files(total_files):
    """
    Placeholder for frontend notification about total files.
    In a real implementation, use WebSockets or server-sent events.
    """
    print(f"Total files to scan: {total_files}")

def notify_frontend_scan_progress():
    """
    Placeholder for frontend notification about scan progress.
    """
    scan_tracker = FolderScanTracker()
    print(f"Scanned {scan_tracker.scanned_files} of {scan_tracker.total_files} files")

def fetch_last_scan_results(limit=10):
    """
    Fetch the last `limit` comprehensive scan results.
    """
    db = get_db()
    cursor = db.cursor()

    query = '''
    SELECT id, filename, filepath, timestamp, av_results, final_result
    FROM scans
    ORDER BY id DESC
    LIMIT ?
    '''
    rows = cursor.execute(query, (limit,)).fetchall()

    # Convert rows to dictionary format with parsed AV results
    return [
        {
            "id": row["id"],
            "filename": row["filename"],
            "filepath": row["filepath"],
            "timestamp": row["timestamp"],
            "av_results": json.loads(row["av_results"]),
            "final_result": row["final_result"],
        }
        for row in rows
    ]

def fetch_latest_credentials():
    # Connect to the database
    from app import create_app
    app = create_app()
    with app.app_context():
        db= get_db()
        cursor = db.cursor()

        # Fetch all records from the table
        cursor.execute('''
            SELECT av_name, ip_address, username, password, av_exec_command, av_update_command, custom_field
            FROM av
            ORDER BY id DESC
        ''')
        
        rows = cursor.fetchall()
        
        credentials = [
            {
                "av_name": row[0],
                "ip_address": row[1],
                "username": row[2],
                "password": row[3],
                "av_exec_command": row[4],
                "av_update_command": row[5],
                "custom_field": row[6],
            } for row in rows

        ]
        
        return credentials if credentials else None
