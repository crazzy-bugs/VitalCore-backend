import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fabric import Connection
from app.database import get_db
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from flask import current_app, jsonify

results_lock = Lock()

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

# Function to test a file for viruses using ClamAV
def test_file(path, username, password, ip, avname):
    """
    Connect to a remote system, send the file, and run ClamAV scan.
    Returns a parsed scan result.
    """
    try:
        conn = Connection(
            host=ip,
            user=username,
            connect_kwargs={
                "password": password,
            },
        )
        file = os.path.basename(path)
        print("Connected to system")

        # Send the file to the remote system
        conn.put(path, file)
        print("Sent the file")

        # Run ClamAV scan, allow non-zero exit codes with `warn=True`
        # result = conn.run(f'clamdscan {file} --fdpass', warn=True)
        
        av_commands = {'defender':fr'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\{username}\{file}',
                       'eset': fr'C:\Program Files\ESET\ESET Security\ecls.exe "C:\Users\{username}\{file}"',
                       'clamav':fr'clamdscan {file} --fdpass'}

        # command = fr'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\{username}\{file}'
        command = av_commands[avname]
        result = conn.run(command)
        print("Scan Completed")

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
    # if "found no threats" in output:
        print("Scan completed: No threats detected.")
        return "Scan completed: No threats detected."
    elif ("found" in output and "threats" in output) or ("detected: files -" in output or "result=" in output) or ("Infected files" in output):
    # elif "found" in output and "threats" in output:
        print("Scan completed: Threats detected!")
        return "Scan completed: Threats detected!"
    
    for line in clam_output:
        if line.endswith("OK"):
            return "Scan completed: No threats detected."
        if "FOUND" in line:
            return "Scan completed: Threats detected!"

    # If no definitive result, return unknown status
    return "Scan result could not be parsed."
    
    # else:
    #     print("Scan result could not be parsed.")
    #     return None

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

# Insert scan results into the database
def insert_scan_results(file_path, avname, result, scan_logs):
    """
    Inserts the scan results into the database.
    """
    from app import create_app
    app = create_app()
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        query = '''
        INSERT INTO scans (filename, filepath, timestamp, avname, result, scan_logs)
        VALUES (?, ?, ?, ?, ?, ?)
        '''
        cursor.execute(query, (
            os.path.basename(file_path),
            file_path,
            int(time.time()),
            avname,
            result[0],
            scan_logs,
        ))
        db.commit()

# Event handler for new file events
class FileHandler(FileSystemEventHandler):
    def __init__(self, credentials, executor):
        self.credentials = credentials
        self.executor = executor

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, file_path):
        """
        Processes a file for virus scanning using multiple AV credentials.
        """
        with ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(test_file, file_path, cred["username"], cred["password"], cred["ipaddress"], cred["avname"])
                for cred in self.credentials
            ]
            for future, cred in zip(futures, self.credentials):
                result = future.result()
                for avname, scan_result in result.items():
                    print(f"Scan Result for {file_path} ({avname}): {scan_result}")
                    insert_scan_results(file_path, avname, scan_result, str(result))

# Function to process existing files in the folder
def process_existing_files(folder_path, credentials):
    """
    Scans all existing files in the folder.
    """
    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if os.path.isfile(file_path):
            FileHandler(credentials, None).process_file(file_path)

# Main function to monitor the folder
def monitor_folder(folder_path, credentials):
    """
    Monitors a folder for newly created files and scans them.
    """
    print("Checking existing files...")
    process_existing_files(folder_path, credentials)

    event_handler = FileHandler(credentials, None)
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=False)
    observer.start()
    print(f"Monitoring folder: {folder_path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("\nStopped monitoring.")

# Fetch recent files from the database
def get_recent_files(limit=10):
    """
    Retrieves the most recent file scan records.
    """
    db = get_db()
    cursor = db.cursor()

    query = '''
    SELECT id, file_path, file_hash, scan_status, virus_name, av_name, scan_timestamp 
    FROM files 
    ORDER BY id DESC 
    LIMIT ?
    '''
    result = cursor.execute(query, (limit,)).fetchall()

    # Convert rows to dictionary format
    return [
        {
            "id": row["id"],
            "file_path": row["file_path"],
            "file_hash": row["file_hash"],
            "scan_status": row["scan_status"],
            "virus_name": row["virus_name"],
            "av_name": row["av_name"],
            "scan_timestamp": row["scan_timestamp"],
        }
        for row in result
    ]

# Fetch the last scan results
def fetch_last_scan_results(limit=10):
    """
    Fetch the last `limit` scan results from the `scans` table.
    """
    db = get_db()
    cursor = db.cursor()

    query = '''
    SELECT id, filename, filepath, timestamp, avname, result, scan_logs, created_at, updated_at
    FROM scans
    ORDER BY id DESC
    LIMIT ?
    '''
    rows = cursor.execute(query, (limit,)).fetchall()

    # Convert rows to dictionary format
    return [
        {
            "id": row["id"],
            "filename": row["filename"],
            "filepath": row["filepath"],
            "timestamp": row["timestamp"],
            "avname": row["avname"],
            "result": row["result"],
            "scan_logs": row["scan_logs"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]

# Example usage:
# if __name__ == "__main__":
#     ip = "192.168.29.97"
#     username = "kali"
#     password = "kali"
#     watch = "D:/SIH/Target"
#     credentials = [{"username": username, "password": password, "ipaddress": ip, "avname": "ClamAV"}]
#     monitor_folder(watch, credentials)
