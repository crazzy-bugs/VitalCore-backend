from flask import Blueprint, jsonify, request
import threading
from .services import monitor_folder, get_recent_files, fetch_last_scan_results
from . import target_bp

# Global variable to store the process object
task_thread = None
function_running = False

# Endpoint to run the script
@target_bp.route('/run', methods=['POST'])
def run_watcher():
    global task_thread, function_running
    if function_running:
        return jsonify({"message": "Function is already running"}), 400

    function_running = True
    # Replace with your target folder path
    target_folder = "D:/SIH/Target"

# Replace with your array of credentials
    credentials = [
    {"username": "kali", "password": "kali", "ipaddress": "192.168.29.97", "avname": "ClamAV"}
    ]
    # Start the function in a new thread
    task_thread = threading.Thread(target=monitor_folder, args=(target_folder, credentials))
    task_thread.start()
    return jsonify({"message": "Function started"}), 200

# Endpoint to check if the script is running
@target_bp.route('/is-running', methods=['GET'])
def is_watcher_running():
    if function_running:
        return jsonify({"message": "Function is running"}), 200
    else:
        return jsonify({"message": "Function is not running"}), 200
    
@target_bp.route('/fetchLastTen', methods=['GET'])
def fetchLastTen():
    files = get_recent_files()
    return jsonify(files)

@target_bp.route('/latest', methods=['GET'])
def get_latest_scans():
    """
    Endpoint to fetch the last 10 scan results.
    """
    try:
        results = fetch_last_scan_results(limit=10)
        return jsonify({"success": True, "data": results}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

