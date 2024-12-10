from flask import jsonify
import threading
from .services import monitor_folder, get_recent_files, fetch_last_scan_results
from app.database import fetch_latest_credentials  # Import the function to fetch credentials
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
    target_folder = "D:/Test/hello"

    # Fetch credentials dynamically from the database
    credentials = fetch_latest_credentials()
    if not credentials:
        function_running = False
        return jsonify({"message": "No credentials found in the database"}), 500

    # Start the function in a new thread
    task_thread = threading.Thread(target=monitor_folder, args=(target_folder, [credentials]))
    task_thread.start()
    return jsonify({"message": "Function started", "credentials": credentials}), 200

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
