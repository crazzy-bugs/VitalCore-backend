from flask import jsonify, request
import threading
from .services import monitor_folder, get_recent_files, fetch_last_scan_results, create_target
from app.database import fetch_latest_credentials, fetch_target_folder  # Import fetch functions
from . import target_bp

# Global variable to store the process object
task_thread = None
function_running = False


@target_bp.route('/add', methods=['POST'])
def add_av():
    data = request.json
    return create_target(data)

# Endpoint to run the script
@target_bp.route('/run', methods=['POST'])
def run_watcher():
    global task_thread, function_running
    if function_running:
        return jsonify({"message": "Function is already running"}), 400

    # Fetch the target folder dynamically from the database
    target_folder = fetch_target_folder()
    if not target_folder:
        return jsonify({"message": "No target folder found in the database"}), 500

    # Fetch credentials dynamically from the database
    credentials = fetch_latest_credentials()
    if not credentials:
        return jsonify({"message": "No credentials found in the database"}), 500

    function_running = True

    # Start the function in a new thread
    task_thread = threading.Thread(target=monitor_folder, args=(target_folder, [credentials]))
    task_thread.start()
    return jsonify({"message": "Function started", "target_folder": target_folder, "credentials": credentials}), 200

# Endpoint to check if the script is running
@target_bp.route('/is-running', methods=['GET'])
def is_watcher_running():
    if function_running:
        return jsonify({"message": "Function is running"}), 200
    else:
        return jsonify({"message": "Function is not running"}), 200

# Endpoint to fetch the last 10 recent files
@target_bp.route('/fetchLastTen', methods=['GET'])
def fetchLastTen():
    try:
        files = get_recent_files()
        return jsonify({"success": True, "data": files}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Endpoint to fetch the latest scan results
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
