from flask import Blueprint, jsonify, request
import psutil
from database import get_db
from fileMonitoring.watcher import watch_directory
import threading


# Define Blueprint
target_bp = Blueprint('target', __name__)

# Global variable to store the process object
task_thread = None
function_running = False

def function_wrapper():
    global function_running
    function_running = True
    try:
        watch_directory()  # Run the imported function
    finally:
        function_running = False

@target_bp.route('/add', methids=['POST'])
def add_target():
    data = request.json
    

# Endpoint to run the script
@target_bp.route('/run', methods=['POST'])
def run_watcher():
    global task_thread, function_running
    if function_running:
        return jsonify({"message": "Function is already running"}), 400

    # Start the function in a new thread
    task_thread = threading.Thread(target=function_wrapper)
    task_thread.start()
    return jsonify({"message": "Function started"}), 200

# Endpoint to check if the script is running
@target_bp.route('/is-running', methods=['GET'])
def is_watcher_running():
    if function_running:
        return jsonify({"message": "Function is running"}), 200
    else:
        return jsonify({"message": "Function is not running"}), 200
