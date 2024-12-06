from flask import Blueprint, request, jsonify
from database import get_db

settings_bp = Blueprint('settings', __name__)

# Retrieve application settings
@settings_bp.route('', methods=['GET'])
def get_settings():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM settings ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        if row:
            return jsonify(dict(row))
        return jsonify({"error": "Settings not found"}), 404


# Update application settings
@settings_bp.route('', methods=['PUT'])
def update_settings():
    data = request.json
    target_folder = data.get('target_folder')
    destination_folder = data.get('destination_folder')
    quarantine_folder = data.get('quarantine_folder')
    unsafe_file_action = data.get('unsafe_file_action')

    if not target_folder or not destination_folder or not quarantine_folder or not unsafe_file_action:
        return jsonify({"error": "Missing required fields"}), 400

    if unsafe_file_action not in ['delete', 'quarantine']:
        return jsonify({"error": "Invalid action for unsafe files. Choose 'delete' or 'quarantine'"}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO settings (target_folder, destination_folder, quarantine_folder, unsafe_file_action, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        ''', (target_folder, destination_folder, quarantine_folder, unsafe_file_action))
        conn.commit()
        return jsonify({"message": "Settings updated successfully", "id": cursor.lastrowid}), 200
