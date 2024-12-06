from flask import Blueprint, request, jsonify
from database import get_db

scans_bp = Blueprint('scans', __name__)

@scans_bp.route('', methods=['POST'])
def create_scan():
    data = request.json
    filename = data.get('filename')
    location = data.get('location')
    timestamp = data.get('timestamp')

    if not filename or not location or not timestamp:
        return jsonify({"error": "Missing required fields"}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO scans (filename, location, timestamp) 
               VALUES (?, ?, ?)''', 
            (filename, location, timestamp)
        )
        conn.commit()
        return jsonify({"message": "Scan created", "id": cursor.lastrowid}), 201

@scans_bp.route('', methods=['GET'])
def get_scans():
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'ASC')
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))
    offset = (page - 1) * limit

    filters = {
        'filename': request.args.get('filename'),
        'location': request.args.get('location'),
        'timestamp': request.args.get('timestamp')
    }

    query = 'SELECT * FROM scans WHERE 1=1'
    params = []

    if search:
        query += ' AND (filename LIKE ? OR location LIKE ?)'
        params.extend([f"%{search}%", f"%{search}%"])

    for field, value in filters.items():
        if value:
            query += f' AND {field} = ?'
            params.append(value)

    if sort:
        query += f' ORDER BY {sort} {order}'
    query += ' LIMIT ? OFFSET ?'
    params.extend([limit, offset])

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return jsonify([dict(row) for row in rows])

@scans_bp.route('/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    fields = request.args.get('fields', '*')
    query = f'SELECT {fields} FROM scans WHERE id = ?'

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (scan_id,))
        row = cursor.fetchone()
        if row:
            return jsonify(dict(row))
        return jsonify({"error": "Scan not found"}), 404

@scans_bp.route('/<int:scan_id>', methods=['PUT'])
def update_scan(scan_id):
    data = request.json
    result = data.get('result')
    final_result = data.get('final_result')
    scan_logs = data.get('scan_logs')

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''UPDATE scans 
               SET result = ?, final_result = ?, scan_logs = ?, updated_at = datetime('now') 
               WHERE id = ?''', 
            (result, final_result, scan_logs, scan_id)
        )
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify({"message": "Scan updated"})

@scans_bp.route('/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify({"message": "Scan deleted"})
