from . import antivirus_bp
from flask import jsonify, request, stream_with_context
from .services import (
    create_antivirus,
    fetch_all_antivirus,
    fetch_antivirus_by_id,
    update_antivirus_record,
    delete_antivirus_record,
    ping_vm,
    test_file
)


@antivirus_bp.route('/add', methods=['POST'])
def add_av():
    data = request.json
    safe_path = r"D:\Repositories\new-sih\testfiles\test.py"
    malicious_path = r"D:\Repositories\new-sih\testfiles\testing.exe"
    if create_antivirus(data):
        if ping_vm(data.get('ip_address')):
            safe_result = test_file(data,safe_path)
            # malicious_result = test_file(data,malicious_path)
            malicious_result = False
            if (safe_result == True and malicious_result == False):
                return {"status": True, "message": "Added Succesfully", "safe_result": safe_result, "malicious_result": malicious_result}, 200
            else:
                return {"status": False, "message": "Tests failed", "safe_result": safe_result, "malicious_result": malicious_result}
        else:
            return {"status": False, "message": "System not reachable", "safe_result": "", "malicious_result": ""}, 400
    else:
        return {"status": False, "message": "Failed to add system", "safe_result": "", "malicious_result": ""}, 400

# @antivirus_bp.route('/status', methods=['GET'])
#     data = request.json
# def av_status(data)

@antivirus_bp.route('/fetch/all', methods=['GET'])
def fetch_av():
    search = request.args.get('search')
    sort_by = request.args.get('sort_by', 'id')
    sort_order = request.args.get('sort_order', 'asc')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    result = fetch_all_antivirus(search, sort_by, sort_order, page, per_page)
    return jsonify(result)


@antivirus_bp.route('/fetch/<int:av_id>', methods=['GET'])
def get_antivirus_by_id(av_id):
    result, status = fetch_antivirus_by_id(av_id)
    return jsonify(result), status


@antivirus_bp.route('/update/<int:av_id>', methods=['PUT'])
def update_antivirus(av_id):
    data = request.json
    result, status = update_antivirus_record(av_id, data)
    return jsonify(result), status


@antivirus_bp.route('/delete/<int:av_id>', methods=['DELETE'])
def delete_antivirus(av_id):
    result, status = delete_antivirus_record(av_id)
    return jsonify(result), status


# from . import antivirus_bp
# from flask import jsonify, request
# from app.database import get_db


# @antivirus_bp.route('/add', methods=['POST'])
# def add_av():
#     data = request.json
#     av_name = data.get('av_name')
#     ip_address = data.get('ip_address')
#     username = data.get('username')
#     password = data.get('password')
#     av_exec_command = data.get('av_exec_command')
#     av_update_command = data.get('av_update_command')
#     custom_field = data.get('custom_field')

#     with get_db() as conn:
#         cursor = conn.cursor()
#         cursor.execute('''
#             INSERT INTO av (av_name, ip_address, username, password, av_exec_command, av_update_command, custom_field) 
#             VALUES (?, ?, ?, ?, ?, ?, ?)
#         ''', (av_name, ip_address, username, password, av_exec_command, av_update_command, custom_field))
#         conn.commit()
#         return jsonify({"message": "Antivirus record created", "id": cursor.lastrowid}), 201

# @antivirus_bp.route('/fetch/all', methods=['GET'])
# def fetch_av():
#     search = request.args.get('search')
#     sort_by = request.args.get('sort_by', 'id')
#     sort_order = request.args.get('sort_order', 'asc')
#     page = int(request.args.get('page', 1))
#     per_page = int(request.args.get('per_page', 10))

#     query = 'SELECT * FROM av'
#     params = []

#     if search:
#         query += ' WHERE av_name LIKE ? OR ip_address LIKE ? OR custom_field LIKE ?'
#         search_term = f'%{search}%'
#         params.extend([search_term, search_term, search_term])

#     query += f' ORDER BY {sort_by} {sort_order.upper()}'
#     query += ' LIMIT ? OFFSET ?'
#     params.extend([per_page, (page - 1) * per_page])

#     with get_db() as conn:
#         cursor = conn.cursor()
#         cursor.execute(query, params)
#         rows = cursor.fetchall()
#         records = []
#         for row in rows:
#             record = dict(row)
#             record['username'] = record['username']
#             record['password'] = record['password']
#             records.append(record)

#         cursor.execute('SELECT COUNT(*) FROM av')
#         total_records = cursor.fetchone()[0]

#     return jsonify({
#         'records': records,
#         'total_records': total_records,
#         'page': page,
#         'per_page': per_page,
#         'total_pages': (total_records + per_page - 1) // per_page
#     })



# @antivirus_bp.route('/fetch/<int:av_id>', methods=['GET'])
# def get_antivirus_by_id(av_id):
#     with get_db() as conn:
#         cursor = conn.cursor()
#         cursor.execute('SELECT * FROM av WHERE id = ?', (av_id,))
#         row = cursor.fetchone()
#         if row is None:
#             return jsonify({"error": "Antivirus record not found"}), 404
#         record = dict(row)
#         record['username'] = record['username']
#         record['password'] = record['password']
#         return jsonify(record)



# @antivirus_bp.route('/update/<int:av_id>', methods=['PUT'])
# def update_antivirus(av_id):
#     data = request.json
#     with get_db() as conn:
#         cursor = conn.cursor()
#         cursor.execute('SELECT * FROM av WHERE id = ?', (av_id,))
#         if cursor.fetchone() is None:
#             return jsonify({"error": "Antivirus record not found"}), 404

#         updates = {
#             "av_name": data.get('av_name'),
#             "ip_address": data.get('ip_address'),
#             "username": data.get('username') if data.get('username') else None,
#             "password": data.get('password') if data.get('password') else None,
#             "av_exec_command": data.get('av_exec_command'),
#             "av_update_command": data.get('av_update_command'),
#             "custom_field": data.get('custom_field'),
#         }

#         for key, value in updates.items():
#             if value is not None:
#                 cursor.execute(f'UPDATE av SET {key} = ? WHERE id = ?', (value, av_id))
#         conn.commit()
#         return jsonify({"message": "Antivirus record updated"})


# @antivirus_bp.route('/delete/<int:av_id>', methods=['DELETE'])
# def delete_antivirus(av_id):
#     with get_db() as conn:
#         cursor = conn.cursor()
#         cursor.execute('DELETE FROM av WHERE id = ?', (av_id,))
#         conn.commit()
#         if cursor.rowcount == 0:
#             return jsonify({"error": "Antivirus record not found"}), 404
#         return jsonify({"message": "Antivirus record deleted"})