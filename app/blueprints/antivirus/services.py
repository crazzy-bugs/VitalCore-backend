from app.database import get_db


def create_antivirus(data):
    av_name = data.get('av_name')
    ip_address = data.get('ip_address')
    username = data.get('username')
    password = data.get('password')
    av_exec_command = data.get('av_exec_command')
    av_update_command = data.get('av_update_command')
    custom_field = data.get('custom_field')

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO av (av_name, ip_address, username, password, 
            av_exec_command, av_update_command, custom_field) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (av_name, ip_address, username, password, av_exec_command, av_update_command, custom_field))
        conn.commit()
        return {"message": "Antivirus record created", "id": cursor.lastrowid}, 201


def fetch_all_antivirus(search, sort_by, sort_order, page, per_page):
    query = 'SELECT * FROM av'
    params = []

    if search:
        query += ' WHERE av_name LIKE ? OR ip_address LIKE ? OR custom_field LIKE ?'
        search_term = f'%{search}%'
        params.extend([search_term, search_term, search_term])

    query += f' ORDER BY {sort_by} {sort_order.upper()}'
    query += ' LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        records = [dict(row) for row in rows]

        cursor.execute('SELECT COUNT(*) FROM av')
        total_records = cursor.fetchone()[0]

    return {
        'records': records,
        'total_records': total_records,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_records + per_page - 1) // per_page,
    }


def fetch_antivirus_by_id(av_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM av WHERE id = ?', (av_id,))
        row = cursor.fetchone()
        if row is None:
            return {"error": "Antivirus record not found"}, 404
        return dict(row), 200


def update_antivirus_record(av_id, data):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM av WHERE id = ?', (av_id,))
        if cursor.fetchone() is None:
            return {"error": "Antivirus record not found"}, 404

        updates = {
            "av_name": data.get('av_name'),
            "ip_address": data.get('ip_address'),
            "username": data.get('username'),
            "password": data.get('password'),
            "av_exec_command": data.get('av_exec_command'),
            "av_update_command": data.get('av_update_command'),
            "custom_field": data.get('custom_field'),
        }

        for key, value in updates.items():
            if value is not None:
                cursor.execute(f'UPDATE av SET {key} = ? WHERE id = ?', (value, av_id))
        conn.commit()
        return {"message": "Antivirus record updated"}, 200


def delete_antivirus_record(av_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM av WHERE id = ?', (av_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return {"error": "Antivirus record not found"}, 404
        return {"message": "Antivirus record deleted"}, 200
