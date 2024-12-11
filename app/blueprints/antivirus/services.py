from app.database import get_db
import subprocess
import platform
from fabric import Connection
import os
import json

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
        return {"message": "Antivirus record created", "id": cursor.lastrowid}

def ping_vm(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', host]
    response = subprocess.call(command)

    if response == 0:
        return "System is reachable"
    else:
        return "System is not reachable"


def test_file(data, path):
    avname = data.get('av_name')
    ip = data.get('ip_address')
    username = data.get('username')
    password = data.get('password')
    av_exec_command = data.get('av_exec_command')
    conn = Connection(
        host=ip,
        user=username,
        connect_kwargs={
            "password": password,
        },
    )
    file = os.path.basename(path)
    print("Connected to system")

    conn.put(path, file)
    print("Sent the file")
    # result = conn.run(f'clamdscan {file} --fdpass')
    # av_commands = {"defender":fr'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\{username}\{file}', "clamav":f'clamdscan {file} --fdpass'}
    # command = fr'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\{username}\{file}'
    av_commands = {'defender':fr'"C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\{username}\{file}',
                       'eset': fr'C:\Program Files\ESET\ESET Security\ecls.exe "C:\Users\{username}\{file}"',
                       'clamav':fr'clamdscan {file} --fdpass'}
    
    command = av_commands[avname]
    result = conn.run(command)
    print(result.stdout)
    parsed_result = parse_output(result)
    return parsed_result
    
def parse_output(result):
    output = result.stdout.strip().lower()
    if ("found no threats" in output) or ("detected: files - 0" in output and "objects 0" in output):
    # if "found no threats" in output:
        print("Scan completed: No threats detected.")
        return True
    elif ("found" in output and "threats" in output) or ("detected: files -" in output or "result=" in output):
    # elif "found" in output and "threats" in output:
        print("Scan completed: Threats detected!")
        return False
    else:
        print("Scan result could not be parsed.")
        return None

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
