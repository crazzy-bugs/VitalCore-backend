from flask import Blueprint, request, jsonify
import sqlite3
from cryptography.fernet import Fernet
import os
import json

antivirus_bp = Blueprint('antivirus', __name__)

DATABASE = 'antivirus.db'

# Key for encryption (should be securely stored)
SECRET_KEY = os.getenv('SECRET_KEY', Fernet.generate_key().decode())
fernet = Fernet(SECRET_KEY.encode())


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def encrypt(data):
    """Encrypt data using Fernet."""
    return fernet.encrypt(data.encode()).decode()


def decrypt(data):
    """Decrypt data using Fernet."""
    return fernet.decrypt(data.encode()).decode()


# Create the `av` table (run once to initialize)
@antivirus_bp.route('/init', methods=['POST'])
def init_table():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS av (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                av_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                av_exec_command TEXT,
                av_update_command TEXT,
                custom_field TEXT
            )
        ''')
        conn.commit()
    return jsonify({"message": "Table `av` initialized"}), 201


# 1. CREATE: Add a new antivirus record
@antivirus_bp.route('', methods=['POST'])
def create_antivirus():
    data = request.json
    av_name = data.get('av_name')
    ip_address = data.get('ip_address')
    username = encrypt(data.get('username'))  # Encrypt username
    password = encrypt(data.get('password'))  # Encrypt password
    av_exec_command = data.get('av_exec_command')
    av_update_command = data.get('av_update_command')
    custom_field = data.get('custom_field')

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO av (av_name, ip_address, username, password, av_exec_command, av_update_command, custom_field) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (av_name, ip_address, username, password, av_exec_command, av_update_command, custom_field))
        conn.commit()
        return jsonify({"message": "Antivirus record created", "id": cursor.lastrowid}), 201


# 2. READ: Get all antivirus records with searching, sorting, filtering, and pagination
@antivirus_bp.route('', methods=['GET'])
def get_antivirus():
    search = request.args.get('search')
    sort_by = request.args.get('sort_by', 'id')
    sort_order = request.args.get('sort_order', 'asc')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))

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
        records = []
        for row in rows:
            record = dict(row)
            record['username'] = decrypt(record['username'])  # Decrypt username
            record['password'] = decrypt(record['password'])  # Decrypt password
            records.append(record)

        cursor.execute('SELECT COUNT(*) FROM av')
        total_records = cursor.fetchone()[0]

    return jsonify({
        'records': records,
        'total_records': total_records,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_records + per_page - 1) // per_page
    })


# 3. READ: Get a single antivirus record by ID
@antivirus_bp.route('/<int:av_id>', methods=['GET'])
def get_antivirus_by_id(av_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM av WHERE id = ?', (av_id,))
        row = cursor.fetchone()
        if row is None:
            return jsonify({"error": "Antivirus record not found"}), 404
        record = dict(row)
        record['username'] = decrypt(record['username'])  # Decrypt username
        record['password'] = decrypt(record['password'])  # Decrypt password
        return jsonify(record)


# 4. UPDATE: Update an antivirus record
@antivirus_bp.route('/<int:av_id>', methods=['PUT'])
def update_antivirus(av_id):
    data = request.json
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM av WHERE id = ?', (av_id,))
        if cursor.fetchone() is None:
            return jsonify({"error": "Antivirus record not found"}), 404

        # Update fields
        updates = {
            "av_name": data.get('av_name'),
            "ip_address": data.get('ip_address'),
            "username": encrypt(data.get('username')) if data.get('username') else None,
            "password": encrypt(data.get('password')) if data.get('password') else None,
            "av_exec_command": data.get('av_exec_command'),
            "av_update_command": data.get('av_update_command'),
            "custom_field": data.get('custom_field'),
        }

        for key, value in updates.items():
            if value is not None:
                cursor.execute(f'UPDATE av SET {key} = ? WHERE id = ?', (value, av_id))
        conn.commit()
        return jsonify({"message": "Antivirus record updated"})


# 5. DELETE: Delete an antivirus record
@antivirus_bp.route('/<int:av_id>', methods=['DELETE'])
def delete_antivirus(av_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM av WHERE id = ?', (av_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Antivirus record not found"}), 404
        return jsonify({"message": "Antivirus record deleted"})


# Endpoint to fetch encryption key (for development/debugging only; disable in production)
@antivirus_bp.route('/get-key', methods=['GET'])
def get_key():
    return jsonify({"key": SECRET_KEY})
