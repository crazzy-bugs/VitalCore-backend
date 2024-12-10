import sqlite3
from contextlib import contextmanager
from flask import g

DATABASE = 'antivirus.db'

# Initialize the database and ensure tables are created
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Table for scans
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                avname TEXT DEFAULT NULL,
                result TEXT DEFAULT NULL,
                scan_logs TEXT DEFAULT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Table for notifications
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Table for antiviruses
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

        # Table for settings
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_folder TEXT NOT NULL,
                destination_folder TEXT NOT NULL,
                quarantine_folder TEXT NOT NULL,
                unsafe_file_action TEXT CHECK(unsafe_file_action IN ('delete', 'quarantine')) NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
        ''')

        # Table for files
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                file_hash TEXT,
                scan_status TEXT,
                virus_name TEXT,
                av_name TEXT,
                scan_timestamp TEXT
            )
        ''')

        conn.commit()


# Context manager for database connection
def get_db():
    """Get a database connection."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Allows rows to be returned as dictionaries
    return g.db


def fetch_latest_credentials():
    """
    Fetch the latest antivirus credentials (username, password, ip_address, av_name) from the av table.
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Query to fetch the latest credentials based on the id (descending order)
        cursor.execute("""
            SELECT username, password, ip_address, av_name 
            FROM av 
            ORDER BY id DESC 
            LIMIT 1;
        """)
        row = cursor.fetchone()
        
        if row:
            return {
                "username": row["username"],
                "password": row["password"],
                "ipaddress": row["ip_address"],
                "avname": row["av_name"]
            }
        else:
            print("No credentials found in the database.")
            return None  # If no rows exist
    except Exception as e:
        print(f"Error fetching credentials: {e}")
        return None
