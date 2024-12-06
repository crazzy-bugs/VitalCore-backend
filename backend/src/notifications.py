from flask import Blueprint, request, jsonify, Response
import sqlite3
import json
from threading import Lock
import queue

notifications_bp = Blueprint('notifications', __name__)

DATABASE = 'antivirus.db'

# Store active SSE clients
clients = []
clients_lock = Lock()  # Lock to manage client list updates safely


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def send_notification_event(notification):
    """
    Broadcast a notification event to all connected clients.
    """
    with clients_lock:
        for client in clients:
            try:
                client.put(f"data: {json.dumps(notification)}\n\n")
            except Exception:
                clients.remove(client)  # Remove client if there's an issue


# 1. CREATE: Add a new notification
@notifications_bp.route('', methods=['POST'])
def create_notification():
    data = request.json
    title = data.get('title')
    body = data.get('body')

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO notifications (title, body) 
               VALUES (?, ?)''',
            (title, body)
        )
        conn.commit()
        notification = {
            "id": cursor.lastrowid,
            "title": title,
            "body": body,
            "is_read": 0,
        }
        send_notification_event(notification)
        return jsonify({"message": "Notification created", "notification": notification}), 201


# 2. READ: Get all notifications
@notifications_bp.route('', methods=['GET'])
def get_notifications():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM notifications ORDER BY created_at DESC')
        rows = cursor.fetchall()
        return jsonify([dict(row) for row in rows])


# 3. UPDATE: Mark a notification as read
@notifications_bp.route('/<int:notification_id>/read', methods=['PUT'])
def mark_notification_as_read(notification_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''UPDATE notifications 
               SET is_read = 1 
               WHERE id = ?''',
            (notification_id,)
        )
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Notification not found"}), 404
        return jsonify({"message": "Notification marked as read"})


# 4. DELETE: Delete a notification
@notifications_bp.route('/<int:notification_id>', methods=['DELETE'])
def delete_notification(notification_id):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM notifications WHERE id = ?', (notification_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return jsonify({"error": "Notification not found"}), 404
        return jsonify({"message": "Notification deleted"})


# 5. Server-Sent Events: Stream notifications
@notifications_bp.route('/stream', methods=['GET'])
def stream_notifications():
    def event_stream():
        q = queue.Queue(maxsize=10)  # Use a queue for event delivery
        with clients_lock:
            clients.append(q)
        try:
            while True:
                data = q.get()
                yield data
        except GeneratorExit:
            with clients_lock:
                clients.remove(q)

    return Response(event_stream(), content_type='text/event-stream')
