# Antivirus Management API

This is a Flask-based RESTful API for managing antivirus configurations, scans, and notifications. It supports CRUD operations with secure encryption for sensitive data like usernames and passwords.

---

## Features

- Manage antivirus configurations with encrypted credentials.
- Server-sent events for notifications.
- CRUD operations for scans and notifications.
- SQLite database for persistent storage.

---

## Requirements

- Python 3.7+
- SQLite
- Flask
- Cryptography library

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/antivirus-management-api.git
cd antivirus-management-api
```

### 2. Set Up a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Running the Application

Start the Flask development server:

```bash
python3 app.py
```

The API will be available at [http://127.0.0.1:3000](http://127.0.0.1:3000).

---

## API Endpoints

### Antivirus (/antiviruses)

- **POST /antiviruses**: Create a new antivirus entry.
- **GET /antiviruses**: Retrieve all antivirus entries.
- **GET /antiviruses/{id}**: Retrieve a specific antivirus entry by ID.
- **PUT /antiviruses/{id}**: Update an antivirus entry.
- **DELETE /antiviruses/{id}**: Delete an antivirus entry.

### Scans (/scans)

- Similar CRUD operations as above. Run the provided shell script to test the antivirus endpoints:

### Notifications (/notifications)

- Similar CRUD operations as above.
- **GET /notifications/stream**: Stream real-time notifications.

---

## Testing the API

### Using `av-endpoints.sh`

Run the provided shell script to test the antivirus endpoints:

````bash
chmod +x av-endpoints.sh
./av-endpoints.sh
```ints.sh
./av-endpoints.sh
````
