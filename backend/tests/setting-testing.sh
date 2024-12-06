#!/bin/bash

# Base URL for the application
BASE_URL="http://127.0.0.1:3000/settings"

# Test: Retrieve current settings
echo "Fetching current settings..."
curl -X GET "$BASE_URL" \
    -H "Content-Type: application/json" \
    -w "\n"

# Test: Update settings
echo "Updating settings..."
curl -X PUT "$BASE_URL" \
    -H "Content-Type: application/json" \
    -d '{
        "target_folder": "/path/to/target",
        "destination_folder": "/path/to/destination",
        "quarantine_folder": "/path/to/quarantine",
        "unsafe_file_action": "quarantine"
    }' \
    -w "\n"

# Test: Fetch settings after update
echo "Fetching updated settings..."
curl -X GET "$BASE_URL" \
    -H "Content-Type: application/json" \
    -w "\n"