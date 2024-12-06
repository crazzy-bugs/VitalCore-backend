#!/bin/bash

# Base URL for the API
BASE_URL="http://localhost:3000/antiviruses"

echo "Testing Antivirus Endpoints..."
echo "------------------------------"

# 1. Create a new antivirus
echo "Creating a new antivirus..."
CREATE_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{
          "av_name": "Test Antivirus",
          "ip_address": "192.168.1.1",
          "username": "admin",
          "password": "password123",
          "av_exec_command": "scan -start",
          "av_update_command": "update -start",
          "custom_field": "Custom Value"
        }' \
    $BASE_URL)
echo "Response: $CREATE_RESPONSE"

# Extract the created antivirus ID
AV_ID=$(echo $CREATE_RESPONSE | jq -r '.id')
echo "Created antivirus with ID: $AV_ID"

# 2. Get all antiviruses
echo "Fetching all antiviruses..."
curl -s -X GET $BASE_URL | jq

# 3. Get a single antivirus by ID
echo "Fetching antivirus with ID: $AV_ID..."
curl -s -X GET "$BASE_URL/$AV_ID" | jq

# 4. Update the antivirus
echo "Updating antivirus with ID: $AV_ID..."
UPDATE_RESPONSE=$(curl -s -X PUT -H "Content-Type: application/json" \
    -d '{
          "av_name": "Updated Antivirus",
          "ip_address": "192.168.1.2",
          "username": "admin_updated",
          "password": "newpassword456",
          "av_exec_command": "scan -restart",
          "av_update_command": "update -restart",
          "custom_field": "Updated Custom Value"
        }' \
    "$BASE_URL/$AV_ID")
echo "Response: $UPDATE_RESPONSE"

# 5. Delete the antivirus
echo "Deleting antivirus with ID: $AV_ID..."
DELETE_RESPONSE=$(curl -s -X DELETE "$BASE_URL/$AV_ID")
echo "Response: $DELETE_RESPONSE"

# 6. Try to fetch the deleted antivirus
echo "Fetching antivirus with ID: $AV_ID after deletion..."
curl -s -X GET "$BASE_URL/$AV_ID" | jq

echo "------------------------------"
echo "Testing completed!"
