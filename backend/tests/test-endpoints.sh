#!/bin/bash

BASE_URL="http://localhost:3000"

echo "Testing routes on $BASE_URL"
echo "---------------------------"

# Helper function to parse JSON response
parse_json() {
  echo "$1" | jq -r "$2" 2>/dev/null || echo ""
}

# 1. Test creating a scan
echo "Creating a new scan..."
SCAN_RESPONSE=$(curl -s -X POST "$BASE_URL/scans" \
  -H "Content-Type: application/json" \
  -d '{"filename": "test_file.txt", "location": "/path/to/file", "timestamp": 1672502400}')

echo "Response: $SCAN_RESPONSE"
SCAN_ID=$(parse_json "$SCAN_RESPONSE" '.id')
if [ -z "$SCAN_ID" ]; then
  echo "Failed to create a scan. Skipping further scan tests."
else
  echo "Created scan with ID: $SCAN_ID"

  # 2. Test fetching all scans
  echo "Fetching all scans..."
  ALL_SCANS=$(curl -s "$BASE_URL/scans")
  echo "Response: $ALL_SCANS"

  # 3. Test fetching a scan by ID
  echo "Fetching scan by ID: $SCAN_ID..."
  SCAN_BY_ID=$(curl -s "$BASE_URL/scans/$SCAN_ID")
  echo "Response: $SCAN_BY_ID"

  # 4. Test updating a scan
  echo "Updating scan ID: $SCAN_ID..."
  UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/scans/$SCAN_ID" \
    -H "Content-Type: application/json" \
    -d '{"result": "clean", "final_result": "clean", "scan_logs": "Scan completed successfully"}')
  echo "Response: $UPDATE_RESPONSE"

  # 5. Test deleting a scan
  echo "Deleting scan ID: $SCAN_ID..."
  DELETE_RESPONSE=$(curl -s -X DELETE "$BASE_URL/scans/$SCAN_ID")
  echo "Response: $DELETE_RESPONSE"
fi

# 6. Test creating a notification
echo "Creating a new notification..."
NOTIFICATION_RESPONSE=$(curl -s -X POST "$BASE_URL/notifications" \
  -H "Content-Type: application/json" \
  -d '{"title": "New Scan Alert", "body": "A new scan has been added"}')

echo "Response: $NOTIFICATION_RESPONSE"
NOTIFICATION_ID=$(parse_json "$NOTIFICATION_RESPONSE" '.notification.id')
if [ -z "$NOTIFICATION_ID" ]; then
  echo "Failed to create a notification. Skipping further notification tests."
else
  echo "Created notification with ID: $NOTIFICATION_ID"

  # 7. Test fetching all notifications
  echo "Fetching all notifications..."
  ALL_NOTIFICATIONS=$(curl -s "$BASE_URL/notifications")
  echo "Response: $ALL_NOTIFICATIONS"

  # 8. Test marking a notification as read
  echo "Marking notification ID: $NOTIFICATION_ID as read..."
  MARK_READ_RESPONSE=$(curl -s -X PUT "$BASE_URL/notifications/$NOTIFICATION_ID/read")
  echo "Response: $MARK_READ_RESPONSE"

  # 9. Test deleting a notification
  echo "Deleting notification ID: $NOTIFICATION_ID..."
  DELETE_NOTIFICATION_RESPONSE=$(curl -s -X DELETE "$BASE_URL/notifications/$NOTIFICATION_ID")
  echo "Response: $DELETE_NOTIFICATION_RESPONSE"
fi

# 10. Test SSE for notifications
echo "Starting SSE stream for notifications..."
curl -N "$BASE_URL/notifications/stream" &
SSE_PID=$!
sleep 5

echo "Sending new notification during SSE stream..."
SSE_NOTIFICATION_RESPONSE=$(curl -s -X POST "$BASE_URL/notifications" \
  -H "Content-Type: application/json" \
  -d '{"title": "Real-time Alert", "body": "This is a live SSE test"}')

echo "SSE Response: $SSE_NOTIFICATION_RESPONSE"

# Allow SSE stream to process
sleep 5
kill $SSE_PID

echo "---------------------------"
echo "Testing completed!"