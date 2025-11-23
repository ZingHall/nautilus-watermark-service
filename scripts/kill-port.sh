#!/bin/bash
# Kill process running on a specific port

PORT="${1:-8080}"

if [ -z "$PORT" ]; then
    echo "Usage: $0 <port>"
    echo "Example: $0 8080"
    exit 1
fi

echo "🔍 Looking for process on port $PORT..."

PIDS=$(lsof -ti:$PORT 2>/dev/null)

if [ -z "$PIDS" ]; then
    echo "✅ No process found on port $PORT"
    exit 0
fi

echo "Found process(es): $PIDS"
echo "Killing process(es)..."

for PID in $PIDS; do
    echo "  Killing PID: $PID"
    kill -9 "$PID" 2>/dev/null || true
done

sleep 1

# Verify
if lsof -ti:$PORT >/dev/null 2>&1; then
    echo "⚠️  Warning: Process may still be running on port $PORT"
    exit 1
else
    echo "✅ Port $PORT is now free"
fi

