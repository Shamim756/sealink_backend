#!/bin/bash

# Port 3000-এ থাকা সব process kill
echo "🔍 Checking port 3000..."
if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null 2>&1; then
  echo "⚠️  Port 3000 busy — killing old process..."
  sudo fuser -k 3000/tcp
  sleep 1
fi

echo "✅ Port 3000 free"
echo "🚀 Starting backend..."
npm run dev
