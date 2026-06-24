#!/bin/bash
echo "Starting Antigravity Network Recon Platform..."

# Setup and start backend
cd backend
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
echo "[*] Installing backend dependencies..."
pip install -r requirements.txt > /dev/null 2>&1
echo "[*] Starting FastAPI Backend on port 8000..."
uvicorn api:app --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!
cd ..

# Start frontend
cd frontend
echo "[*] Starting Vite React Frontend..."
npm run dev &
FRONTEND_PID=$!

echo ""
echo "================================================="
echo "✅ Backend running at: http://127.0.0.1:8000"
echo "✅ Frontend running at: http://localhost:5173"
echo "================================================="
echo "Press Ctrl+C to stop both servers."

# Wait for user interrupt
trap "kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT SIGTERM
wait
