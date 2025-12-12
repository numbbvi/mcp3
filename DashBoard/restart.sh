#!/bin/bash
# 현재 스크립트가 있는 디렉토리로 이동
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "기존 프로세스 종료 중..."
pkill -f "nodemon app.js" || pkill -f "node app.js" || true
sleep 2

echo "서버 재시작 중..."
npm run dev
