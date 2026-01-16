#!/usr/bin/env pwsh

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "   TEAMVAULT DEBUG HELPER" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Check if server is running
Write-Host "Checking Server..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5000" -Method GET -ErrorAction SilentlyContinue -TimeoutSec 2
    Write-Host "✅ Server is running on port 5000" -ForegroundColor Green
} catch {
    Write-Host "❌ Server is NOT running. Please start with: npm run dev" -ForegroundColor Red
}

Write-Host ""

# Check if client is running
Write-Host "Checking Client..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5173" -Method GET -ErrorAction SilentlyContinue -TimeoutSec 2
    Write-Host "✅ Client is running on port 5173" -ForegroundColor Green
} catch {
    Write-Host "❌ Client is NOT running. Please start with: npm run dev" -ForegroundColor Red
}

Write-Host ""

# Check MongoDB
Write-Host "Checking MongoDB..." -ForegroundColor Yellow
$mongoProcess = Get-Process mongod -ErrorAction SilentlyContinue
if ($mongoProcess) {
    Write-Host "✅ MongoDB is running" -ForegroundColor Green
} else {
    Write-Host "⚠️  MongoDB might not be running locally" -ForegroundColor Yellow
    Write-Host "   (You may be using MongoDB Atlas - that's fine)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Quick Fix Commands:" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "1. Start Server:  cd server; npm run dev" -ForegroundColor White
Write-Host "2. Start Client:  cd client; npm run dev" -ForegroundColor White
Write-Host "3. Open Browser:  http://localhost:5173" -ForegroundColor White
Write-Host ""

Read-Host "Press Enter to exit"
