@echo off
echo ====================================
echo    TEAMVAULT - QUICK START
echo ====================================
echo.
echo Starting MongoDB (if installed locally)...
start "" mongod

timeout /t 3

echo.
echo Starting Server...
start cmd /k "cd /d %~dp0server && npm run dev"

timeout /t 5

echo.
echo Starting Client...
start cmd /k "cd /d %~dp0client && npm run dev"

echo.
echo ====================================
echo Server: http://localhost:5000
echo Client: http://localhost:5173
echo ====================================
echo.
echo Press any key to open browser...
pause > nul
start http://localhost:5173
