@echo off
echo Starting Air-Gapped AI Security Scanner UI...

:: Start the Flask server in the background
cd backend
start /b python app.py

:: Wait for a few seconds for the server to start
timeout /t 3 /nobreak > nul

:: Open the default web browser to the app URL
start http://127.0.0.1:5000/

echo Server is running in the background. Close this window to keep it running, or terminate python to stop.
