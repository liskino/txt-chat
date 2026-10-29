@echo off
REM txt-chat launcher: Node.js server + Cloudflare tunnel (public URL)
REM ASCII only: cmd.exe reads .bat in system codepage, Cyrillic would break.

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js not found. Install it from https://nodejs.org then run this file again.
  pause
  exit /b 1
)

set PORT=4322
set CFDIR=%LOCALAPPDATA%\Programs\cloudflared
set CFEXE=%CFDIR%\cloudflared.exe

REM ── quick tunnel: no account, free, random public URL ──
if not exist "%CFEXE%" (
  echo Downloading cloudflared...
  powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path '%CFDIR%' | Out-Null; Invoke-WebRequest 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile '%CFEXE%' -UseBasicParsing"
)

echo.
echo Server:   http://localhost:4322
echo Public:   printed by cloudflared below (https://....trycloudflare.com)
echo Browser opens automatically. Close this window to stop everything.
echo.

start "" http://localhost:4322
start "" "%CFEXE%" tunnel --url http://127.0.0.1:4322
node "%~dp0server.mjs"
