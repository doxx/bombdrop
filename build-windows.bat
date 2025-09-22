@echo off
REM Build script for Windows binaries

REM Clear any existing GOFLAGS environment variable
set GOFLAGS=

REM Set variables
set BINARY_NAME=bombdrop
set BUILD_DIR=bin\windows
set VERSION=1.0.0

REM Get current date/time for build info (simplified)
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do set BUILD_DATE=%%c-%%a-%%b
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set BUILD_TIME_ONLY=%%a:%%b
set BUILD_TIME=%BUILD_DATE%T%BUILD_TIME_ONLY%

REM Get git commit (if available)
git rev-parse --short HEAD >nul 2>&1
if %errorlevel% equ 0 (
    for /f %%i in ('git rev-parse --short HEAD') do set GIT_COMMIT=%%i
) else (
    set GIT_COMMIT=unknown
)

REM Set Go build flags
set "LDFLAGS=-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%"

echo Building Windows binaries...

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Build for Windows AMD64
echo Building for Windows (AMD64)...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags "%LDFLAGS%" -o "%BUILD_DIR%\%BINARY_NAME%-windows-amd64.exe" .
if %errorlevel% equ 0 (
    echo ✅ Windows AMD64 build successful: %BUILD_DIR%\%BINARY_NAME%-windows-amd64.exe
) else (
    echo ❌ Windows AMD64 build failed!
    exit /b 1
)

REM Build for Windows ARM64
echo Building for Windows (ARM64)...
set GOARCH=arm64
go build -ldflags "%LDFLAGS%" -o "%BUILD_DIR%\%BINARY_NAME%-windows-arm64.exe" .
if %errorlevel% equ 0 (
    echo ✅ Windows ARM64 build successful: %BUILD_DIR%\%BINARY_NAME%-windows-arm64.exe
) else (
    echo ❌ Windows ARM64 build failed!
    exit /b 1
)

echo.
echo 🚀 All Windows builds completed successfully!
echo 📁 Binaries saved to: %BUILD_DIR%\
dir "%BUILD_DIR%"
