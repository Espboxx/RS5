@echo off
setlocal enabledelayedexpansion

:: Create output directory
if not exist "build" mkdir build

:: Build flags
set FLAGS=-ldflags="-s -w"

:: Windows builds
set GOOS=windows
set CGO_ENABLED=0

set GOARCH=amd64
go build %FLAGS% -o build/reverseproxy_windows_amd64.exe
if %errorlevel% neq 0 goto :error

set GOARCH=386
go build %FLAGS% -o build/reverseproxy_windows_386.exe
if %errorlevel% neq 0 goto :error

set GOARCH=arm64
go build %FLAGS% -o build/reverseproxy_windows_arm64.exe
if %errorlevel% neq 0 goto :error

:: Linux builds
set GOOS=linux

set GOARCH=amd64
go build %FLAGS% -o build/reverseproxy_linux_amd64
if %errorlevel% neq 0 goto :error

set GOARCH=386
go build %FLAGS% -o build/reverseproxy_linux_386
if %errorlevel% neq 0 goto :error

set GOARCH=arm64
go build %FLAGS% -o build/reverseproxy_linux_arm64
if %errorlevel% neq 0 goto :error

:: macOS builds
set GOOS=darwin

set GOARCH=amd64
go build %FLAGS% -o build/reverseproxy_darwin_amd64
if %errorlevel% neq 0 goto :error

set GOARCH=arm64
go build %FLAGS% -o build/reverseproxy_darwin_arm64
if %errorlevel% neq 0 goto :error

echo Build completed successfully
exit /b 0

:error
echo Build failed with error #%errorlevel%
exit /b %errorlevel% 