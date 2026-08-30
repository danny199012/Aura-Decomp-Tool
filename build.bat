@echo off

setlocal EnableDelayedExpansion

echo ========================================
echo   Aura Decomp Tool - Build Script
echo ========================================
echo.
echo Build started at %date% %time%
echo.

REM Check if npm is installed
where npm >nul 2>nul
if errorlevel 1 (
    echo ERROR: npm is not installed or not in PATH.
    echo Please install Node.js first.
    echo.
    pause
    exit /b 1
)
echo [1/5] npm found.

echo [1/5] Checking Node.js version...
node --version
npm --version
echo.

REM Check if Rust/Cargo is installed
where cargo >nul 2>nul
if errorlevel 1 (
    echo WARNING: Rust/Cargo is not installed or not in PATH.
    echo Tauri requires Rust. Please install from https://rustup.rs/
    echo.
    echo You can still build the frontend, but Tauri build will fail.
    set RUST_AVAILABLE=0
) else (
    echo [2/5] Rust/Cargo found:
    cargo --version
    echo.
    set RUST_AVAILABLE=1
)

echo [3/5] Installing frontend dependencies...
call npm install 2>&1
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    echo.
    pause
    exit /b 1
)
echo.

echo [4/5] Running TypeScript check and Vite build...
call npm run build 2>&1
if errorlevel 1 (
    echo ERROR: Frontend build failed.
    echo.
    pause
    exit /b 1
)
echo.

if "%RUST_AVAILABLE%"=="1" (
    echo [5/5] Building Tauri application...
    call npm run tauri build 2>&1
    if errorlevel 1 (
        echo ERROR: Tauri build failed.
        echo.
        pause
        exit /b 1
    )
    echo.
) else (
    echo [5/5] Skipping Tauri build (Rust not available).
    echo To enable Tauri build, install Rust from https://rustup.rs/
    echo.
    goto :end_success
)

echo ========================================
echo   Build completed successfully!
echo ========================================
echo The built application will be in:
echo   src-tauri/target/release/bundle/
goto :end_success

:end_success
echo.
echo ========================================
echo   Build completed successfully!
echo ========================================
pause
exit /b 0