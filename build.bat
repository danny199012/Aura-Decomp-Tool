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

echo [1/6] Installing frontend dependencies...
call npm install 2>&1
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    echo.
    pause
    exit /b 1
)
echo.

REM Check for Rust/Cargo
set RUST_AVAILABLE=0
where cargo >nul 2>nul
if errorlevel 1 (
    echo WARNING: Rust/Cargo is not installed or not in PATH.
    echo Tauri requires Rust. Please install from https://rustup.rs/
    echo.
    echo You can still build the frontend, but Tauri build will fail.
) else (
    echo [2/6] Rust/Cargo found:
    cargo --version
    echo.
    set RUST_AVAILABLE=1
)

echo [3/6] Running TypeScript check + Vite build...
call npm run build 2>&1
if errorlevel 1 (
    echo ERROR: Frontend build failed.
    echo.
    pause
    exit /b 1
)
echo.

if "%RUST_AVAILABLE%"=="1" (
    echo [4/6] Building Tauri application...
    call npm run tauri build 2>&1
    if errorlevel 1 (
        echo ERROR: Tauri build failed.
        echo.
        pause
        exit /b 1
    )
    echo.
) else (
    echo [4/6] Skipping Tauri build (Rust not available).
    echo.
)

echo [5/6] Building aura-cli (standalone CLI)...
if "%RUST_AVAILABLE%"=="1" (
    pushd cli && call cargo build --release 2>&1 && popd
    if errorlevel 1 (
        echo WARNING: aura-cli build failed (GUI build already succeeded).
    )
    echo.
) else (
    echo Skipping aura-cli (Rust not available).
    echo.
)

echo (6/6) Done.
echo ========================================
echo   Build completed successfully!
echo ========================================
echo Artifacts:
echo   GUI bundle: src-tauri/target/release/bundle/
echo   CLI binary: cli/target/release/aura-cli.exe
echo.
