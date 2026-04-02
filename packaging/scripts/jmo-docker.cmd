@echo off
REM JMo Security Docker Wrapper for Windows
REM Automatically handles Git Bash MSYS path conversion issues
REM
REM Usage: jmo-docker scan --repo /scan --profile fast
REM        jmo-docker wizard
REM        jmo-docker --help
REM
REM This wrapper:
REM   1. Sets MSYS_NO_PATHCONV=1 to prevent path mangling
REM   2. Mounts current directory to /scan in container
REM   3. Passes all arguments to the JMo Docker container

setlocal EnableDelayedExpansion

REM Prevent MSYS path conversion (fixes Git Bash issues)
set MSYS_NO_PATHCONV=1

REM Default image (can be overridden with JMO_DOCKER_IMAGE env var)
if not defined JMO_DOCKER_IMAGE (
    set JMO_DOCKER_IMAGE=ghcr.io/jimmy058910/jmo-security:latest
)

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not running or not installed.
    echo Please start Docker Desktop and try again.
    exit /b 1
)

REM Create .jmo directory if it doesn't exist (for history persistence)
if not exist "%CD%\.jmo" mkdir "%CD%\.jmo"

REM Run JMo in Docker with current directory mounted
REM Note: Using -t only (not -it) for better compatibility with Git Bash/mintty
docker run --rm -t ^
    -v "%CD%:/scan" ^
    -v "%CD%/.jmo:/scan/.jmo" ^
    -w /scan ^
    %JMO_DOCKER_IMAGE% %*

exit /b %errorlevel%
