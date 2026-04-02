# JMo Security Docker Wrapper for PowerShell
# Cross-platform script for Windows PowerShell and PowerShell Core
#
# Usage: .\jmo-docker.ps1 scan --repo /scan --profile fast
#        .\jmo-docker.ps1 wizard
#        .\jmo-docker.ps1 --help
#
# This wrapper:
#   1. Mounts current directory to /scan in container
#   2. Persists scan history via .jmo volume mount
#   3. Passes all arguments to the JMo Docker container

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

# Default image (can be overridden with JMO_DOCKER_IMAGE env var)
$Image = if ($env:JMO_DOCKER_IMAGE) { $env:JMO_DOCKER_IMAGE } else { "ghcr.io/jimmy058910/jmo-security:latest" }

# Check if Docker is running
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker not running"
    }
} catch {
    Write-Error "ERROR: Docker is not running or not installed."
    Write-Error "Please start Docker Desktop and try again."
    exit 1
}

# Create .jmo directory if it doesn't exist (for history persistence)
$JmoDir = Join-Path $PWD ".jmo"
if (-not (Test-Path $JmoDir)) {
    New-Item -ItemType Directory -Path $JmoDir -Force | Out-Null
}

# Determine TTY flags based on terminal availability
# Use -it for interactive terminals, -t only for non-interactive (CI, piped)
try {
    $isInteractive = [Environment]::UserInteractive -and
                     -not [Console]::IsInputRedirected -and
                     -not [Console]::IsOutputRedirected
} catch {
    $isInteractive = $false
}

if ($isInteractive) {
    $TtyFlags = @("-it")
} else {
    $TtyFlags = @("-t")
}

# Run JMo in Docker with current directory mounted
$dockerArgs = @("run", "--rm") + $TtyFlags + @(
    "-v", "${PWD}:/scan",
    "-v", "${PWD}/.jmo:/scan/.jmo",
    "-w", "/scan",
    $Image
) + $Arguments

& docker @dockerArgs
exit $LASTEXITCODE
