<#
.SYNOPSIS
    Ralph CLI Testing Loop - AI-Driven Autonomous Testing

.DESCRIPTION
    Implements the Ralph Loop pattern: feeds prompts to Claude CLI for autonomous
    test discovery, bug fixing, and iteration until all tasks are resolved.

    Architecture:
    - Outer loop (this script): Brain-dead simple, just pipes prompt to Claude
    - Inner loop (Claude): Reads plan, picks task, implements, tests, updates plan

.PARAMETER Mode
    Test mode:
    - test: Run test suite, discover failures, populate IMPLEMENTATION_PLAN.md
    - build: Fix one task per iteration until plan is empty (default)

.PARAMETER MaxIterations
    Maximum iterations before stopping (0 = infinite until plan empty)

.PARAMETER SkipPermissions
    Use --dangerously-skip-permissions for full autonomy (use with caution)

.EXAMPLE
    # Test discovery (single iteration)
    .\.claude\ralph-cli-testing\loop.ps1 -Mode test -MaxIterations 1

    # Build mode (fix issues until complete)
    .\.claude\ralph-cli-testing\loop.ps1 -Mode build

    # Full autonomy mode
    .\.claude\ralph-cli-testing\loop.ps1 -Mode build -SkipPermissions
#>

param(
    [ValidateSet("test", "build")]
    [string]$Mode = "build",

    [int]$MaxIterations = 0,

    [switch]$SkipPermissions
)

# Configuration
$RalphDir = ".claude\ralph-cli-testing"
$PromptFile = if ($Mode -eq "test") {
    "$RalphDir\PROMPT_test.md"
} else {
    "$RalphDir\PROMPT_build.md"
}
$PlanFile = "$RalphDir\IMPLEMENTATION_PLAN.md"
$LogDir = "$RalphDir\iteration-logs"
$Iteration = 0

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Banner
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ralph CLI Testing Loop" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Mode: $Mode"
Write-Host "Max Iterations: $(if ($MaxIterations -eq 0) { 'Infinite' } else { $MaxIterations })"
Write-Host "Skip Permissions: $SkipPermissions"
Write-Host "Prompt File: $PromptFile"
Write-Host ""

# Verify prompt file exists
if (-not (Test-Path $PromptFile)) {
    Write-Host "ERROR: Prompt file not found: $PromptFile" -ForegroundColor Red
    exit 1
}

# Build Claude command arguments
$ClaudeArgs = @("-p")
if ($SkipPermissions) {
    $ClaudeArgs += "--dangerously-skip-permissions"
}

# Main loop
while ($true) {
    $Iteration++
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogFile = "$LogDir\iteration-$($Iteration.ToString('00')).log"

    # Check iteration limit
    if ($MaxIterations -gt 0 -and $Iteration -gt $MaxIterations) {
        Write-Host ""
        Write-Host "Max iterations ($MaxIterations) reached." -ForegroundColor Yellow
        break
    }

    Write-Host "----------------------------------------" -ForegroundColor Yellow
    Write-Host "Iteration $Iteration - $Timestamp" -ForegroundColor Yellow
    Write-Host "----------------------------------------"

    # Log header
    "=== Iteration $Iteration started at $Timestamp ===" | Out-File -FilePath $LogFile -Encoding utf8
    "" | Out-File -FilePath $LogFile -Append -Encoding utf8

    # THE CORE: Feed prompt to Claude
    # This is the heart of Ralph - everything else happens inside Claude
    Get-Content $PromptFile -Raw | claude @ClaudeArgs 2>&1 | Tee-Object -FilePath $LogFile -Append

    # Check Claude exit code
    $ClaudeExitCode = $LASTEXITCODE
    if ($ClaudeExitCode -ne 0) {
        Write-Host ""
        Write-Host "Claude exited with code $ClaudeExitCode" -ForegroundColor Yellow
    }

    # Check if plan is complete (no open or in-progress tasks)
    if (Test-Path $PlanFile) {
        $Plan = Get-Content $PlanFile -Raw
        if ($Plan -notmatch "Status:\s*(Open|In Progress)") {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Green
            Write-Host "  COMPLETE - All tasks resolved!" -ForegroundColor Green
            Write-Host "========================================" -ForegroundColor Green
            Write-Host "Total iterations: $Iteration"
            break
        }
    }

    Write-Host ""
}

# Final summary
Write-Host ""
Write-Host "Loop finished after $Iteration iteration(s)." -ForegroundColor Cyan
Write-Host "Logs saved to: $LogDir"
