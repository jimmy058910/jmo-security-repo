<#
.SYNOPSIS
    Ralph CLI Testing Loop - AI-Driven Autonomous Testing

.DESCRIPTION
    Implements the Ralph Loop pattern: invokes Claude CLI for autonomous
    test discovery, bug fixing, and iteration until all tasks are resolved.

    Architecture:
    - Outer loop (this script): Invokes Claude with prompt content via pipeline
    - Inner loop (Claude): Reads plan, picks task, implements, tests, updates plan

    Auto Mode (default):
    - If no open tasks: Runs AUDIT to discover new issues
    - If open tasks exist: Runs BUILD to fix one task
    - Terminates when audit finds nothing AND plan is empty

    CRITICAL: Uses synchronous pipeline execution (Get-Content | claude)
    which blocks until Claude exits. This ensures sequential iteration.

.PARAMETER Mode
    Operating mode:
    - auto: Smart mode switching based on plan state (default)
    - test: Run test suite, discover failures, populate IMPLEMENTATION_PLAN.md
    - build: Fix one task per iteration until plan is empty
    - audit: Comprehensive multi-phase analysis (code review, coverage gaps, etc.)
    - validate: Validate scan accuracy against known-vulnerable targets
    - dedup: Analyze deduplication effectiveness and cluster quality

.PARAMETER Target
    Scope for audit mode (each loads a dedicated prompt):
    - wizard: Focus on jmo wizard and wizard_flows (default)
    - cli: Focus on jmo.py, scan_orchestrator, tool_installer, installers/
    - core: Focus on history_db, normalize_and_report, config, dedup
    - adapters: Focus on 29 tool adapters (consistency, parsing)
    - reporters: Focus on 13 reporters (XSS, output safety)
    - security: Cross-cutting security audit (CWE hunting)
    - all: Cycle through all targets sequentially

.PARAMETER MaxIterations
    Maximum iterations before stopping (0 = infinite until plan empty)
    Note: Audit-only and test modes default to 1 iteration

.PARAMETER SkipPermissions
    Use --dangerously-skip-permissions for full autonomy (use with caution)

.PARAMETER FreshSession
    Force a fresh session for each iteration (don't use --continue)
    This matches the original Ralph Playbook behavior exactly.

.EXAMPLE
    # Auto mode - discovers and fixes issues automatically
    .\tools\ralph-testing\loop.ps1 -SkipPermissions

    # Test discovery (single iteration)
    .\tools\ralph-testing\loop.ps1 -Mode test -MaxIterations 1

    # Build mode only (fix issues until complete)
    .\tools\ralph-testing\loop.ps1 -Mode build

    # Audit specific targets (each has dedicated prompt)
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target wizard -SkipPermissions
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target cli -SkipPermissions
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target core -SkipPermissions
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target adapters -SkipPermissions
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target reporters -SkipPermissions
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target security -SkipPermissions

    # Full codebase audit (cycles through all targets)
    .\tools\ralph-testing\loop.ps1 -Mode audit -Target all -SkipPermissions -MaxIterations 20

    # Full autonomy with circuit breaker (2 hour max)
    .\tools\ralph-testing\loop.ps1 -SkipPermissions -MaxDurationMinutes 120

    # With rate limiting (5s between iterations)
    .\tools\ralph-testing\loop.ps1 -SkipPermissions -MaxIterations 5 -DelayBetweenIterations 5

    # Custom struggle threshold (5 failures before forced audit)
    .\tools\ralph-testing\loop.ps1 -SkipPermissions -StruggleThreshold 5

    # Full robust run with all safeguards
    .\tools\ralph-testing\loop.ps1 -SkipPermissions -MaxDurationMinutes 120 -StruggleThreshold 3 -DelayBetweenIterations 2

    # Validate scan accuracy against baselines
    .\tools\ralph-testing\loop.ps1 -Mode validate -SkipPermissions

    # Analyze deduplication effectiveness
    .\tools\ralph-testing\loop.ps1 -Mode dedup -SkipPermissions
#>

param(
    [ValidateSet("auto", "test", "build", "audit", "validate", "dedup")]
    [string]$Mode = "auto",

    [ValidateSet("all", "wizard", "cli", "core", "adapters", "reporters", "security")]
    [string]$Target = "wizard",

    [int]$MaxIterations = 0,

    [switch]$SkipPermissions,

    [switch]$FreshSession,

    # Circuit breaker: max total runtime in minutes (0 = unlimited)
    [int]$MaxDurationMinutes = 0,

    # Per-iteration timeout in minutes (0 = unlimited)
    [int]$MaxIterationMinutes = 20,

    # Consecutive failures before forcing audit (struggle detection)
    [int]$StruggleThreshold = 3,

    # Seconds to wait between iterations (rate limiting, 0 = no delay)
    [int]$DelayBetweenIterations = 0
)

# Configuration
$RalphDir = "tools/ralph-testing"
$PlanFile = "$RalphDir/IMPLEMENTATION_PLAN.md"
$LogDir = "$RalphDir/iteration-logs"
$LearningsFile = "$LogDir/learnings.txt"
$Iteration = 0
$ConsecutiveEmptyAudits = 0
$ConsecutiveFailures = 0
$ForceAudit = $false
$LoopStartTime = Get-Date

# Prompt file mapping - compound keys for audit:target
$PromptFiles = @{
    "test"             = "$RalphDir/PROMPT_test.md"
    "build"            = "$RalphDir/PROMPT_build.md"
    "validate"         = "$RalphDir/PROMPT_validate.md"
    "dedup"            = "$RalphDir/PROMPT_dedup_analysis.md"
    # Audit targets - compound keys
    "audit:wizard"     = "$RalphDir/PROMPT_audit_wizard.md"
    "audit:cli"        = "$RalphDir/PROMPT_audit_cli.md"
    "audit:core"       = "$RalphDir/PROMPT_audit_core.md"
    "audit:adapters"   = "$RalphDir/PROMPT_audit_adapters.md"
    "audit:reporters"  = "$RalphDir/PROMPT_audit_reporters.md"
    "audit:security"   = "$RalphDir/PROMPT_audit_security.md"
    "audit:all"        = "$RalphDir/PROMPT_audit_all.md"
}

# Single-run modes default to 1 iteration
if (($Mode -in @("audit", "test", "validate", "dedup")) -and $MaxIterations -eq 0) {
    $MaxIterations = 1
}

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Function to check if plan has open tasks
function Test-HasOpenTasks {
    if (-not (Test-Path $PlanFile)) {
        return $false
    }
    $Plan = Get-Content $PlanFile -Raw
    # Match actual task status lines, not template examples
    return $Plan -match "\*\*Status:\*\*\s*(Open|In Progress)(?!\s*\|)"
}

# Function to get task count for display
function Get-OpenTaskCount {
    if (-not (Test-Path $PlanFile)) {
        return 0
    }
    $Plan = Get-Content $PlanFile -Raw
    $Matches = [regex]::Matches($Plan, "\*\*Status:\*\*\s*(Open|In Progress)(?!\s*\|)")
    return $Matches.Count
}

# Function to determine effective mode for this iteration
# Returns compound key for audit modes (e.g., "audit:wizard", "audit:cli")
function Get-EffectiveMode {
    param(
        [string]$RequestedMode,
        [string]$AuditTarget,
        [bool]$ForceAuditMode = $false
    )

    # Struggle detection can force audit mode
    if ($ForceAuditMode) {
        return "audit:$AuditTarget"
    }

    if ($RequestedMode -ne "auto") {
        # For audit mode, return compound key with target
        if ($RequestedMode -eq "audit") {
            return "audit:$AuditTarget"
        }
        return $RequestedMode
    }

    # Auto mode: check plan state
    if (Test-HasOpenTasks) {
        return "build"
    } else {
        return "audit:$AuditTarget"
    }
}

# Function for enhanced completion detection
function Test-SpecificationComplete {
    if (-not (Test-Path $PlanFile)) {
        return @{
            Resolved = 0
            Total = 0
            CompletionRate = 0
            IsComplete = $false
        }
    }

    $Plan = Get-Content $PlanFile -Raw

    # Count resolved vs total ever created
    $Resolved = ([regex]::Matches($Plan, "\*\*Status:\*\*\s*Resolved")).Count
    $Total = ([regex]::Matches($Plan, "### TASK-\d+")).Count

    # Check for explicit completion markers
    $HasCompletionMarker = $Plan -match "## Specification Complete"

    return @{
        Resolved = $Resolved
        Total = $Total
        CompletionRate = if ($Total -gt 0) { [math]::Round($Resolved / $Total * 100, 1) } else { 0 }
        IsComplete = $HasCompletionMarker -or ($Resolved -eq $Total -and $Total -gt 0)
    }
}

# Banner
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ralph CLI Testing Loop v3.0" -ForegroundColor Cyan
Write-Host "  (Robust Autonomous Execution)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Mode: $Mode$(if ($Mode -eq 'auto') { ' (auto-switches between audit/build)' })"
if ($Mode -eq "audit" -or $Mode -eq "auto") {
    Write-Host "Target: $Target"
}
Write-Host "Max Iterations: $(if ($MaxIterations -eq 0) { 'Infinite' } else { $MaxIterations })"
Write-Host "Max Duration: $(if ($MaxDurationMinutes -eq 0) { 'Unlimited' } else { "$MaxDurationMinutes min" })"
Write-Host "Struggle Threshold: $StruggleThreshold consecutive failures"
if ($DelayBetweenIterations -gt 0) {
    Write-Host "Rate Limiting: ${DelayBetweenIterations}s between iterations"
}
Write-Host "Skip Permissions: $SkipPermissions"
Write-Host ""

# Build skip permissions flag once
$SkipFlag = if ($SkipPermissions) { "--dangerously-skip-permissions" } else { $null }

# Main loop - SYNCHRONOUS execution, one iteration at a time
while ($true) {
    $Iteration++
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogFile = "$LogDir/iteration-$($Iteration.ToString('00')).log"

    # Check iteration limit BEFORE starting work
    if ($MaxIterations -gt 0 -and $Iteration -gt $MaxIterations) {
        Write-Host ""
        Write-Host "Max iterations ($MaxIterations) reached." -ForegroundColor Yellow
        break
    }

    # Circuit breaker: check total runtime
    if ($MaxDurationMinutes -gt 0) {
        $TotalElapsed = ((Get-Date) - $LoopStartTime).TotalMinutes
        if ($TotalElapsed -gt $MaxDurationMinutes) {
            Write-Host ""
            Write-Host "CIRCUIT BREAKER: Max duration ($MaxDurationMinutes min) reached" -ForegroundColor Red
            Write-Host "Total runtime: $([math]::Round($TotalElapsed, 1)) minutes"
            break
        }
    }

    # Determine effective mode for this iteration (may be forced by struggle detection)
    # Returns compound key for audit modes (e.g., "audit:wizard")
    $EffectiveMode = Get-EffectiveMode -RequestedMode $Mode -AuditTarget $Target -ForceAuditMode $ForceAudit
    $ForceAudit = $false  # Reset after use
    $PromptFile = $PromptFiles[$EffectiveMode]
    $OpenTasks = Get-OpenTaskCount

    # Verify prompt file exists
    if (-not (Test-Path $PromptFile)) {
        Write-Host "ERROR: Prompt file not found: $PromptFile" -ForegroundColor Red
        exit 1
    }

    # ════════════════════════════════════════════════════════════════
    # ITERATION HEADER - displayed BEFORE starting this iteration
    # ════════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ITERATION $Iteration - $Timestamp" -ForegroundColor Yellow
    Write-Host "  Mode: $EffectiveMode$(if ($Mode -eq 'auto') { ' (auto)' }) | Open Tasks: $OpenTasks" -ForegroundColor Yellow
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""

    # Log header
    "=== Iteration $Iteration started at $Timestamp ===" | Out-File -FilePath $LogFile -Encoding utf8
    "Mode: $EffectiveMode | Open Tasks: $OpenTasks" | Out-File -FilePath $LogFile -Append -Encoding utf8
    "" | Out-File -FilePath $LogFile -Append -Encoding utf8

    # ════════════════════════════════════════════════════════════════
    # THE CORE: Synchronous Claude invocation with progress monitoring
    # This BLOCKS until Claude exits - ensuring sequential iterations
    #
    # MATCHING RALPH PLAYBOOK PATTERN:
    #   cat PROMPT.md | claude -p --output-format=stream-json --verbose
    #
    # Every iteration starts fresh (no --continue) with deterministic context.
    # ════════════════════════════════════════════════════════════════

    $StartTime = Get-Date

    # Start background progress monitor (updates every 60 seconds)
    # Writes to both a progress file AND attempts console output
    $ProgressFile = "$LogDir/progress.txt"
    "Started at $(Get-Date -Format 'HH:mm:ss')" | Out-File -FilePath $ProgressFile -Encoding utf8

    $Runspace = [runspacefactory]::CreateRunspace()
    $Runspace.Open()
    $Runspace.SessionStateProxy.SetVariable("PlanFile", $PlanFile)
    $Runspace.SessionStateProxy.SetVariable("StartTime", $StartTime)
    $Runspace.SessionStateProxy.SetVariable("ProgressFile", $ProgressFile)

    $ProgressScript = {
        while ($true) {
            Start-Sleep -Seconds 60
            $Elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)
            $Now = Get-Date -Format "HH:mm:ss"

            # Count git changes
            try {
                $GitOutput = & git status --porcelain 2>$null
                $GitChanges = if ($GitOutput) { ($GitOutput | Measure-Object).Count } else { 0 }
            } catch { $GitChanges = "?" }

            # Get current task from plan
            $CurrentTask = "working"
            if (Test-Path $PlanFile) {
                $PlanContent = Get-Content $PlanFile -Raw -ErrorAction SilentlyContinue
                if ($PlanContent -match "### (TASK-\d+)[^\r\n]*") {
                    $Lines = $PlanContent -split "`n"
                    for ($i = 0; $i -lt $Lines.Count; $i++) {
                        if ($Lines[$i] -match "### (TASK-\d+)") {
                            $TaskId = $Matches[1]
                            for ($j = $i; $j -lt [Math]::Min($i + 8, $Lines.Count); $j++) {
                                if ($Lines[$j] -match "\*\*Status:\*\* In Progress") {
                                    $CurrentTask = $TaskId
                                    break
                                }
                            }
                        }
                    }
                }
            }

            $ProgressMsg = "[$Now] ${Elapsed}m elapsed | $CurrentTask | Files changed: $GitChanges"

            # Write to progress file (guaranteed to work)
            $ProgressMsg | Out-File -FilePath $ProgressFile -Encoding utf8

            # Also try stderr for console display
            try { [Console]::Error.WriteLine($ProgressMsg) } catch {}
        }
    }

    $PowerShell = [powershell]::Create()
    $PowerShell.Runspace = $Runspace
    $PowerShell.AddScript($ProgressScript) | Out-Null
    $ProgressHandle = $PowerShell.BeginInvoke()

    Write-Host "Progress file: $ProgressFile" -ForegroundColor DarkGray
    Write-Host "(Monitor in another terminal: Get-Content $ProgressFile -Wait)" -ForegroundColor DarkGray

    # ─────────────────────────────────────────────────────────────
    # RALPH PLAYBOOK PATTERN: cat PROMPT.md | claude -p [flags]
    # Using stdin piping + stream-json for reliability
    # ─────────────────────────────────────────────────────────────

    Write-Host "Starting fresh session ($EffectiveMode mode)..." -ForegroundColor DarkGray
    Write-Host ""

    # Build flags array matching Ralph Playbook
    $ClaudeFlags = @("-p", "--output-format=stream-json", "--verbose")
    if ($SkipPermissions) {
        $ClaudeFlags += "--dangerously-skip-permissions"
    }

    # Use stdin piping like Ralph Playbook: cat PROMPT.md | claude -p
    # Note: Output may not display in real-time but execution is more reliable
    Get-Content $PromptFile -Raw | & claude @ClaudeFlags

    # Stop progress monitor
    $PowerShell.Stop()
    $PowerShell.Dispose()
    $Runspace.Close()
    $Runspace.Dispose()

    # ════════════════════════════════════════════════════════════════
    # POST-ITERATION: Only reached AFTER Claude exits
    # ════════════════════════════════════════════════════════════════

    $ClaudeExitCode = $LASTEXITCODE
    $EndTime = Get-Date
    $Duration = ($EndTime - $StartTime).ToString("hh\:mm\:ss")
    $CompletionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Log completion
    "" | Out-File -FilePath $LogFile -Append -Encoding utf8
    "=== Iteration $Iteration completed at $CompletionTime ===" | Out-File -FilePath $LogFile -Append -Encoding utf8
    "Duration: $Duration | Exit code: $ClaudeExitCode" | Out-File -FilePath $LogFile -Append -Encoding utf8

    Write-Host ""
    Write-Host "────────────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "Iteration $Iteration complete | Duration: $Duration | Exit: $ClaudeExitCode" -ForegroundColor Gray

    if ($ClaudeExitCode -ne 0) {
        Write-Host "Claude exited with non-zero code $ClaudeExitCode" -ForegroundColor Yellow

        # Non-zero exit doesn't always mean failure - check the plan
        if (Test-Path $PlanFile) {
            $Plan = Get-Content $PlanFile -Raw
            if ($Plan -notmatch "\*\*Status:\*\*\s*(Open|In Progress)(?!\s*\|)") {
                Write-Host "All tasks appear resolved despite non-zero exit." -ForegroundColor Green
            }
        }
    }

    # ════════════════════════════════════════════════════════════════
    # COMPLETION CHECK
    # ════════════════════════════════════════════════════════════════

    $NewOpenTasks = Get-OpenTaskCount
    Write-Host "Open tasks: $OpenTasks -> $NewOpenTasks" -ForegroundColor Gray
    Write-Host "────────────────────────────────────────────────────────────" -ForegroundColor Gray

    if ($Mode -eq "auto") {
        # Auto mode: Track if audit found nothing
        if ($EffectiveMode -eq "audit" -and $NewOpenTasks -eq 0) {
            $ConsecutiveEmptyAudits++
            Write-Host "Audit found no new issues. (Empty audits: $ConsecutiveEmptyAudits)" -ForegroundColor Cyan

            if ($ConsecutiveEmptyAudits -ge 2) {
                Write-Host ""
                Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
                Write-Host "  COMPLETE - No issues found!" -ForegroundColor Green
                Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
                Write-Host "Total iterations: $Iteration"
                Write-Host "Two consecutive audits found no issues."
                break
            }
        } else {
            # Reset counter if we found tasks or were in build mode
            $ConsecutiveEmptyAudits = 0
        }
    } else {
        # Non-auto modes: Original completion check
        if ($NewOpenTasks -eq 0) {
            Write-Host ""
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "  COMPLETE - All tasks resolved!" -ForegroundColor Green
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "Total iterations: $Iteration"
            break
        }
    }

    # ════════════════════════════════════════════════════════════════
    # STRUGGLE DETECTION: Track consecutive failures
    # ════════════════════════════════════════════════════════════════

    $MadeProgress = ($ClaudeExitCode -eq 0) -and ($NewOpenTasks -lt $OpenTasks -or ($EffectiveMode -eq "audit" -and $NewOpenTasks -gt 0))

    if (-not $MadeProgress) {
        $ConsecutiveFailures++
        Write-Host "No progress made. (Consecutive failures: $ConsecutiveFailures/$StruggleThreshold)" -ForegroundColor DarkYellow

        if ($ConsecutiveFailures -ge $StruggleThreshold) {
            Write-Host ""
            Write-Host "STRUGGLE DETECTED: $ConsecutiveFailures consecutive failures" -ForegroundColor Red
            Write-Host "Forcing audit mode on next iteration to reassess..." -ForegroundColor Yellow
            $ForceAudit = $true
            $ConsecutiveFailures = 0  # Reset counter
        }
    } else {
        $ConsecutiveFailures = 0  # Reset on success
    }

    # ════════════════════════════════════════════════════════════════
    # RATE LIMITING: Optional delay between iterations
    # ════════════════════════════════════════════════════════════════

    if ($DelayBetweenIterations -gt 0) {
        Write-Host "Rate limiting: waiting $DelayBetweenIterations seconds..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $DelayBetweenIterations
    }

    # ════════════════════════════════════════════════════════════════
    # ENHANCED COMPLETION: Check specification progress
    # ════════════════════════════════════════════════════════════════

    $SpecStatus = Test-SpecificationComplete
    if ($SpecStatus.Total -gt 0) {
        Write-Host "Specification progress: $($SpecStatus.Resolved)/$($SpecStatus.Total) tasks ($($SpecStatus.CompletionRate)%)" -ForegroundColor DarkCyan
    }
}

# Final summary
$TotalRuntime = ((Get-Date) - $LoopStartTime).ToString("hh\:mm\:ss")
$FinalSpec = Test-SpecificationComplete

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  LOOP COMPLETE" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total iterations: $Iteration"
Write-Host "Total runtime: $TotalRuntime"
if ($FinalSpec.Total -gt 0) {
    Write-Host "Final progress: $($FinalSpec.Resolved)/$($FinalSpec.Total) tasks resolved ($($FinalSpec.CompletionRate)%)"
}
Write-Host "Logs saved to: $LogDir"
Write-Host "Learnings: $LearningsFile"
