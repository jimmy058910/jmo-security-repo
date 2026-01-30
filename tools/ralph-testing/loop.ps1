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
    - all: Cycle through all targets sequentially (default, full codebase)
    - wizard: Focus on jmo wizard and wizard_flows
    - cli: Focus on jmo.py, scan_orchestrator, tool_installer, installers/
    - core: Focus on history_db, normalize_and_report, config, dedup
    - adapters: Focus on 29 tool adapters (consistency, parsing)
    - reporters: Focus on 13 reporters (XSS, output safety)
    - security: Cross-cutting security audit (CWE hunting)

.PARAMETER MaxIterations
    Maximum iterations before stopping (0 = infinite until plan empty)
    Note: Audit-only and test modes default to 1 iteration

.PARAMETER SkipPermissions
    Use --dangerously-skip-permissions for full autonomy (use with caution)

.PARAMETER FreshSession
    Force a fresh session for each iteration (don't use --continue)
    This matches the original Ralph Playbook behavior exactly.

.PARAMETER Force
    Bypass cooldown rules and force a full audit regardless of audit-state.json.
    Use when you want to re-audit targets that were recently audited.
    This injects a FORCE MODE instruction into the prompt that overrides cooldowns.

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

    # Force audit (bypass cooldowns, re-audit even if recently audited)
    .\tools\ralph-testing\loop.ps1 -Mode audit -Force -SkipPermissions

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
    [string]$Target = "all",

    [int]$MaxIterations = 0,

    [switch]$SkipPermissions,

    [switch]$FreshSession,

    # Force audit even if within cooldown period (ignores audit-state.json cooldowns)
    [switch]$Force,

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

# Function to check if all audit targets are in cooldown
# Returns $true if every target has been audited recently and is clean/partial
function Test-AllTargetsInCooldown {
    $StateFile = "$RalphDir/audit-state.json"
    if (-not (Test-Path $StateFile)) {
        return $false
    }

    try {
        $State = Get-Content $StateFile -Raw | ConvertFrom-Json
        $Targets = @("wizard", "cli", "core", "adapters", "reporters", "security")

        foreach ($target in $Targets) {
            $audit = $State.audits.$target
            if (-not $audit) { return $false }

            # Check if target needs auditing based on cooldown rules
            $lastAudit = [DateTime]::Parse($audit.last_audit)
            $daysSince = ((Get-Date) - $lastAudit).Days

            # Targets with issues always need attention
            if ($audit.status -eq "issues") { return $false }
            # Partial targets need re-audit after 3 days
            if ($audit.status -eq "partial" -and $daysSince -ge 3) { return $false }
            # Clean targets need re-audit after 7 days
            if ($audit.status -eq "clean" -and $daysSince -ge 7) { return $false }
        }

        return $true  # All targets in cooldown
    } catch {
        return $false
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
if ($Force) {
    Write-Host "Force Mode: TRUE (ignoring cooldowns)" -ForegroundColor Yellow
}
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

    # Determine if Force will be applied to this audit
    $AutoForceAudit = ($Mode -eq "auto" -and $EffectiveMode.StartsWith("audit:"))
    $ModeDisplay = $EffectiveMode
    if ($Mode -eq "auto") {
        if ($AutoForceAudit) {
            $ModeDisplay = "$EffectiveMode (auto+force)"
        } else {
            $ModeDisplay = "$EffectiveMode (auto)"
        }
    } elseif ($Force -and $EffectiveMode.StartsWith("audit:")) {
        $ModeDisplay = "$EffectiveMode (force)"
    }

    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ITERATION $Iteration - $Timestamp" -ForegroundColor Yellow
    Write-Host "  Mode: $ModeDisplay | Open Tasks: $OpenTasks" -ForegroundColor Yellow
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

    # ─────────────────────────────────────────────────────────────
    # RALPH PLAYBOOK PATTERN with LIVE TEXT STREAMING
    # Parses stream-json in real-time, displays assistant text,
    # logs raw JSON to iteration log for debugging
    # Reference: https://www.aihero.dev/heres-how-to-stream-claude-code-with-afk-ralph
    # ─────────────────────────────────────────────────────────────

    Write-Host "Starting fresh session ($EffectiveMode mode)..." -ForegroundColor DarkGray
    Write-Host ""

    # Build flags array matching Ralph Playbook
    $ClaudeFlags = @("-p", "--output-format=stream-json", "--verbose")
    if ($SkipPermissions) {
        $ClaudeFlags += "--dangerously-skip-permissions"
    }

    # Stream with real-time text extraction
    # - Logs raw JSON to iteration log for debugging
    # - Extracts and displays assistant text as it streams
    #
    # Claude Code stream-json format (per https://www.ytyng.com/en/blog/claude-stream-json-jq/):
    #   {"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"..."}}}
    #
    # We extract: stream_event.event.delta.text for real-time streaming

    # Build prompt content (with optional force mode injection)
    $PromptContent = Get-Content $PromptFile -Raw

    # Inject Force instruction when:
    # 1. User explicitly specified -Force flag, OR
    # 2. Auto mode is switching to audit (bypass cooldowns for the audit→build→audit cycle)
    $ShouldForceAudit = $Force -or ($Mode -eq "auto" -and $EffectiveMode.StartsWith("audit:"))

    if ($ShouldForceAudit -and $EffectiveMode.StartsWith("audit:")) {
        $ForceReason = if ($Force) { "user specified -Force flag" } else { "auto mode audit cycle (bypassing cooldowns)" }
        $ForceInstruction = @"

---

## FORCE MODE ACTIVE

**CRITICAL OVERRIDE:** Force mode is active because: $ForceReason

You MUST:
1. **IGNORE ALL COOLDOWN RULES** - Do not skip targets based on last_audit dates
2. **AUDIT ALL TARGETS** regardless of their status in audit-state.json
3. Run the full audit cycle as if all targets have never been audited
4. Still update audit-state.json with new timestamps after auditing

Proceed with full audit of all targets NOW.
"@
        $PromptContent = $PromptContent + $ForceInstruction
    }

    $PromptContent | & claude @ClaudeFlags 2>&1 | ForEach-Object {
        $line = $_

        # Log raw JSON to iteration log for debugging
        $line | Out-File -FilePath $LogFile -Append -Encoding utf8

        # Parse and display Claude activity in real-time
        if ($line -match '^\{') {
            try {
                $json = $line | ConvertFrom-Json

                # Handle assistant messages (text output OR tool calls)
                if ($json.type -eq "assistant" -and $json.message) {
                    foreach ($content in $json.message.content) {
                        if ($content.type -eq "text" -and $content.text) {
                            # Text output from Claude - display it
                            Write-Host -NoNewline $content.text
                        }
                        elseif ($content.type -eq "tool_use" -and $content.name) {
                            # Tool call - show brief indicator
                            Write-Host -NoNewline "[" -ForegroundColor DarkGray
                            Write-Host -NoNewline $content.name -ForegroundColor Cyan
                            Write-Host -NoNewline "] " -ForegroundColor DarkGray
                        }
                    }
                }
                # Handle result message (final output)
                elseif ($json.type -eq "result" -and $json.result) {
                    Write-Host ""
                    Write-Host "=== Result ===" -ForegroundColor Green
                    Write-Host $json.result
                }
            } catch {
                # Non-parseable line, skip silently
            }
        }
    }

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
        # Auto mode: Check if audit ran and found nothing
        # EffectiveMode is compound key like "audit:all", "audit:wizard", etc.
        $WasAuditMode = $EffectiveMode.StartsWith("audit:")

        if ($WasAuditMode -and $OpenTasks -eq 0 -and $NewOpenTasks -eq 0) {
            # Audit ran with no tasks before AND found no new tasks
            # This means we're done - no work to do
            Write-Host ""
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "  AUTO MODE COMPLETE" -ForegroundColor Green
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "- No open tasks in plan"
            Write-Host "- Audit found no new issues (cooldowns may be active)"
            Write-Host "- Run with -Force to bypass cooldowns"
            Write-Host ""
            Write-Host "Total iterations: $Iteration"
            break
        } elseif ($WasAuditMode -and $NewOpenTasks -eq 0) {
            # Audit found nothing but there were tasks before (now resolved)
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

    # Determine if we made progress this iteration
    # Note: EffectiveMode is compound key like "audit:all", so use StartsWith
    $WasAuditMode = $EffectiveMode.StartsWith("audit:")

    # In auto mode with 0→0 tasks after audit, this isn't struggle - it's completion
    # (the completion check above should have exited, but be safe here too)
    if ($Mode -eq "auto" -and $WasAuditMode -and $NewOpenTasks -eq 0 -and $OpenTasks -eq 0) {
        $MadeProgress = $true  # Not struggling, just done
    } else {
        $MadeProgress = ($ClaudeExitCode -eq 0) -and ($NewOpenTasks -lt $OpenTasks -or ($WasAuditMode -and $NewOpenTasks -gt 0))
    }

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
