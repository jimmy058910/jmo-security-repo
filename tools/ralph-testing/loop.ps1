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
    - wizard-scan: Test jmo wizard with automation flags against Juice Shop repo

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

    # Wizard scan - test jmo wizard automation against Juice Shop (needs 3 successes)
    .\tools\ralph-testing\loop.ps1 -Mode wizard-scan -SkipPermissions
#>

param(
    [ValidateSet("auto", "test", "build", "audit", "validate", "dedup", "wizard-scan")]
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

# Prompt file mapping - compound keys for audit:target and wizard-scan:mode
$PromptFiles = @{
    "test"                = "$RalphDir/PROMPT_test.md"
    "build"               = "$RalphDir/PROMPT_build.md"
    "validate"            = "$RalphDir/PROMPT_validate.md"
    "dedup"               = "$RalphDir/PROMPT_dedup_analysis.md"
    # Wizard-scan modes (v2.0 - repo and image)
    "wizard-scan"         = "$RalphDir/PROMPT_wizard_scan.md"
    "wizard-scan:repo"    = "$RalphDir/PROMPT_wizard_scan.md"
    "wizard-scan:image"   = "$RalphDir/PROMPT_wizard_scan.md"
    # Audit targets - compound keys
    "audit:wizard"        = "$RalphDir/PROMPT_audit_wizard.md"
    "audit:cli"           = "$RalphDir/PROMPT_audit_cli.md"
    "audit:core"          = "$RalphDir/PROMPT_audit_core.md"
    "audit:adapters"      = "$RalphDir/PROMPT_audit_adapters.md"
    "audit:reporters"     = "$RalphDir/PROMPT_audit_reporters.md"
    "audit:security"      = "$RalphDir/PROMPT_audit_security.md"
    "audit:all"           = "$RalphDir/PROMPT_audit_all.md"
}

# Single-run modes default to 1 iteration (except wizard-scan which needs multiple for 3 successes)
if (($Mode -in @("audit", "test", "validate", "dedup")) -and $MaxIterations -eq 0) {
    $MaxIterations = 1
}

# Wizard-scan mode defaults to 25 iterations (max allowed before giving up)
if ($Mode -eq "wizard-scan" -and $MaxIterations -eq 0) {
    $MaxIterations = 25
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
# Returns "wizard-scan:repo" or "wizard-scan:image" for wizard modes
#
# Auto Mode Cycle (v2.0):
#   1. If open tasks exist → build (fix issues)
#   2. If wizard-scan needs attention → wizard-scan (repo or image mode)
#   3. If audits need attention → audit (discover new issues)
#   4. All complete → exit
#
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
        # For wizard-scan mode, determine which sub-mode
        if ($RequestedMode -eq "wizard-scan") {
            $WizardMode = Get-WizardModeToRun
            return "wizard-scan:$WizardMode"
        }
        return $RequestedMode
    }

    # Auto mode: smart cycling through phases (v2.0)
    #
    # Priority 1: Fix open tasks (build mode)
    if (Test-HasOpenTasks) {
        return "build"
    }

    # Priority 2: Run wizard-scan if not complete (needs 3 consecutive successes for BOTH modes)
    if (Test-WizardScanNeedsAttention) {
        $WizardMode = Get-WizardModeToRun
        return "wizard-scan:$WizardMode"
    }

    # Priority 3: Check if all audits are on cooldown - if so, we might be complete
    if (Test-AllTargetsInCooldown) {
        # Double-check wizard completion
        if (Test-WizardScanComplete) {
            return "complete"  # Special mode indicating all done
        }
    }

    # Priority 4: Run audit to discover new issues
    return "audit:$AuditTarget"
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

# ════════════════════════════════════════════════════════════════════════════
# UNIFIED STATE MANAGEMENT (v2.0)
# ════════════════════════════════════════════════════════════════════════════

# Function to read the unified state file
function Get-UnifiedState {
    $StateFile = "$RalphDir/unified-state.json"
    if (-not (Test-Path $StateFile)) {
        # Fall back to creating default state
        return @{
            wizard_scan = @{
                repo = @{ consecutive_successes = 0; status = "not_started" }
                image = @{ consecutive_successes = 0; status = "not_started" }
                required_successes = 3
            }
            audits = @{}
            tasks = @{ open = 0 }
            completion = @{ is_complete = $false }
            cooldown_rules = @{
                wizard_passing_days = 1
                audit_clean_days = 7
                audit_partial_days = 3
            }
        }
    }

    try {
        return Get-Content $StateFile -Raw | ConvertFrom-Json
    } catch {
        Write-Host "WARNING: Failed to parse unified-state.json" -ForegroundColor Yellow
        return $null
    }
}

# Function to check if all audit targets are in cooldown
# Returns $true if every target has been audited recently and is clean/partial
function Test-AllTargetsInCooldown {
    $State = Get-UnifiedState
    if (-not $State) { return $false }

    # Also check legacy file for backwards compatibility
    $LegacyFile = "$RalphDir/audit-state.json"
    if ((Test-Path $LegacyFile) -and -not $State.audits) {
        try {
            $LegacyState = Get-Content $LegacyFile -Raw | ConvertFrom-Json
            $State.audits = $LegacyState.audits
        } catch {}
    }

    $Targets = @("wizard", "cli", "core", "adapters", "reporters", "security")
    $Rules = $State.cooldown_rules

    foreach ($target in $Targets) {
        $audit = $State.audits.$target
        if (-not $audit) { return $false }

        try {
            $lastAudit = [DateTime]::Parse($audit.last_audit)
            $daysSince = ((Get-Date) - $lastAudit).Days
        } catch {
            return $false
        }

        # Targets with issues always need attention
        if ($audit.status -eq "issues") { return $false }
        # Partial targets need re-audit after cooldown
        $partialDays = if ($Rules.audit_partial_days) { $Rules.audit_partial_days } else { 3 }
        if ($audit.status -eq "partial" -and $daysSince -ge $partialDays) { return $false }
        # Clean targets need re-audit after cooldown
        $cleanDays = if ($Rules.audit_clean_days) { $Rules.audit_clean_days } else { 7 }
        if ($audit.status -eq "clean" -and $daysSince -ge $cleanDays) { return $false }
    }

    return $true  # All targets in cooldown
}

# Function to check wizard-scan progress (both repo and image need 3 successes)
function Test-WizardScanComplete {
    $State = Get-UnifiedState
    if (-not $State) { return $false }

    $Required = if ($State.wizard_scan.required_successes) { $State.wizard_scan.required_successes } else { 3 }

    $RepoSuccesses = if ($State.wizard_scan.repo.consecutive_successes) {
        $State.wizard_scan.repo.consecutive_successes
    } else { 0 }

    $ImageSuccesses = if ($State.wizard_scan.image.consecutive_successes) {
        $State.wizard_scan.image.consecutive_successes
    } else { 0 }

    # Both modes must have required successes
    return ($RepoSuccesses -ge $Required) -and ($ImageSuccesses -ge $Required)
}

# Function to check if repo wizard needs attention
function Test-WizardRepoNeedsAttention {
    $State = Get-UnifiedState
    if (-not $State) { return $true }

    $Required = if ($State.wizard_scan.required_successes) { $State.wizard_scan.required_successes } else { 3 }
    $Repo = $State.wizard_scan.repo

    # Needs attention if not yet passing
    if ($Repo.consecutive_successes -lt $Required) { return $true }

    # Needs attention if has blocking issue
    if ($Repo.blocking_issue) { return $true }

    # Check cooldown if already passing
    if ($Repo.last_run) {
        try {
            $lastRun = [DateTime]::Parse($Repo.last_run)
            $daysSince = ((Get-Date) - $lastRun).Days
            $cooldownDays = if ($State.cooldown_rules.wizard_passing_days) {
                $State.cooldown_rules.wizard_passing_days
            } else { 1 }
            return $daysSince -ge $cooldownDays
        } catch {}
    }

    return $false
}

# Function to check if image wizard needs attention
function Test-WizardImageNeedsAttention {
    $State = Get-UnifiedState
    if (-not $State) { return $true }

    $Required = if ($State.wizard_scan.required_successes) { $State.wizard_scan.required_successes } else { 3 }
    $Image = $State.wizard_scan.image

    # Needs attention if not yet passing
    if ($Image.consecutive_successes -lt $Required) { return $true }

    # Needs attention if has blocking issue
    if ($Image.blocking_issue) { return $true }

    # Check cooldown if already passing
    if ($Image.last_run) {
        try {
            $lastRun = [DateTime]::Parse($Image.last_run)
            $daysSince = ((Get-Date) - $lastRun).Days
            $cooldownDays = if ($State.cooldown_rules.wizard_passing_days) {
                $State.cooldown_rules.wizard_passing_days
            } else { 1 }
            return $daysSince -ge $cooldownDays
        } catch {}
    }

    return $false
}

# Function to check wizard-scan needs attention (either mode)
function Test-WizardScanNeedsAttention {
    return (Test-WizardRepoNeedsAttention) -or (Test-WizardImageNeedsAttention)
}

# Function to get which wizard mode to run (repo or image)
# Returns "repo" or "image" based on which has fewer successes
function Get-WizardModeToRun {
    $State = Get-UnifiedState
    if (-not $State) { return "repo" }

    $Required = if ($State.wizard_scan.required_successes) { $State.wizard_scan.required_successes } else { 3 }

    $RepoSuccesses = if ($State.wizard_scan.repo.consecutive_successes) {
        $State.wizard_scan.repo.consecutive_successes
    } else { 0 }

    $ImageSuccesses = if ($State.wizard_scan.image.consecutive_successes) {
        $State.wizard_scan.image.consecutive_successes
    } else { 0 }

    # If both complete, check which needs re-run based on cooldown
    if ($RepoSuccesses -ge $Required -and $ImageSuccesses -ge $Required) {
        if (Test-WizardRepoNeedsAttention) { return "repo" }
        if (Test-WizardImageNeedsAttention) { return "image" }
        return "repo"  # Default
    }

    # Run whichever has fewer successes (repo if tied)
    if ($RepoSuccesses -le $ImageSuccesses) {
        return "repo"
    }
    return "image"
}

# Function to check if auto mode is complete
function Test-AutoModeComplete {
    $State = Get-UnifiedState
    if (-not $State) { return $false }

    # Check all four criteria
    $NoOpenTasks = -not (Test-HasOpenTasks)
    $WizardComplete = Test-WizardScanComplete
    $AllAuditsOnCooldown = Test-AllTargetsInCooldown

    return $NoOpenTasks -and $WizardComplete -and $AllAuditsOnCooldown
}

# Function to display unified status dashboard
function Show-UnifiedStatus {
    $State = Get-UnifiedState
    if (-not $State) {
        Write-Host "[No state file found]" -ForegroundColor DarkGray
        return
    }

    $Required = if ($State.wizard_scan.required_successes) { $State.wizard_scan.required_successes } else { 3 }

    $RepoSuccesses = if ($State.wizard_scan.repo.consecutive_successes) {
        $State.wizard_scan.repo.consecutive_successes
    } else { 0 }

    $ImageSuccesses = if ($State.wizard_scan.image.consecutive_successes) {
        $State.wizard_scan.image.consecutive_successes
    } else { 0 }

    $OpenTasks = Get-OpenTaskCount

    # Count clean audits
    $CleanAudits = 0
    $Targets = @("wizard", "cli", "core", "adapters", "reporters", "security")
    foreach ($target in $Targets) {
        if ($State.audits.$target.status -eq "clean") { $CleanAudits++ }
    }

    # Build status line colors
    $TaskColor = if ($OpenTasks -eq 0) { "Green" } else { "Yellow" }
    $RepoColor = if ($RepoSuccesses -ge $Required) { "Green" } else { "Yellow" }
    $ImageColor = if ($ImageSuccesses -ge $Required) { "Green" } else { "Yellow" }
    $RepoCheck = if ($RepoSuccesses -ge $Required) { " OK" } else { "" }
    $ImageCheck = if ($ImageSuccesses -ge $Required) { " OK" } else { "" }

    Write-Host ""
    Write-Host "+----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|              UNIFIED AUTO MODE STATUS v2.0               |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host -NoNewline "| Tasks:  " -ForegroundColor Cyan
    Write-Host -NoNewline "$OpenTasks open" -ForegroundColor $TaskColor
    Write-Host -NoNewline " | Audits: $CleanAudits/6 clean" -ForegroundColor Cyan
    Write-Host "                      |" -ForegroundColor Cyan
    Write-Host -NoNewline "| Wizard REPO:  $RepoSuccesses/$Required" -ForegroundColor Cyan
    Write-Host -NoNewline "$RepoCheck" -ForegroundColor $RepoColor
    Write-Host -NoNewline " | IMAGE: $ImageSuccesses/$Required" -ForegroundColor Cyan
    Write-Host -NoNewline "$ImageCheck" -ForegroundColor $ImageColor
    Write-Host "                      |" -ForegroundColor Cyan
    Write-Host "+----------------------------------------------------------+" -ForegroundColor Cyan
}

# Compact banner - just essential info
$IterLimit = if ($MaxIterations -eq 0) { "∞" } else { $MaxIterations }
$Duration = if ($MaxDurationMinutes -eq 0) { "∞" } else { "${MaxDurationMinutes}m" }
$SkipInfo = if ($SkipPermissions) { " --skip-perms" } else { "" }
$ForceInfo = if ($Force) { " --force" } else { "" }
Write-Host "Ralph v4.0 | $Mode | iter=$IterLimit dur=$Duration$SkipInfo$ForceInfo" -ForegroundColor Cyan

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
    # Returns compound key for audit modes (e.g., "audit:wizard") or wizard modes (e.g., "wizard-scan:repo")
    $EffectiveMode = Get-EffectiveMode -RequestedMode $Mode -AuditTarget $Target -ForceAuditMode $ForceAudit
    $ForceAudit = $false  # Reset after use

    # Handle "complete" mode - auto mode detected all work is done
    if ($EffectiveMode -eq "complete") {
        Write-Host ""
        Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  UNIFIED AUTO MODE COMPLETE!" -ForegroundColor Green
        Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
        Show-UnifiedStatus
        Write-Host ""
        Write-Host "All completion criteria met:" -ForegroundColor Green
        Write-Host "  - No open tasks in IMPLEMENTATION_PLAN.md"
        Write-Host "  - Wizard REPO: 3/3 consecutive successes"
        Write-Host "  - Wizard IMAGE: 3/3 consecutive successes"
        Write-Host "  - All audit targets on cooldown"
        Write-Host ""
        Write-Host "Total iterations: $($Iteration - 1)"
        break
    }

    $PromptFile = $PromptFiles[$EffectiveMode]
    $OpenTasks = Get-OpenTaskCount

    # Verify prompt file exists
    if (-not $PromptFile -or -not (Test-Path $PromptFile)) {
        Write-Host "ERROR: Prompt file not found for mode: $EffectiveMode" -ForegroundColor Red
        Write-Host "  Expected: $PromptFile" -ForegroundColor Red
        exit 1
    }

    # Compact iteration header
    $ModeDisplay = $EffectiveMode
    if ($Mode -eq "auto") { $ModeDisplay = "$EffectiveMode (auto)" }
    elseif ($Force -and $EffectiveMode.StartsWith("audit:")) { $ModeDisplay = "$EffectiveMode (force)" }

    Write-Host ""
    Write-Host "[$Iteration] $Timestamp | $ModeDisplay | tasks=$OpenTasks" -ForegroundColor Yellow

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

    # Build prompt content (with optional mode injections)
    $PromptContent = Get-Content $PromptFile -Raw

    # Inject wizard mode instruction for wizard-scan modes
    if ($EffectiveMode.StartsWith("wizard-scan:")) {
        $WizardSubMode = $EffectiveMode -replace "wizard-scan:", ""

        # Build mode-specific details (avoid nested here-strings)
        if ($WizardSubMode -eq "repo") {
            $ModeDetails = @"
**REPO MODE** - Testing SAST, secrets, SCA, and IaC scanning:
- Target: ``tools/ralph-testing/fixtures/juice-shop`` (cloned repo)
- Results: ``tools/ralph-testing/wizard-results/repo/``
- Command: ``jmo wizard --profile balanced --target-type repo --target tools/ralph-testing/fixtures/juice-shop ...``
"@
        } else {
            $ModeDetails = @"
**IMAGE MODE** - Testing container image scanning:
- Target: ``bkimminich/juice-shop:latest`` (Docker image)
- Results: ``tools/ralph-testing/wizard-results/image/``
- Command: ``jmo wizard --profile balanced --target-type image --target bkimminich/juice-shop:latest ...``
"@
        }

        $WizardModeInstruction = @"

---

## WIZARD MODE: $($WizardSubMode.ToUpper())

**This iteration is running in $WizardSubMode mode.**

$ModeDetails

**State File:** Update ``tools/ralph-testing/unified-state.json`` in the ``wizard_scan.$WizardSubMode`` section after the scan.
"@
        $PromptContent = $PromptContent + $WizardModeInstruction
    }

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
2. **AUDIT ALL TARGETS** regardless of their status in unified-state.json
3. Run the full audit cycle as if all targets have never been audited
4. Still update unified-state.json with new timestamps after auditing

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
        # Auto mode: Check completion status
        # EffectiveMode is compound key like "audit:all", "audit:wizard", "wizard-scan:repo", etc.
        $WasAuditMode = $EffectiveMode.StartsWith("audit:")
        $WasWizardScan = $EffectiveMode.StartsWith("wizard-scan:")

        # Check if wizard-scan achieved successes
        if ($WasWizardScan) {
            $WizardSubMode = $EffectiveMode -replace "wizard-scan:", ""
            $State = Get-UnifiedState
            if ($State) {
                $Successes = if ($WizardSubMode -eq "repo") {
                    $State.wizard_scan.repo.consecutive_successes
                } else {
                    $State.wizard_scan.image.consecutive_successes
                }
                $Required = if ($State.wizard_scan.required_successes) { $State.wizard_scan.required_successes } else { 3 }
                Write-Host "Wizard ${WizardSubMode}: $Successes/$Required consecutive successes" -ForegroundColor Cyan
            }
        }

        # Check if full auto mode is complete
        if (Test-AutoModeComplete) {
            Write-Host ""
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "  UNIFIED AUTO MODE COMPLETE" -ForegroundColor Green
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Show-UnifiedStatus
            Write-Host ""
            Write-Host "All criteria met:"
            Write-Host "  - No open tasks"
            Write-Host "  - Wizard REPO: 3/3 successes"
            Write-Host "  - Wizard IMAGE: 3/3 successes"
            Write-Host "  - All audits on cooldown"
            Write-Host ""
            Write-Host "Total iterations: $Iteration"
            break
        }

        if ($WasAuditMode -and $OpenTasks -eq 0 -and $NewOpenTasks -eq 0) {
            # Audit ran with no tasks before AND found no new tasks
            $ConsecutiveEmptyAudits++
            Write-Host "Audit found no new issues. (Empty audits: $ConsecutiveEmptyAudits)" -ForegroundColor Cyan
        } elseif (-not $WasWizardScan) {
            # Reset counter if we found tasks or were in build mode (not wizard-scan)
            $ConsecutiveEmptyAudits = 0
        }
    } elseif ($Mode -eq "wizard-scan") {
        # Wizard-scan mode: Check for 3 consecutive successes (both modes)
        if (Test-WizardScanComplete) {
            Write-Host ""
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "  WIZARD-SCAN COMPLETE - Both REPO and IMAGE passing!" -ForegroundColor Green
            Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
            Show-UnifiedStatus
            Write-Host "Total iterations: $Iteration"
            break
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
    # Note: EffectiveMode is compound key like "audit:all", "wizard-scan:repo", so use StartsWith
    $WasAuditMode = $EffectiveMode.StartsWith("audit:")
    $WasWizardScan = $EffectiveMode.StartsWith("wizard-scan:")

    # In auto mode with 0→0 tasks after audit, this isn't struggle - it's completion
    # (the completion check above should have exited, but be safe here too)
    if ($Mode -eq "auto" -and $WasAuditMode -and $NewOpenTasks -eq 0 -and $OpenTasks -eq 0) {
        $MadeProgress = $true  # Not struggling, just done
    } elseif ($WasWizardScan) {
        # Wizard-scan progress is measured by exit code (Claude handles state tracking)
        $MadeProgress = ($ClaudeExitCode -eq 0)
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
# Show unified status if relevant
if ($Mode -in @("auto", "wizard-scan")) {
    Show-UnifiedStatus
    $WizardComplete = Test-WizardScanComplete
    if ($WizardComplete) {
        Write-Host "Wizard-scan: COMPLETE (REPO + IMAGE both passing)" -ForegroundColor Green
    } else {
        Write-Host "Wizard-scan: IN PROGRESS (check unified-state.json)" -ForegroundColor Yellow
    }
}
Write-Host "Logs saved to: $LogDir"
Write-Host "State file: $RalphDir/unified-state.json"
Write-Host "Learnings: $LearningsFile"
