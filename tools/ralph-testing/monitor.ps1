<#
.SYNOPSIS
    Ralph Loop Monitor - Watch progress in a separate terminal

.DESCRIPTION
    Provides real-time monitoring of Ralph Loop execution by watching:
    - IMPLEMENTATION_PLAN.md for task status changes
    - Git status for file modifications
    - Iteration log files for new output

    Run this in a separate terminal while loop.ps1 is executing to get
    detailed visibility into Claude's progress.

.PARAMETER Interval
    How often to check for changes (seconds). Default: 5

.PARAMETER ShowGitDiff
    Show git diff summary when files change. Default: false (reduces noise)

.EXAMPLE
    # Basic monitoring
    .\tools\ralph-testing\monitor.ps1

    # Faster updates
    .\tools\ralph-testing\monitor.ps1 -Interval 2

    # Include git diff details
    .\tools\ralph-testing\monitor.ps1 -ShowGitDiff
#>

param(
    [int]$Interval = 5,
    [switch]$ShowGitDiff
)

$RalphDir = "tools/ralph-testing"
$PlanFile = "$RalphDir/IMPLEMENTATION_PLAN.md"
$LogDir = "$RalphDir/iteration-logs"

# State tracking
$LastPlanHash = ""
$LastGitStatus = ""
$LastLogCount = 0
$StartTime = Get-Date

# Helper function to get task counts
function Get-TaskCounts {
    param([string]$Content)

    $Open = ([regex]::Matches($Content, '\*\*Status:\*\*\s*Open(?!\s*\|)')).Count
    $InProgress = ([regex]::Matches($Content, '\*\*Status:\*\*\s*In Progress(?!\s*\|)')).Count
    $Resolved = ([regex]::Matches($Content, '\*\*Status:\*\*\s*Resolved(?!\s*\|)')).Count

    return @{
        Open = $Open
        InProgress = $InProgress
        Resolved = $Resolved
        Total = $Open + $InProgress + $Resolved
    }
}

# Helper function to format elapsed time
function Format-Elapsed {
    param([datetime]$Start)
    $Elapsed = (Get-Date) - $Start
    return $Elapsed.ToString("hh\:mm\:ss")
}

# Banner
Clear-Host
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ralph Loop Monitor" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Watching: $PlanFile"
Write-Host "Interval: ${Interval}s"
Write-Host "Press Ctrl+C to stop"
Write-Host ""
Write-Host "Waiting for activity..." -ForegroundColor DarkGray
Write-Host ""

# Monitor loop
while ($true) {
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $Elapsed = Format-Elapsed -Start $StartTime

    # Check plan file changes
    if (Test-Path $PlanFile) {
        $CurrentPlanHash = (Get-FileHash $PlanFile).Hash

        if ($CurrentPlanHash -ne $LastPlanHash) {
            $PlanContent = Get-Content $PlanFile -Raw
            $Counts = Get-TaskCounts -Content $PlanContent

            if ($LastPlanHash -eq "") {
                # Initial load
                Write-Host "[$Timestamp] PLAN LOADED" -ForegroundColor Green
            } else {
                Write-Host "[$Timestamp] PLAN UPDATED" -ForegroundColor Green
            }

            # Display task summary
            $StatusBar = "  Open: $($Counts.Open) | In Progress: $($Counts.InProgress) | Resolved: $($Counts.Resolved)"
            if ($Counts.Total -gt 0) {
                $PercentComplete = [math]::Round(($Counts.Resolved / $Counts.Total) * 100)
                $StatusBar += " ($PercentComplete% complete)"
            }
            Write-Host $StatusBar -ForegroundColor Yellow

            $LastPlanHash = $CurrentPlanHash
        }
    }

    # Check git status changes
    $CurrentGitStatus = git status --porcelain 2>$null
    if ($CurrentGitStatus -ne $LastGitStatus) {
        if ($CurrentGitStatus) {
            $FileCount = @($CurrentGitStatus).Count
            $Added = @($CurrentGitStatus | Where-Object { $_ -match '^\?\?' }).Count
            $Modified = @($CurrentGitStatus | Where-Object { $_ -match '^.M' }).Count
            $Deleted = @($CurrentGitStatus | Where-Object { $_ -match '^.D' }).Count

            Write-Host "[$Timestamp] FILES CHANGED ($FileCount total)" -ForegroundColor Magenta
            Write-Host "  Added: $Added | Modified: $Modified | Deleted: $Deleted" -ForegroundColor DarkMagenta

            if ($ShowGitDiff -and $LastGitStatus) {
                # Show which specific files changed
                $NewFiles = @($CurrentGitStatus | Where-Object { $LastGitStatus -notcontains $_ })
                if ($NewFiles.Count -gt 0 -and $NewFiles.Count -le 5) {
                    Write-Host "  New changes:" -ForegroundColor DarkGray
                    foreach ($File in $NewFiles) {
                        Write-Host "    $File" -ForegroundColor DarkGray
                    }
                }
            }
        }
        $LastGitStatus = $CurrentGitStatus
    }

    # Check for new log files
    if (Test-Path $LogDir) {
        $LogFiles = @(Get-ChildItem -Path $LogDir -Filter "*.log" -ErrorAction SilentlyContinue)
        if ($LogFiles.Count -gt $LastLogCount) {
            $NewestLog = $LogFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-Host "[$Timestamp] NEW LOG FILE" -ForegroundColor Blue
            Write-Host "  $($NewestLog.Name)" -ForegroundColor DarkBlue
            $LastLogCount = $LogFiles.Count
        }
    }

    # Periodic heartbeat (every 60 seconds)
    $SecondsSinceStart = ((Get-Date) - $StartTime).TotalSeconds
    if ($SecondsSinceStart -gt 0 -and [math]::Floor($SecondsSinceStart) % 60 -eq 0) {
        Write-Host "[$Timestamp] Monitoring active ($Elapsed elapsed)" -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds $Interval
}
