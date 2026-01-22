# Test Start-Process -Wait approach
$content = "Count slowly from 1 to 3, one per line"

Write-Host "=== Test 1: Start-Process with -Wait (shares console) ===" -ForegroundColor Yellow
$process = Start-Process -FilePath "claude" -ArgumentList "-p", $content, "--dangerously-skip-permissions", "--max-turns", "1" -Wait -NoNewWindow -PassThru
Write-Host "Exit code: $($process.ExitCode)"

Write-Host ""
Write-Host "=== Test 2: Direct call (for comparison) ===" -ForegroundColor Yellow
& claude -p $content --dangerously-skip-permissions --max-turns 1
Write-Host "Exit code: $LASTEXITCODE"
