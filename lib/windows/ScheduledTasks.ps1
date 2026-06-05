#===============================================================================
#   Scheduled Tasks Analysis
#===============================================================================

function Test-ScheduledTasks {
    Write-Section "5. SCHEDULED TASKS ANALYSIS"

    Write-Host "  Checking for suspicious scheduled tasks..." -ForegroundColor White
    Write-Host ""

    # Get non-Microsoft tasks
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Author -notmatch 'Microsoft' -and
        $_.State -eq 'Ready' -and
        $_.TaskPath -notmatch '^\\Microsoft'
    }

    # Check for tasks running scripts from unusual locations
    $suspiciousTasks = @()

    foreach ($task in $tasks) {
        try {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if ($action.Execute -match 'powershell|cmd|wscript|cscript|mshta') {
                    if ($action.Arguments -match 'http|temp|appdata\\local\\temp') {
                        $suspiciousTasks += [PSCustomObject]@{
                            Name = $task.TaskName
                            Path = $task.TaskPath
                            Command = "$($action.Execute) $($action.Arguments)"
                        }
                    }
                }
            }
        } catch {}
    }

    if ($suspiciousTasks) {
        Write-Warn "Suspicious scheduled tasks (scripts from unusual locations):"
        $suspiciousTasks | Format-Table -AutoSize
    } else {
        Write-Ok "No suspicious scheduled tasks detected"
    }

    # Show non-Microsoft tasks count
    $taskCount = ($tasks | Measure-Object).Count
    Write-Info "Non-Microsoft scheduled tasks: $taskCount"
}
