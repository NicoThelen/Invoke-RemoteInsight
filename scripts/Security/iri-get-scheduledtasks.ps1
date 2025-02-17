<#
.SYNOPSIS
    All Scheduled Tasks
.DESCRIPTION
    Lists all scheduled tasks of the system.
    This module is also used in iri-get-persistence, but only scheduled tasks with executable actions are displayed there. 
    Here, everything is displayed unfiltered.
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-scheduledtasks
.Notes
    Author: Nico Thelen
#>

$tasks = Get-CimInstance -Namespace "Root/Microsoft/Windows/TaskScheduler" -ClassName MSFT_ScheduledTask

$task_results = @()
foreach ($task in $tasks) { 
    foreach ($action in $task.Actions) { 
        $details = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName
        $task_results += [PSCustomObject]@{ 
            Path = $task.TaskPath 
            Name = $task.TaskName 
            State = $task.State 
            Next_Run_Time = $details.NextRunTime
            Last_Run_Time = $details.LastRunTime
            Author = $task.Principal.UserId 
            Execute = $action.Execute
            Arguments = $action.Arguments
        }
    } 
}


Write-Output $task_results