<#
.SYNOPSIS
    All Scheduled Jobs
.DESCRIPTION
    Lists all scheduled jobs of the system.
    This module is also used in iri-get-persistence. 
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-scheduledjobs
.Notes
    Author: Nico Thelen
#>

$jobs = Get-ScheduledJob 

$jobs_results = @()
foreach ($job in $jobs) {
    $options = $jobs.Options
    $jobs_results += [PSCustomObject]@{
        Name = $job.Name
        ID = $job.Id
        Enabled = $job.Enabled
        Show_in_TaskScheduler = $options.ShowInTaskScheduler
        Run_elevanted = $options.RunElevated
        Execute = $job.Command
    }
}

Write-Output $jobs_results