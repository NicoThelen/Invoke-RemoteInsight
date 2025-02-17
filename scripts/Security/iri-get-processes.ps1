<#
.SYNOPSIS
    Overview: All running Processes
.DESCRIPTION
    Displays all running processes with in depth details for each process. 
    The following data is collected for each process:
    - Starttime 
    - Name
    - ProcessID
    - Parent ProcessID
    - Owner
    - Commandline
    - Path
    - SHA256 Hash

    Can be used to identify interesting processes for further analysis with 'iri-analyse-process'
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-processes
.Notes
    Author: Nico Thelen
#>

$processes = Get-WmiObject -Class Win32_Process | ForEach-Object {
            [PSCustomObject]@{
                StartTime = ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate))
                Name = $_.Name
                PID = $_.ProcessId
                P_PID = $_.ParentProcessId
                User = $($_.GetOwner()).User 
                CommandLine = if($_.CommandLine){$_.CommandLine} else {"N/A"}
                Path = if($_.Path){$_.Path} else {"N/A"}
                Hash = if($_.Path){$(Get-FileHash -Algorithm SHA256 -Path $_.Path).Hash} else {"N/A"}}
            } -ErrorAction SilentlyContinue

Write-Output $processes
