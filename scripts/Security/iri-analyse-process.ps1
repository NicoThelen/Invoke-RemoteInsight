<#
.SYNOPSIS
    Analysis a specific process
.DESCRIPTION
    Aggregates the following informations for a given PID:
    - Basic Process Informations
    - Loaded Modules
    - Network Connections (UDP / TCP)
    - Process Chain (Parent / Child)

    Parameter:
    Required: -processid            -> The process id (PID) to be analyzed
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-analyse-process -processid=1337
.Notes
    Author: Nico Thelen
#>


param (
    [Parameter(Mandatory=$true)]
    [hashtable]$proc_id
)

$process_id = $proc_id['processid']

# Get the basic process informations
Write-Output "======== Process Informations ========"
Get-WmiObject -Class Win32_Process -Filter "ProcessId = $process_id" | ForEach-Object {
    $owner = $_.GetOwner()
    [PSCustomObject]@{
        Name         = $_.Name
        PID          = $_.ProcessId
        ParentPID    = $_.ParentProcessId
        User         = "$($owner.User)"
        CommandLine  = $_.CommandLine
        Path         = $_.ExecutablePath
    }
} | Format-List | Out-String
Write-Output ""

Write-Output "======== Modules ========"
# Get all loaded modules by the specified process
$modules = Get-WmiObject -Query "Associators of {Win32_Process.Handle='$process_id'} Where AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile" | Select-Object -Property Name, Path | Format-Table -AutoSize | out-string
if (-not $modules) {
    $modules = "No modules found"
}
$modules
Write-Output ""

# Get TCP and UDP connections 
Write-Output "======== Network Informations ========"
$tcp_connections = Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $process_id } | out-string
$udp_connections = Get-NetUDPEndpoint | Where-Object { $_.OwningProcess -eq $process_id } | out-string

if (-not $tcp_connections) {
    $tcp_connections = "No active TCP network connections for this process"
}
$tcp_connections

if (-not $udp_connections) {
    $udp_connections = "No active UDP network connections for this process"
}
$udp_connections
Write-Output ""

# Get parent process chain
$parent_chain = New-Object System.Collections.ArrayList
function parent_process_chain {
    param (
        [int]$process_id
    )
    $current_process = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $process_id"
    if ($current_process -and $current_process.ParentProcessId -ne 0) {
        $owner = $current_process.GetOwner()
        $parent_process = [PSCustomObject]@{
            Name        = $current_process.Name
            PID         = $current_process.ProcessId
            ParentPID   = $current_process.ParentProcessId
            User        = "$($owner.User)"
            CommandLine = $current_process.CommandLine
            Path        = $current_process.ExecutablePath
        }
        $parent_chain.Add($parent_process) | Out-Null
        parent_process_chain $current_process.ParentProcessId
    }
}
parent_process_chain $process_id
$p_chain = $parent_chain | Sort-Object PID | Format-Table -AutoSize -Property Name, PID, ParentPID, User, CommandLine, Path | out-string

# Get child process chain
$child_chain = New-Object System.Collections.ArrayList
function child_process_chain {
    param (
        [int]$parent_process_id
    )
    $child_processes = Get-WmiObject -Class Win32_Process -Filter "ParentProcessId = $parent_process_id"
    foreach ($child in $child_processes) {
        $owner = $child.GetOwner()
        $child_process = [PSCustomObject]@{
            Name        = $child.Name
            PID         = $child.ProcessId
            ParentPID   = $child.ParentProcessId
            User        = "$($owner.User)"
            CommandLine = $child.CommandLine
            Path        = $child.ExecutablePath
        }
        $child_chain.Add($child_process) | Out-Null
        child_process_chain $child.ProcessId
    }
}
child_process_chain $process_id
$c_chain = $child_chain | Format-Table -AutoSize -Property Name, PID, ParentPID, User, CommandLine, Path | out-string

Write-Output "======== Process Chain ========"
$p_chain
$c_chain