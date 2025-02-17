<#
.SYNOPSIS
    All active SMB Sessions
.DESCRIPTION
    Displays all currently active SMB sessions
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-smbsessions
.Notes
    Author: Nico Thelen
#>

$sessions = Get-SmbSession

Write-Output $sessions