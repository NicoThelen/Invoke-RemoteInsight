<#
.SYNOPSIS
    All Profiles
.DESCRIPTION
    Aggregates the following informations for all profiles:
    - Local Path
    - LastUseTime
    - SID

.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-profiles
.Notes
    Author: Nico Thelen
#>

$prof = Get-CimInstance -ClassName win32_userprofile | Select-Object -Property LocalPath, LastUseTime, SID | Format-Table

Write-Output $prof
