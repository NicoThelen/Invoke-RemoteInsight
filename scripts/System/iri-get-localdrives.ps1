<#
.SYNOPSIS
    Local Drives
.DESCRIPTION
    Displays all local drives for the system.
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-localdrives
.Notes
    Author: Nico Thelen
#>

$localdrives = Get-WmiObject win32_logicaldisk | Select-Object DeviceID, DriveType, Description, VolumeName, Size, FreeSpace

Write-Output $localdrives