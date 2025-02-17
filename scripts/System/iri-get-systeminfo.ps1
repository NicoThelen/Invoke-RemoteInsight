<#
.SYNOPSIS
    System Informations
.DESCRIPTION
    Aggregates the following system related informations:
    - hostname
    - OS Name
    - OS Version
    - Boottime
    - System directory
    - Domain
    - CPU
    - Hotfixes
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-systeminfo
.Notes
    Author: Nico Thelen
#>


# Get all relevant systeminformations
$sysinfo = Get-ComputerInfo -Property CsName, WindowsRegisteredOwner, WindowsProductName, OsProductType, CsDomain, CsUserName, WindowsCurrentVersion, OsVersion, OSDisplayVersion, OsWindowsDirectory, OsSystemDirectory, OsSystemDevice, OsBootDevice, OsLastBootUpTime, OsLocalDateTime

Write-Output $sysinfo
