<#
.SYNOPSIS
    Network Drives
.DESCRIPTION
    Displays all network drives for the system
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-netdrives
.Notes
    Author: Nico Thelen
#>

$netdrives = net use

Write-Output $netdrives