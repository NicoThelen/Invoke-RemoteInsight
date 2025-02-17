<#
.SYNOPSIS
    Retrieve Microsoft Office Alerts
.DESCRIPTION
    Queries all events of the OAlerts windows eventlog. 
    All notifications, alerts and activities that Microsoft Office displays or executes during user interaction are stored in this log. 
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-winevents-officealerts
.Notes
    Author: Nico Thelen
#>

$oAlerts = Get-WinEvent -FilterHashtable @{LogName="OAlerts"}

Write-Output $oAlerts
