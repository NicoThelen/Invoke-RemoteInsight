<#
.SYNOPSIS
    Display opened files
.DESCRIPTION
    Lists all open files on the system. Both local and remotely opened files. 
    Processes and their PID are also displayed

    The prerequisite is the activation of the 'maintain objects list'.
    If it is not activated, the script aborts. 
    It must be activated via 'openfiles /local on' and a follow-up restart.
    It can then be deactivated via 'openfiles /local off' and a further restart
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-openfiles
.Notes
    Author: Nico Thelen
#>

$check = openfiles /local   # Get 'maintain objects list' status

# Validation of the 'maintain objects list' status, as this is a requirement for Openfiles
if ($check -match "deaktiviert" -or $check -match "disabled") {     # This approach only covers the status check for the German and English languages
    Write-Output "'maintain objects list' is currently disabled. To enable it use 'openfiles /local on' and reboot afterwards"
} else {
    $openfiles = openfiles /query /v    # Get a list of all open files + processes and their PID
}

Write-Output $openfiles
