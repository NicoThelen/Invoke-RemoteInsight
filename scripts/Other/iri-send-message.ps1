<#
.SYNOPSIS
    Send Message
.DESCRIPTION
    Send a custom message to the target systems desktop. The message will popup in a small window.

    Parameter: 
    Required: -msg          -> The message to be displayed on the target systems desktop
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-send-message -msg=Hello 
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-send-message -msg="Hello this is a example"
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-send-message -msg="Example with \"escaped\" quotes" 
.Notes
    Author: Nico Thelen
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$msg
)

$message = $msg['msg']

Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "msg * $message" | Out-Null