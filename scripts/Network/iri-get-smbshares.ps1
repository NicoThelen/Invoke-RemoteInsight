<#
.SYNOPSIS
    Show SMB Shares
.DESCRIPTION
    Displays informations about current SMB Shares on the system.
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-smbshares
.Notes
    Author: Nico Thelen
#>

$smb_shares = Get-SmbShare

Write-Output $smb_shares