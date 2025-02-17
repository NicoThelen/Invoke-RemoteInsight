<#
.SYNOPSIS
    All Accounts
.DESCRIPTION
    Aggregates the following informations for all accounts:
    - Name
    - Domain
    - SID
    - PasswordRequired
    - PasswordExpires
    - PasswordChangeable

.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-accounts
.Notes
    Author: Nico Thelen
#>

$accounts = Get-WmiObject -Class Win32_UserAccount | Select-Object -Property Name, Domain, SID, PasswordRequired, PasswordExpires, PasswordChangeable | Format-Table -Autosize 

Write-Output $accounts
