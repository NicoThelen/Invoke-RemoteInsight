<#
.SYNOPSIS
    Overview: Groups
.DESCRIPTION
    Aggregates the following informations:
    - all local groups
    - all member of each local group

.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-groups
.Notes
    Author: Nico Thelen
#>

Write-Output "======== Groups ========"
Get-LocalGroup | Format-Table -Autosize | Out-String
Write-Output ""

Write-Output "======== Group Members ========"
Get-LocalGroup | ForEach-Object { $members = Get-LocalGroupMember -Group $_.Name; if ($members) { Write-Output "Group: $($_.Name)"; $members | ForEach-Object { Write-Output "Member: $($_.Name)" } } }