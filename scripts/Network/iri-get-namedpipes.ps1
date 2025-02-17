<#
.SYNOPSIS
    Get Named Pipes
.DESCRIPTION
    Lists all named pipes to identify potentially suspicious named pipes
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-namedpipes
.Notes
    Author: Nico Thelen
#>

Get-ChildItem -Path "\\.\pipe\" | Format-List PSPath, Name, Fullname