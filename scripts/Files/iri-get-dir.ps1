<#
.SYNOPSIS
    List Directory
.DESCRIPTION
    Lists all Objects (Folder, Files) recursively from a given directory
    Displays the following Informations: 
    - Name
    - Path
    - Mode 
    - CreationTimeUtc
    - LastAccessTimeUtc
    - LastWriteTimeUtc

    Parameter: 
    Required: -path         -> The parent directory from which the scan starts
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-dir -path=C:\Windows 
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-dir -path="C:\Program Files (x86)\Microsoft"
.Notes
    Author: Nico Thelen
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$path
)

$target_path = $path['path']

Push-Location $target_path          # Push to given directory
$dir_list = Get-ChildItem -Path $target_path -Recurse | Select-Object Name, FullName, Mode, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
Pop-Location 

Write-Output $dir_list