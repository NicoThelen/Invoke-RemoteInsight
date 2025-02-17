<#
.SYNOPSIS
    Analysis of ADS
.DESCRIPTION
    Lists all ADS and their content for a given file
    Displays the following Informations: 
    - ADS Name
    - ADS Content

    Parameter: 
    Required: -path         -> The path to the file whose ADS is to be analyzed
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-analyse-ads -path=C:\Windows\System32\Suspicious.png
.Notes
    Author: Nico Thelen
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$params
)

$target_path = $params['path']

$streams = Get-Item -Path $target_path -Stream *    # Get all streams
$result = @()

foreach ($stream in $streams) {
    $result += [PSCustomObject]@{        # Store all informations in a PSObject
        ADS_Name = $stream.stream
        ADS_Content = Get-Content -Path $target_path -Stream $stream.stream | Out-String
    }
}

Write-Output $result
