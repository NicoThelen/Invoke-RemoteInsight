<#
.SYNOPSIS
    List File ADS
.DESCRIPTION
    Shows extended information for a file or all files (recursively) from a given directory. 
    It is very similar to 'iri-get-hashes' and 'iri-get-dir' but offers extended visibility into the files (ADS) and ignores directories.
    Additionally, optional parameters are available to limit the result to files with specific ADS.
    Displays the following Informations: 
    - Name
    - Path
    - Mode
    - SHA256 Hash
    - ADS 
    - CreationTimeUtc
    - LastAccessTimeUtc
    - LastWriteTimeUtc

    Parameter:
    Required: -path             -> The parent directory from which the scan starts or the path to a file
    Optional: -recurse          -> This switch can be used to reference all subdirectories
                                -> Syntax: -recurse=True
    Optional: -number           -> This parameter can be used to determine a minimum number of ADS
    Optional: -type             -> This parameter can be used to determine a specific ADS type
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-ads -path=C:\Windows\System32\ByteCodeGenerator.exe
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-ads -path="C:\Program Files (x86)\Microsoft"
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-ads -path=C:\Windows\System32 -recurse=recurse
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-ads -path=C:\Windows\System32 -recurse=recurse -number=2
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-ads -path=C:\Windows\System32 -recurse=recurse -type=Zone.Identifier
.Notes
    Author: Nico Thelen
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$params
)

$target_path = $params['path']
$recurse = $params['recurse']
$ads_num = $params['number']
$ads_type = $params['type']

Push-Location $target_path -ErrorAction SilentlyContinue             # Push to given directory

if ($recurse -eq "True") {
    $file_list = Get-ChildItem -Path $target_path -File -Recurse | Select-Object Name, FullName, Mode, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc   # Get all files recursively
} else {
    $file_list = Get-ChildItem -Path $target_path -File | Select-Object Name, FullName, Mode, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc    # Get all files from given directory
}

$result_list = @()

foreach ($file in $file_list) {
    $stream_list = @()

    $streams = Get-Item -Path $file.FullName -Stream *

    # Check if the file meets the minimum number of streams (if $ads_num is set)
    if ($ads_num -and ($streams.Count -lt $ads_num)) {
        continue                                        # Skip the file
    }

    # Check if the file has at least one stream matching the type (if $ads_type is set)
    $has_matching_type = $false
    if ($ads_type) {
        foreach ($stream in $streams) {
            if ($stream.Stream -like "*$ads_type*") {
                $has_matching_type = $true
                break  # No need to keep checking once we find a match
            }
        }

        # If $ads_type is set and no matching type is found, skip the file
        if (-not $has_matching_type) {
            continue
        }
    }
    
    # If a file with ADS found matching the parameters, save them
    foreach ($stream in $streams) {
        $stream_list += $stream.Stream
    }

    $hash = (Get-FileHash -Algorithm SHA256 $file.FullName -ErrorAction Stop).Hash
    
    $result_list += [PSCustomObject]@{        # Store all informations in a PSObject
        Name = $file.Name
        Path = $file.FullName
        Mode = $file.Mode
        Hash = $hash
        Streams = $stream_list -join ", "
        CreationTimeUtc = $file.CreationTimeUtc
        LastAccessTimeUtc = $file.LastAccessTimeUtc
        LastWriteTimeUtc = $file.LastWriteTimeUtc
    }
}

Pop-Location

Write-Output $result_list
