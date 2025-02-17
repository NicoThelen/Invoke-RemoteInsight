<#
.SYNOPSIS
    Hash all files
.DESCRIPTION
    Generates the hash value of all files recursively starting from a given root directory.
    Displays the following informations: 
    - Hash Algorithm
    - Filepath
    - Hash

    Parameter:
    Required: -path         -> The parent directory from which the hash calculation starts
    Optional: -recurse      -> This parameter can be used to reference all subdirectories
                            -> Syntax: -recurse=recurse
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-hashes -path=C:\Windows\System32
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-hashes -path="C:\Program Files (x86)\Microsoft"
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-hashes -path=C:\Windows\System32 -recurse=recurse
.Notes
    Author: Nico Thelen
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$params
)

$target_path = $params['path']
$recurse = $params['recurse']

$hash_list = @()

Push-Location -Path $target_path    # Push location to the given root directory

if ($recurse -eq "recurse") {
    $files_to_hash = Get-ChildItem -Path $target_path -Recurse -File -ErrorAction SilentlyContinue  # Get all files to hash recursively
} else {
    $files_to_hash = Get-ChildItem -Path $target_path -File -ErrorAction SilentlyContinue  # Get all files to hash
}

# Loop through each file and generate the hash
foreach ($file in $files_to_hash) {
    try {
        $hash = Get-FileHash -Algorithm SHA256 $file.FullName -ErrorAction Stop
        $hash_list += [PSCustomObject]@{        # Store all informations in a PSObject
            Algorithm = $hash.Algorithm
            Path = $file.FullName
            Hash = $hash.hash
        }
    }
    catch {
        $hash_list += [PSCustomObject]@{        # Also store fails in the PSObejct 
            Algorithm = "N/A"
            Path = $file.FullName
            Hash = "N/A"
        }
    }
}

Pop-Location                                            # Reset current directory location

Write-Output $hash_list