<#
.SYNOPSIS
    Get File by Hash
.DESCRIPTION
    Searches for a file by hash starting from a given directory.
    The search can optionally be performed recursively for all subdirectories.

    If a suitable file is found, the logic from iri-get-file is reused and the file is transferred from the remote system to the local one.
    The transfer takes place by creating a compressed Base64 encoded object. 
    The result is a file object including metadata and compressed base64 encoded file content.

    The content can then be translated into the original file using the iri-helper.ps1 help tool. 
    Be careful with files that could potentially be malicious.

    Parameter: 
    Required: -path         -> The path from which the search starts
    Required: -hash         -> The hash of the file to be searched for
    Optional: -recurse      -> this parameter can be used to reference all subdirectories
                            -> Syntax: -recurse=recurse
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-filebyhash -path=C:\Windows\System32\ -hash=5AC3D561D0E5440020FADDFC95A73ABAE1C9794F7A4B5207B9CD2D99C4A7498C
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-filebyhash -path=C:\Windows\System32\ -hash=5AC3D561D0E5440020FADDFC95A73ABAE1C9794F7A4B5207B9CD2D99C4A7498C -recurse=recurse
.Notes
    Author: Nico Thelen & Kansa - https://github.com/davehull/Kansa/blob/master/Modules/Disk/Get-File.ps1
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$params
)

$target_path = $params['path']
$target_hash = $params['hash']
$recurse = $params['recurse']


####### Reuse a slightly modified form of the code from iri-get-file #######
function get_base64_Gzipped_Stream {
    Param(
        [Parameter(Mandatory=$True)]
        [System.IO.FileInfo]$file
    )

    $mem_file = New-Object System.IO.MemoryStream (,[System.IO.File]::ReadAllBytes($file))      # Read file into memory stream
    $mem_strm = New-Object System.IO.MemoryStream       # Create an empty memory stream to store GZipped bytes
    $gz_strm  = New-Object System.IO.Compression.GZipStream $mem_strm, ([System.IO.Compression.CompressionMode]::Compress)      # Create a GZipStream with $mem_strm as its underlying storage

    # Pass $mem_file's bytes through the GZipstream into the $mem_strm
    $gz_strm.Write($mem_file.ToArray(), 0, $file.Length)
    $gz_strm.Close()
    $gz_strm.Dispose()

    return [System.Convert]::ToBase64String($mem_strm.ToArray())   # Return Base64 Encoded GZipped stream
}

function file_infos {
    param (
        $file
    )
    
    # Create a custom object with the specified properties to store file information
    $obj = "" | Select-Object FullName, Name, Length, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc, Hash, Content

    if (Test-Path($file)) {
        $target = Get-ChildItem $file   # Get the file objects for the specified path

        # Populate the custom object with file properties
        $obj.FullName = $target.FullName                   
        $obj.Name = $target.Name                           
        $obj.Length = $target.Length                       
        $obj.CreationTimeUtc = $target.CreationTimeUtc     
        $obj.LastAccessTimeUtc = $target.LastAccessTimeUtc 
        $obj.LastWriteTimeUtc = $target.LastWriteTimeUtc   

        # Temporarily set the error action preference to stop on error
        $EAP = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'

        Try {
            $obj.Hash = $(Get-FileHash $file -Algorithm SHA256).Hash
        } Catch {
            $obj.Hash = 'Error hashing file'
        }

        # Restore the original error action preference
        $ErrorActionPreference = $EAP

        $obj.Content = get_base64_Gzipped_Stream($target)   # Compress and encode the file content as a Base64 GZipped stream, then store it

        return $obj

    } else {
        return $null
    }
}

###########################################################################


function search_hash {
    param (
        [string]$file_path
    )

    try {
        $hash = $(Get-FileHash -Path $file_path -Algorithm SHA256).Hash         # Calculate the hash of the file

        # If the hash matches, call function to get file informations and content
        if ($hash -eq $target_hash) {
            return file_infos $file_path
        }

        return $null

    } catch {
        Write-Output "Failed to process file $file_path - $_"
    }
}

# Search for files in the specified root directory
try {
    if ($recurse -eq "recurse") {
        $files = Get-ChildItem -Path $target_path -File -Recurse
    } else {
        $files = Get-ChildItem -Path $target_path -File
    }

    $hits = @()

    # Loop through each file found and start the hash search
    foreach ($f in $files) {
        $hit = search_hash $f.FullName
        if ($null -ne $hit) {
            $hits += $hit
        }
    }

    # Filter out null results and output the matches
    Write-Output $hits
} catch {
    Write-Output "Error searching files in $target_path - $_"
}
