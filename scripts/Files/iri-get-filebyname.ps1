<#
.SYNOPSIS
    Get File by Name
.DESCRIPTION
    Searches for a file by name starting from a given directory.
    The search can optionally be performed recursively for all subdirectories.
    A wildcard (*) can also be used in the file name.

    If a suitable file is found, the logic from iri-get-file is reused and the file is transferred from the remote system to the local one.
    The transfer takes place by creating a compressed Base64 encoded object. 
    The result is a file object including metadata and compressed base64 encoded file content.

    The content can then be translated into the original file using the iri-helper.ps1 help tool. 
    Be careful with files that could potentially be malicious.

    Parameter: 
    Required: -path         -> The path from which the search starts
    Required: -name         -> The name of the file to be searched for
    Optional: -recurse      -> This parameter can be used to reference all subdirectories
                            -> Syntax: -recurse=recurse
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-filebyname -path=C:\Windows\System32\ -name=mimikatz.exe
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-filebyname -path=C:\Windows\System32\ -name=mimikatz.exe -recurse=recurse
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-filebyname -path=C:\Windows\System32\ -name=mimi*.exe -recurse=recurse
.Notes
    Author: Nico Thelen & Kansa - https://github.com/davehull/Kansa/blob/master/Modules/Disk/Get-File.ps1
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$params
)

$target_path = $params['path']
$target_name = $params['name']
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
        if ($f.Name -like $target_name) {
            $hit = file_infos $f.FullName
            $hits += $hit
        }
    }

    # Filter out null results and output the matches
    Write-Output $hits
} catch {
    Write-Output "Error searching files in $target_path - $_"
}
