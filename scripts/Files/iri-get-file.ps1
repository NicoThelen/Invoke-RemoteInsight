<#
.SYNOPSIS
    Get File
.DESCRIPTION
    Copies a file from the remote system. 
    The transfer takes place by creating a compressed Base64 encoded object. 
    The result is a file object including metadata and compressed base64 encoded file content.

    To get the object that represents the file with the original timestamp, no further action is required. 

    To receive the fully encoded file directly instead of the file object, execute this script with the following parameter:
    -outputtype=file
    
    In this way, the transferred file object is converted directly back to the file
    Be careful with files that could potentially be malicious.

    Parameter: 
    Required: -path         -> The path to the file to be copied
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-file -path=C:\Windows\System32\drivers\etc\hosts
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-file -path=C:\Windows\System32\drivers\etc\hosts -outputtype=file
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-file -path="C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" -outputtype=file
.Notes
    Author: Nico Thelen & Kansa - https://github.com/davehull/Kansa/blob/master/Modules/Disk/Get-File.ps1
#>

param (
    [Parameter(Mandatory=$true)]
    [hashtable]$file_to_copy
)

## Get arguments from param dict
$file = $file_to_copy['path']


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

    Write-Output $obj

} else {
    Write-Output $null
}

