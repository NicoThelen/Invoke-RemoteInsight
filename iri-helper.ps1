<#
.SYNOPSIS
    iri Helper: Convert file content
.DESCRIPTION
    Decompresses and decodes a string in memory and outputs the original.
    The compressed and base64 encoded file content string from the file objects of the module 'iri-get-file' is used as input.
    This is necessary if the parameter '-outputtype=file' was not used when using 'iri-get-file', which automatically takes over this task.

    The string can be piped into this script or you can use the classic parameter
    
    Parameter:
    Required if not passed by pipe: -in     -> The content string
    Required: -out                          -> Path and name of the output file
.EXAMPLE
    iri-helper -in "ABC123" -out "C:\Users\analyst\output.file" 
.EXAMPLE
    "ABC123" | iri-helper -out "C:\Users\analyst\output.file" 
.Notes
    Author: Nico Thelen
#>


[CmdletBinding()]
param (  
    [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
    [string]$in, 

    [Parameter(Mandatory=$True)]
    [string]$out
)   

$compressed_bytes = [System.Convert]::FromBase64String($in)    # Decode Base64, GZipped content

$compressed_stream = New-Object System.IO.MemoryStream (,$compressed_bytes) # Create a MemoryStream holding the compressed bytes
$decompressed_stream = New-Object System.IO.MemoryStream    # Create a new MemoryStream to hold the decompressed data

$gzipStream = [System.IO.Compression.GZipStream]::new($compressed_stream, [System.IO.Compression.CompressionMode]::Decompress)  # Use GZipStream to decompress the data

# Copy decompressed data to the decompressed stream
$gzipStream.CopyTo($decompressed_stream)
$gzipStream.Close()
$gzipStream.Dispose()

[System.IO.File]::WriteAllBytes($out, $decompressed_stream.ToArray())    # Write decompressed data to a new file in the default location