<#
.SYNOPSIS
    Parse Recycle.bin
.DESCRIPTION
    This module aggregates all information from the system's recycle bin. 
    All existing drives and all existing user spaces are taken into account.
    The parsed tool uses the artifacts $I and $R. It is recommended to select -outputtype=csv
    
    The following information is collected from $I (Metadata):
    - SID
    - Drive 
    - ArtifactType
    - RecyclebinFilename
    - RecyclebinFullpath
    - Filesize
    - DeletionTime
    - OriginalFullPath

    The following information is collected from $R (Content):
    - SID
    - Drive 
    - ArtifactType 
    - RecyclebinFilename
    - RecyclebinFullpath
    - Filesize
    - LastWriteTime
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-analyse-recyclebin -outputtype=csv
.Notes
    Author: Nico Thelen
#>

function parse_i_file {
    param(
        [Parameter(Mandatory = $true)]
        [string]$i_file_path
    )

    # Function to parse the $I metadata file.
    # The file structure is assumed as follows:
    # Bytes 0-7:    Header
    # Bytes 8-15:   Original file size
    # Bytes 16-23:  Deletion time
    # Bytes 24-:    Original file path as a Unicode, null-terminated string

    try {
        $bytes = [System.IO.File]::ReadAllBytes($i_file_path)                   # Read the entire file into a byte array
        
        # Check if the file is long enough to contain the expected header and metadata
        if ($bytes.Length -lt 24) {
            return [PSCustomObject]@{
                original_file_size = "NA"
                deletion_time      = "NA"
                original_path      = "NA"
                error_message      = "File '$i_file_path' is too short to parse."
            }
        }
        
        $original_file_size = [BitConverter]::ToInt64($bytes, 8)                # Extract the original file size from bytes 8-15
        $file_time = [BitConverter]::ToInt64($bytes, 16)                        # Extract the deletion time from bytes 16-23.
        $deletion_time = [System.DateTime]::FromFileTime($file_time)            # The deletion time is stored as a 64-bit FILETIME value
        $path_bytes = $bytes[24..($bytes.Length - 1)]                           # Extract the original file path
        $original_path = [System.Text.Encoding]::Unicode.GetString($path_bytes) # The path is stored as a Unicode string starting at byte 24 and is null-terminated
        $original_path = $original_path.Trim([char]0)                           # Take all bytes from index 24 to the end of the array
        
        # Return the parsed metadata in a PSCustomObject.
        return [PSCustomObject]@{
            original_file_size = $original_file_size
            deletion_time      = $deletion_time
            original_path      = $original_path
            error_message      = ""
        }
    }
    catch {
        # In case of any errors during parsing, return an object with error details.
        return [PSCustomObject]@{
            original_file_size = "NA"
            deletion_time      = "NA"
            original_path      = "NA"
            error_message      = "Error parsing '$i_file_path': $_"
        }
    }
}

$results = @()              # Array to collect all found artifacts

# Loop through all file system drives
$drives = Get-PSDrive -PSProvider FileSystem
foreach ($drive in $drives) {

    $recycle_bin_path = Join-Path $drive.Root '$Recycle.Bin'        # Create "$Recycle.Bin" path, it is located at the root of each drive

    # Check if the Recycle Bin folder exists on the drive
    if (Test-Path $recycle_bin_path) {
        $sid_folders = Get-ChildItem -Path $recycle_bin_path -Directory -Force -ErrorAction SilentlyContinue    # Get all subdirectories in the Recycle Bin (Each subdirectory corresponds to a user SID)
        
        foreach ($sid_folder in $sid_folders) {
            $current_sid = $sid_folder.Name
            $files = Get-ChildItem -Path $sid_folder.FullName -File -Force -ErrorAction SilentlyContinue        # Get all files within the current SID folder
            
            foreach ($file in $files) {                                     # Loop through each file          
                if ($file.Name -like '$I*') {                               # If the file name starts with '$I', it is a metadata file
                    $meta_data = parse_i_file $file.FullName                # Parse the metadata file
      
                    # Create a PSCustomObject for the metadata artifact
                    $obj = [PSCustomObject]@{
                        sid                   = $current_sid
                        drive                 = $drive.Name
                        artifact_type         = 'Metadata'
                        recycle_file_name     = $file.Name
                        artefact_file_full_path = $file.FullName
                        file_size             = $meta_data.original_file_size
                        last_write_time       = "N/A"
                        deletion_time         = $meta_data.deletion_time
                        original_path         = $meta_data.original_path
                        error_message         = $meta_data.error_message
                    }
                    $results += $obj
                }
                elseif ($file.Name -like '$R*') {                           # If the file name starts with '$R', it is a content file
                    
                    # For content files, collect basic file information, but not the content itself
                    $obj = [PSCustomObject]@{
                        sid                   = $current_sid
                        drive                 = $drive.Name
                        artifact_type         = 'Content'
                        recycle_file_name     = $file.Name
                        artefact_file_full_path = $file.FullName
                        file_size             = $file.Length
                        last_write_time       = $file.LastWriteTime
                        deletion_time         = "NA"
                        original_path         = "NA"
                        error_message         = ""
                    }
                    $results += $obj
                }
            }
        }
    }
}

Write-Output $results
