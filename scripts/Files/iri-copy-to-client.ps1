<#
.SYNOPSIS
    Copy to Client
.DESCRIPTION
    Copies a file to the remote system.
    The remote destination is always the following: "C:\Windows\Temp\*session_ID*"
    The local source, meaning the file path of the file to be copied, must be specified.

    Note: This module / script is only used for the sake of completeness and to display help. 
    The actual code has been implemented directly in the invoke-remoteinsight.ps1 loader.

    Parameter: 
    Required: -path         -> The local path to the file to be copied to the remote system 
    Optional: -recurse      -> If a directory has been specified, this parameter can be used to reference the entire content
                            -> Syntax: -recurse=recurse
                            -> Alternative (not recommended): Alternatively, a "*" at the end of the path can replace the recurse flag 
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-copy-to-client -path=Path\to\file
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-copy-to-client -path=Path\to\file\ -recurse=recurse
.EXAMPLE    
    Invoke-RemoteInsight@*TargetSystem*>: iri-copy-to-client -path=Path\to\file\*
.Notes
    Author: Nico Thelen
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$path,
    [Parameter(Mandatory=$true)]
    [string]$recurse
)

########################################################################################
# The actual code has been implemented directly in the invoke-remoteinsight.ps1 loader #
########################################################################################