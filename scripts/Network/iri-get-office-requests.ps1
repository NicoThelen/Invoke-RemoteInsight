<#
.SYNOPSIS
    Office Requests
.DESCRIPTION
    Aggregates the web requests triggered by Microsoft Office for all users.
    Lists the following informations: 
    - Username
    - SID
    - WebRequest URL
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-office-requests
.Notes
    Author: Nico Thelen
#>


$sids = Get-WmiObject Win32_userprofile | Select-Object -ExpandProperty SID     # Get all SIDs
$request_list = @()

# Loop through the registry
foreach($sid in $sids) {
    # Get all requested sites for given user (SID)
    $requests = Get-ChildItem -Path "registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Office\16.0\Common\Internet\Server Cache" -erroraction silentlycontinue | Select-Object -ExpandProperty PSChildName   
    $username = ((New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount])).Value    # Translate current SID to username
    
    # Loop through each request found in the registry, checks simultaneously whether requests have been found and creates a separate entry in the psobject for each one
    foreach($request in $requests) {
        $request_list += [PSCustomObject]@{     # Creating a PSObject to store the user in combination with the office requests                  
            User = $username
            SID = $sid
            WebRequest = $request
        }
    }
}

Write-Output $request_list
