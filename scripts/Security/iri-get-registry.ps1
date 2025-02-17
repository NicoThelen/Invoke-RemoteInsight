<#
.SYNOPSIS
    Scan Registry
.DESCRIPTION
    This module provides a type of "snapshot" of the registry.
    Starting from a provided registry key, this and all subkeys are processed recursively.
    When providing a HKU Key, use sid as a placeholder to query all users.

    If no key and no scantype is specified, the tool uses its own predefined set of keys with a deepscan.
    
    There are also 2 scan types: 
    - Normal scan only lists all keys and provides an overview 
    - (Default) Deep scan returns the respective names and values in addition to its key (May take some time)

    Predefined Keys:
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\Run",                                         # potential persistence mechanism
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\RunOnce",                                     # suspicious if used for malicious payloads
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",                 # changes may indicate redirection or misconfiguration
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",                      # verify legitimate folder paths
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",                             # unusual entries can signal compromise
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\RunServices",                                 # monitor for unauthorized programs
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\Policies",                                    # modifications may hide restrictions or malicious settings
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",                         # tracks recently opened documents, useful for forensic timelines
    - "HKU\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",           # records recent file accesses via common dialogs, aiding in activity reconstruction
    - "HKLM\Software\Microsoft\Windows\CurrentVersion\Run",                                            # common target for persistence mechanisms
    - "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",                                        # can launch malicious code on boot
    - "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",                         # verify integrity of system folder paths
    - "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",                    # important for standard folder configurations
    - "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",                                # check for abnormal entries
    - "HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",                                    # potential abuse by malware
    - "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies",                                       # altered settings may hide malicious activity
    - "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",                # debugger hijacking often used to intercept or subvert process execution
    - "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",                                    # modifications can affect login behavior and security
    - "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",                                     # used for DLL injection and persistence
    - "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",                                # monitor cross-architecture persistence
    - "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",                            # monitor cross-architecture persistence
    - "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"     # may indicate manipulation of prefetch behavior for persistence or obfuscation

    Parameter:
    Optional: -path         -> This parameter allows you to specify a registry key (Default: predefined set of keys)
    Optional: -scan         -> This switch determines the level of detail and the performance of the scan (Default: deep)
                            -> Syntax: -scan=normal
.EXAMPLE 
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-registry 
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-registry -path="registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-registry -path="registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows" -scan=normal
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-registry -scan=normal
.Notes
    Author: Nico Thelen
#>

param (
    [hashtable]$params
)

$reg_loc_param = $params['path']
$scan_type = $params['scan']


$registry_locations = @(
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Run",                                                # potential persistence mechanism
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\RunOnce",                                            # suspicious if used for malicious payloads
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",                        # changes may indicate redirection or misconfiguration
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",                             # verify legitimate folder paths
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",                                    # unusual entries can signal compromise
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\RunServices",                                        # monitor for unauthorized programs
    "registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Policies",                                           # modifications may hide restrictions or malicious settings
    "Registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",                                # tracks recently opened documents, useful for forensic timelines
    "Registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",                  # records recent file accesses via common dialogs, aiding in activity reconstruction
    "Registry::HKEY_USERS\sid\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",               # records recent file accesses via common dialogs, aiding in activity reconstruction
    "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",                                            # common target for persistence mechanisms
    "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",                                        # can launch malicious code on boot
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",                         # verify integrity of system folder paths
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",                    # important for standard folder configurations
    "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",                                # check for abnormal entries
    "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices",                                    # potential abuse by malware
    "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies",                                       # altered settings may hide malicious activity
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",                # debugger hijacking often used to intercept or subvert process execution or persistence
    "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",                                    # modifications can affect login behavior and security
    "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows",                                     # used for DLL injection and persistence
    "registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",                                # monitor cross-architecture persistence
    "registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",                            # monitor cross-architecture persistence
    "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"     # may indicate manipulation of prefetch behavior for persistence or obfuscation
)

$sids = Get-WmiObject Win32_userprofile | Select-Object -ExpandProperty SID     # Get all SIDs


# Helper function to convert byte arrays to hexadecimal strings
function convert_to_hex ($byte_array) {
    if ($byte_array -is [byte[]]) {
        return ($byte_array | ForEach-Object { $_.ToString("X2") }) -join " "
    }
    return $byte_array  # Return the value as-is if it's not a byte array
}


function deep_scan {
    param(
        $registry_locations, 
        [ref]$reg_dir
    )
    
    function get_reg_values_deep {
        param(
            [string]$path, 
            [ref]$reg_dir
        )

        try {
            $keys = Get-Item -ErrorAction Stop $path | Select-Object -ExpandProperty Property       # Retrieve properties of the current key

            if ($null -ne $keys) {
                $reg_dir.Value[$path] = @{}        # Create new (nested) dict with registry key as key in the 'data dict'
                foreach ($key in $keys) {
                    try {
                        $value = Get-ItemPropertyValue -Path $path -Name $key -ErrorAction Stop     # Retrieve properties for each key
                        $reg_dir.Value[$path][$key] = $value                                           # Store properties as value of nested dict ('key dict' in 'data dict')
                    } catch {
                        $reg_dir.Value[$path][$key] = "Error: $($_.Exception.Message)"
                    }
                }
            }

            # Retrieve and recurse into subkeys
            $child_keys = Get-Item -ErrorAction Stop $path | Get-ChildItem -ErrorAction Stop
            foreach ($child_key in $child_keys) {
                get_reg_values_deep -Path $child_key.PSPath -Data $reg_dir 
            }
        } catch {
            $reg_dir.Value[$path] = @{ "Error" = "Error: $($_.Exception.Message)" }
        }
    }

    # Iterate through all given registry keys
    foreach ($loc in $registry_locations) {
        try {
            $childs = Get-ChildItem -Path $loc -ErrorAction Stop        # Enumerate subkeys of given registry key
            if (-not $childs) {
                get_reg_values_deep $loc $reg_dir                   # Start routine for the given registry key directly
            } else {
                # Iterate through all childs of given registry key and start the routine
                foreach ($child in $childs) {
                    get_reg_values_deep $child.PSPath $reg_dir
                }
            }
        } catch {
            $reg_dir.Value[$loc] = @{ "Error" = "Error: $($_.Exception.Message)" }
        }
    }
}


function normal_scan {
    param(
        $registry_locations,
        [ref]$result
    )

    # Iterate through all given registry keys
    foreach ($loc in $registry_locations) {
        try {
            $childs = Get-ChildItem -Recurse -Path $loc -ErrorAction Stop | ForEach-Object name      # Enumerate subkeys of given registry key
            $result.Value += $childs
        } catch {
            $result.Value += "Error at $loc"
        }
    }
}


$reg_dir = @{}      # Initialize the data hash table for deep scan, we use a reference of this dict to update it directly from the deep_scan function
$result = @()       # Initialize result list, its used to store the results of reg_dir for deepscans or as reference to update it directly from the normal_scan function

# Check if the user provided a registry key
if ($reg_loc_param) {
    # Check if user chose normal scan, default is deep, so if the var doesnt exist or is not 'normal' the deep scan starts
    if ($scan_type -ne "normal") {
        foreach ($sid in $sids) {                                              
            $dynamic_reg_loc_param = $reg_loc_param -replace 'sid', $sid        # Replace sid in the provided registry key
            deep_scan $dynamic_reg_loc_param ([ref]$reg_dir)                    # Invoke the registry scanning function for this SID
        }
    } else {
        foreach ($sid in $sids) {
            $dynamic_reg_loc_param = $reg_loc_param -replace 'sid', $sid        
            normal_scan $dynamic_reg_loc_param ([ref]$result)                  
        }
    }
} else {
    if ($scan_type -ne "normal") {
        foreach ($sid in $sids) {
            $dynamic_registry_locations = $registry_locations -replace 'sid', $sid  # Replace sid in the registry locations template
            deep_scan $dynamic_registry_locations ([ref]$reg_dir)                      # Invoke the registry scanning function for this SID
        }
    } else {
        foreach ($sid in $sids) {
            $dynamic_registry_locations = $registry_locations -replace 'sid', $sid  
            normal_scan $dynamic_registry_locations ([ref]$result)                  
        }
    }
}
            
# After a deepscan the results from the reg_dir are saved in result, a normalscan saved its output directly into result
if ($scan_type -ne "normal") {
    # Iterate over collected data and format it
    foreach ($loc in $reg_dir.Keys) {
        foreach ($key in $reg_dir[$loc].Keys) {
            $value = $reg_dir[$loc][$key]

            # Check and convert binary data to a readable hexadecimal string
            if ($value -is [string] -and $value.StartsWith("Error:")) {
                $converted_value = $value
            } else {
                $converted_value = convert_to_hex $value
            }

            # Add each record as a PSObject
            $result += [PSCustomObject]@{
                Registry_Key = $loc
                Property = $key
                Value = $converted_value
            }
        }
    }
}

Write-Output $result
