<#
.SYNOPSIS
    All Services
.DESCRIPTION
    Displays an overview of all services. 
    The following data is collected for each service:
    - Name
    - Displayname
    - Process ID
    - State
    - Startmode
    - Path
    - loaded DLL by svchost
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-services
.Notes
    Author: Nico Thelen & Kansa - https://github.com/davehull/Kansa/blob/master/Modules/ASEP/Get-SvcAll.ps1
#>

$all_services = Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId
$service_list = @()

$all_services | ForEach-Object {
    $dll = "N/A"    # Reset variable for each iteration to prevent incorrect entries
	if ($_.PathName.toLower() -like "*\svchost.exe -k *") {         # If service is svchost we additionally get the loaded dll
        $path, $service = $_.PathName.replace(' -k ', ',').split(',')
			if (test-path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\$($_.Name)\Parameters\") {        # Get dll from registry value of the service
				$reg_svc = Get-Item -path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\$($_.Name)\Parameters\" -ErrorAction SilentlyContinue
				$dll = $reg_svc.GetValue("ServiceDll")
				$dll = [Environment]::ExpandEnvironmentVariables($dll)
			} elseif (Test-Path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\$($_.Name)\") {             # Get dll from alternative registry value of the service
				$reg_svc = Get-Item -path "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\$($_.Name)" -ErrorAction SilentlyContinue
				$dll = $reg_svc.GetValue("Description")
				$dll = $dll -replace ",.*", "" -replace "@", ""
				$dll = [Environment]::ExpandEnvironmentVariables($dll)
			}
    }
    $service_list += [PSCustomObject]@{ 
        Name = $_.Name
        Displayname = $_.DisplayName
        State = $_.State
        Startmode = $_.StartMode
        PathName = $_.PathName
        DLL = $dll
        ProcessID = $_.ProcessId
    }
}


Write-Output $service_list