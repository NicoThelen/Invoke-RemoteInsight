<#
.SYNOPSIS
    Driver Informations
.DESCRIPTION
    Returns information about all drivers on the system.
    The following details are displayed for the drivers:
    - Driver
    - OriginalFileName
    - SHA256 Hash
    - Version
    - ClassDescription
    - ClassName
    - BootCritical
    - DriverSignature
    - ProviderName
    - Date
    - LogPath
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-drivers
.Notes
    Author: Nico Thelen
#>


$drivers = Get-WindowsDriver -All -Online | Select-Object Driver, OriginalFileName, @{n="SHA256 Hash";e={(Get-FileHash -Algorithm SHA256 -Path $_.OriginalFileName).Hash}}, Version, ClassDescription, ClassName, BootCritical, DriverSignature, ProviderName, Date, LogPath

Write-Output $drivers
