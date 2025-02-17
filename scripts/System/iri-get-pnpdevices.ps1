<#
.SYNOPSIS
    All PNP Devices
.DESCRIPTION
    Lists all available Plug and Play (PnP) devices for the system. 
    There is no filtering for the device class. 
    The following information is collected:
    - Name
    - Description
    - DeviceID
    - HardwareID
    - Manufacturer
    - PNPClass
    - Present
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-pnpdevices
.Notes
    Author: Nico Thelen
#>


$pnp_results = @()

$data = Get-PnpDevice -ErrorAction SilentlyContinue | Select-Object Name, Description, DeviceId, HardwareId, Manufacturer, PNPClass, Present    # Get all pnp devices

foreach ($device in $data) {
    $pnp_results += [PSCustomObject]@{      # Creation of a PSObject instead of the straightforward “simpler” output to make potential extensions or filtering easier in the future
        Name = $device.Name 
        Description = $device.Description 
        DeviceId = $device.DeviceId 
        HardwareId = $device.HardwareId
        Manufacturer = $device.Manufacturer
        PNPClass = $device.PNPClass
        Present = $device.Present
    }
}

Write-Output $pnp_results
