<#
.SYNOPSIS
    WMI Autorecover
.DESCRIPTION
    The autorecovery entries are read from the registry. The following conditions should be considered in the interpretation:
    - Entries may reference MOF files that no longer exist on disk; attackers might delete them post-compilation
    - Not all compiled MOF files appear here; only those with the pragma autorecover directive are listed
    - The name recorded in this value could not be the original name, but it will include the folder path where it existed during compilation

    This module is also used in iri-get-persistence.
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-wmi-autorecover
.Notes
    Author: Nico Thelen & Infos from https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/
#>


$mofs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM"
$autorecover_mofs = $mofs.'Autorecover MOFs'

Write-Output $autorecover_mofs
