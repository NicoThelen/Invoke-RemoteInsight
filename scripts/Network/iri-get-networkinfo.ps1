<#
.SYNOPSIS
    Network Informations
.DESCRIPTION
    Aggregates the following network related informations:
    - Connectivity statistics (general and per port)
    - Routing tables
    - Arp cache
    - Dns client cache
    - All network adapters
    - TCP Connections with process informations
    - UDP Connections with process informations
    - NetSh Configuration
    - Content of hosts file
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-networkinfo
.Notes
    Author: Nico Thelen
#>


$nstat_es = netstat -es 2>&1
$nstat_r = netstat -r 2>&1

$arp_cache = arp -a 2>&1
$dns_cache = Get-DnsClientCache | Format-List

$adapter = Get-NetAdapter | Select-Object Name, InterfaceDescription, InterfaceIndex, @{n="IPAddress";e={(Get-CimInstance win32_networkadapterconfiguration | Where-Object InterfaceIndex -eq $_.InterfaceIndex).IPAddress}}, MacAddress, MediaType, InterfaceOperationalStatus, AdminStatus, LinkSpeed, MediaConnectionState, DriverInformation | Format-List

$tcp_connections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, Remote*, State, CreationTime, @{n="ProcName";e={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{n="ProcPath";e={(Get-Process -Id $_.OwningProcess).Path}}
$udp_endpoints = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, CreationTime, @{n="ProcName";e={(Get-Process -Id $_.OwningProcess).ProcessName}}, @{n="ProcPath";e={(Get-Process -Id $_.OwningProcess).Path}}

$netsh_config = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NetSh"

$hosts_file = get-content -path "C:\Windows\System32\drivers\etc\hosts"


Write-Output "============= Statistics ============="
Write-Output "General and port specific statistics`n"
Write-Output $nstat_es

Write-Output "`n============= Routing Tables =============`n"
Write-Output $nstat_r

Write-Output "`n============= ARP Cache =============`n"
Write-Output $arp_cache

Write-Output "`n============= DNS Cache =============`n"
Write-Output $dns_cache

Write-Output "`n============= Adapters =============`n"
Write-Output $adapter

Write-Output "`n============= TCP Connections ============="
Write-Output "Shows active TCP connections and process informations`n"
Write-Output $tcp_connections

Write-Output "`n============= UDP Connections ============="
Write-Output "Shows active UDP connections and process informations`n"
Write-Output $udp_endpoints

Write-Output "`n============= NetSh Config ============="
Write-Output "Shows content of the NetSh Registry entry`n"
Write-Output $netsh_config

Write-Output "`n============= Hosts file ============="
Write-Output $hosts_file
