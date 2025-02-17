<#
.SYNOPSIS
    Service Failure Informations (Recovery Options)
.DESCRIPTION
    Outputs all services whose recovery options contain commands for executing code.
    This could be abused for malware persistence and is also included in the module: iri-get-persistence
    In depth informations for each service including: 
    - Name
    - Reset_period
    - Commandline
    - Fail_action1
    - Fail_action2
    - Fail_action3
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-failservices
.Notes
    Author: Nico Thelen & Kansa - https://github.com/davehull/Kansa/blob/master/Modules/ASEP/Get-SvcFail.ps1
#>

$service = $False
$reset_period = $False
$cmd = $False
$Fail_action1 = $False
$Fail_action2 = $False
$Fail_action3 = $False

# Query all services and get the services failure configuration details
$services = & $env:windir\system32\sc query | ForEach-Object {
    if ($_ -match "SERVICE_NAME:\s(.*)") { 
        & $env:windir\system32\sc qfailure $($matches[1])
    }
}

$service_list = @()

# Loops through each line in the failure configuration
$services | ForEach-Object {

    $line = $_.Trim()
    if ($line -match "^S.*\:\s(?<SvcName>[-_A-Za-z0-9]+)") {
        if ($service) {
            $o = "" | Select-Object service, reset_period, cmd, Fail_action1, Fail_action2, Fail_action3    # Creating object with specific properties
            $o.service = $service -replace "False", $null                  # Fill the variables / properties with the values from the regex
            $o.reset_period = $reset_period -replace "False", $null
            $o.cmd = $cmd -replace "False", $null
            $o.Fail_action1 = $Fail_action1 -replace "False", $null
            $o.Fail_action2 = $Fail_action2 -replace "False", $null
            $o.Fail_action3 = $Fail_action3 -replace "False", $null

            $service_list += [PSCustomObject]@{                            # Creating a PSObject to store the services failure informations in a list
                Service = $o.service
                Reset_Period = $o.reset_period
                Command_Line = $o.cmd
                Fail_Action1 = $o.Fail_action1
                Fail_Action2 = $o.Fail_action2
                Fail_Action3 = $o.Fail_action3
            }
        }
        $service = $matches['SvcName']
    } elseif ($line -match "^RESE.*\:\s(?<RstP>[0-9]+|INFINITE)") {         # Regex patterns extract specific information from each line
        $reset_period = $matches['RstP']
    } elseif ($line -match "^C.*\:\s(?<Cli>.*)") {
        $cmd = $matches['Cli']
    } elseif ($line -match "^F.*\:\s(?<Fail1>.*)") {
        $Fail_action1 = $matches['Fail1']
        $Fail_action2 = $Fail_action3 = $False
    } elseif ($line -match "^(?<FailNext>REST.*)") {
        if ($Fail_action2) {
            $Fail_action3 = $matches['FailNext']
        } else {
            $Fail_action2 = $matches['FailNext']
        }
    }

}

# Repeate the code to get the last service after the loop ended
$o = "" | Select-Object service, reset_period, cmd, Fail_action1, Fail_action2, Fail_action3       
$o.service = $service
$o.reset_period = $reset_period
$o.cmd = $cmd
$o.Fail_action1 = $Fail_action1
$o.Fail_action2 = $Fail_action2
$o.Fail_action3 = $Fail_action3

$service_list += [PSCustomObject]@{     # Creating a PSObject to store the services failure informations in a list
    Service = $o.service
    Reset_Period = $o.reset_period
    Command_Line = $o.cmd
    Fail_Action1 = $o.Fail_action1
    Fail_Action2 = $o.Fail_action2
    Fail_Action3 = $o.Fail_action3
}

# Filter the results for services with existing command line code 
$cmd_services = $service_list | Where-Object { $_.Command_Line -and $_.Command_Line -ne $null -and $_.Command_Line -ne "" }

Write-Output $cmd_services