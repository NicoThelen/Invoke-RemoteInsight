<#
.SYNOPSIS
    Checks various persistence methods
.DESCRIPTION
    Analysis and report of different persistence mechanisms and locations. 
    The following actions are performed:
    
    - Registry Autostart
    - Startup Folder
    - Winlogon Registry Check
    - Scheduled Tasks (only Tasks with executable actions)
    - Scheduled Jobs
    - Services (only automatically starting)
    - Service Failure Informations (Recovery Options)
    - WMI Event Consumer
    - WMI Autorecover MOFs (https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/)
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-analyse-persistence
.Notes
    Author: Nico Thelen & Kansa - https://github.com/davehull/Kansa/blob/master/Modules/ASEP/Get-SvcFail.ps1
#>

###### Startup Folder and Registry ######
$startups = Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User
#########################################


###### Winlogon ######
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$userinit = $((Get-ItemProperty -Path $winlogonPath -Name 'Userinit').Userinit)
$shell = $((Get-ItemProperty -Path $winlogonPath -Name 'Shell').Shell)
#########################################


###### Services ######
$services_sys32 = Get-CimInstance -ClassName Win32_Service | Where-Object{ $_.StartMode -eq "Auto" -and $_.PathName -like "*\system32\*" } | Format-List Name, DisplayName, Description, State, ProcessId, Status, PathName, ServiceType, StartMode, DelayedAutoStart
$services_not_sys32 = Get-CimInstance -ClassName Win32_Service | Where-Object{ $_.StartMode -eq "Auto" -and $_.PathName -notlike "*\system32\*" } | Format-List Name, DisplayName, Description, State, ProcessId, Status, PathName, ServiceType, StartMode, DelayedAutoStart
#########################################


###### Service Fail Configuration ######
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

$cmd_services = $service_list | Where-Object { $_.Command_Line -and $_.Command_Line -ne $null -and $_.Command_Line -ne "" } # Filter the results for services with existing command line code 
#########################################


###### Scheduled Tasks ######
$tasks = Get-CimInstance -Namespace "Root/Microsoft/Windows/TaskScheduler" -ClassName MSFT_ScheduledTask

$task_results = @()
foreach ($task in $tasks) { 
    foreach ($action in $task.Actions) { 
        if ($action.PSObject.TypeNames[0] -like '*MSFT_TaskExecAction') { 
            $details = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName
            $task_results += [PSCustomObject]@{ 
                Path = $task.TaskPath 
                Name = $task.TaskName 
                State = $task.State 
                Next_Run_Time = $details.NextRunTime
                Last_Run_Time = $details.LastRunTime
                Author = $task.Principal.UserId 
                Execute = $action.Execute
                Arguments = $action.Arguments
             }
        } 
    } 
}
#########################################


###### Scheduled Jobs ######
$jobs = Get-ScheduledJob 

$jobs_results = @()
foreach ($job in $jobs) {
    $options = $jobs.Options
    $jobs_results += [PSCustomObject]@{
        Name = $job.Name
        ID = $job.Id
        Enabled = $job.Enabled
        Show_in_TaskScheduler = $options.ShowInTaskScheduler
        Run_elevanted = $options.RunElevated
        Execute = $job.Command
    }
}
#########################################


###### WMI Event Consumer ######
$consumers = Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer | Select-Object __RELPATH, Name # Get all EventConsumer
$cmdConsumers = Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Select-Object __RELPATH, Name, CommandLineTemplate # Get specific CommandLineEventConsumer
$scriptConsumers = Get-WmiObject -Namespace "root\subscription" -Class ActiveScriptEventConsumer | Select-Object __RELPATH, Name, ScriptText # Get specific ActiveScriptEventConsumer
$filters = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Select-Object __RELPATH, Name, Query # Get all EventFilter
$bindings = Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding # Get all FilterToConsumerBinding 

$wmi_result_list = @()

# Correlate filter and consumer with bindings
foreach ($binding in $bindings) {
    $filter = $filters | Where-Object { $_.__RELPATH -like "*$($binding.Filter)*" }

    # Step 1 Check CommandLineEventConsumer
    $consumer = $cmdConsumers | Where-Object { $_.__RELPATH -like "*$($binding.Consumer)*" }
    # Step 2 Check ActiveScriptEventConsumer if no CommandLineEventConsumer is found
    if (-not $consumer) {
        $consumer = $scriptConsumers | Where-Object { $_.__RELPATH -like "*$($binding.Consumer)*" }
    }
    # Step 3 Check default class eventconsumer if still no consumer is found
    if (-not $consumer) {
        $consumer = $consumers | Where-Object { $_.__RELPATH -like "*$($binding.Consumer)*" }
    }

    # Output wmi_result as custom objects
    $wmi_result = [PSCustomObject]@{
        FilterName       = if ($filter) { $filter.Name } else { "N/A" } 
        FilterQuery      = if ($filter) { $filter.Query } else { "N/A" } 
        ConsumerName     = if ($consumer.Name) { $consumer.Name } else { "N/A" }
        ConsumerCommand  = if ($consumer.CommandLineTemplate) { $consumer.CommandLineTemplate } else { "N/A" } 
        ConsumerScript   = if ($consumer.ScriptText) { $consumer.ScriptText } else { "N/A" } 
    }

    $wmi_result_list += $wmi_result
}
#########################################


###### WMI Autorecover MOFs ######

$mofs = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM"
$autorecover_mofs = $mofs.'Autorecover MOFs'
#########################################


Write-Output "`n============= Startup programs ============="
Write-Output "Displays all startup programs listed in the Win32_StartupCommand class"
Write-Output $startups | Format-List 

Write-Output "`n============= Winlogon config ============="
Write-Output "Displays the Winlogon configuration, specifically Userinit and Shell values"
Write-Output "Userinit: " $userinit
Write-Output "Shell: " $shell

Write-Output "`n============= Services in System32 ============="
Write-Output "Services that start automatically from System32"
if ($services_sys32.Count -gt 0) { 
    Write-Output $services_sys32
} else { 
    Write-Output "No matches"
} 

Write-Output "`n============= Services not in System32 ============="
Write-Output "Services that start automatically and are not located in System32"
if ($services_not_sys32.Count -gt 0) { 
    Write-Output $services_not_sys32
} else { 
    Write-Output "No matches"
} 


Write-Output "`n============= Services Recovery Options ============="
Write-Output "Services with recovery options containing commands for executing code"
Write-Output $cmd_services

Write-Output "`n============= Scheduled tasks ============="
Write-Output "Scheduled Tasks with executable actions ('MSFT_TaskExecAction') - Amount: $($task_results.count)"
if ($task_results.Count -gt 0) { 
    Write-Output $task_results | Format-List 
} else { 
    Write-Output "No scheduled tasks with executable actions ('MSFT_TaskExecAction') found"
} 

Write-Output "`n============= Scheduled Jobs ============="
Write-Output "Scheduled Jobs - Amount: $($jobs_results.count)"
if ($jobs_results.Count -gt 0) { 
    Write-Output $jobs_results | Format-List 
} else { 
    Write-Output "No scheduled jobs found"
} 

Write-Output "`n============= WMI Event Consumer ============="
Write-Output "WMI Event Consumer, Filter and Filter-Consumer-Bindings"
Write-Output $wmi_result_list

Write-Output "`n============= WMI Autorecover MOFs ============="
Write-Output "Entries may reference MOF files that no longer exist on disk; attackers might delete them post-compilation"
Write-Output "Not all compiled MOF files appear here; only those with the pragma autorecover directive are listed"
Write-Output "The name recorded in this value could not be the original name, but it will include the folder path where it existed during compilation"
Write-Output $autorecover_mofs