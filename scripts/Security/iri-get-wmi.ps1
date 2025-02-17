<#
.SYNOPSIS
    WMI Event Consumer Analysis
.DESCRIPTION
    Analysis of the WMI EvenConsumer on the system and existing autorecovery entries. 
    The corresponding EventFilter and FilterToConsumerBindings are searched for and merged for the EvenConsumer. 
    The following details are displayed for each event consumer: 
    - Filtername
    - FilterQuery
    - ConsumerName
    - ConsumerCommandline
    - ConsumerScripttext

    This module is also used in iri-get-persistence.
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-wmi
.Notes
    Author: Nico Thelen & Infos from https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics/
#>

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

Write-Output $wmi_result_list
