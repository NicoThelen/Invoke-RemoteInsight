<#
.SYNOPSIS
    Retrieve Windows Eventlogs
.DESCRIPTION
    Queries specific Windows events logs from the remote system

    The analyst can determine the filters and accuracy via the parameters.
    The script will dynamically create a filter_hashtable based on the parameters and query the log data via get-winevent.

    Parameter:
    Optional: -logname              -> Specifiy the logname
    Optional: -starttime            -> Specifiy the starttime (use only with EndTime)
    Optional: -endtime              -> Specifiy the endtime (use only with StartTime)
    Optional: -timeframe            -> Specifiy the timeframe (retroactive period in minutes, alternative to start and end time)
    Optional: -eventID              -> Specifiy the eventID
    Optional: -providername         -> Specifiy the providername
    Optional: -userID               -> Specifiy the userID (SID)
    Optional: -taskCategory         -> Specifiy the taskCategory
    Optional: -keyword              -> Specifiy the keyword
    Optional: -maxEvents            -> Specifiy the maximal number of Events (number of max events to retrieve)
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-winevents -logname=security
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-winevents -logname=security -timeframe=42
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-winevents -logname=application -eventID=1337 -maxEvents=69
.Notes
    Author: Nico Thelen
#>


param (
    [Parameter(Mandatory=$true)]
    [hashtable]$winevent_filters
)

$filter_hashtable = @{}

# Iterates through the param-hashtable/dict and creates the filterhashtable based on the passed parameters and arguments
foreach($key in $winevent_filters.Keys) {
    switch ($key) {
        'logname' { 
            $filter_hashtable["LogName"] = $winevent_filters[$key]
        }
        'starttime' { 
            $filter_hashtable["StartTime"] = $winevent_filters[$key]    
        }
        'endtime' { 
            $filter_hashtable["EndTime"] = $winevent_filters[$key]    
        }
        'timeframe' { 
            $start_time = (Get-Date).AddMinutes(-$winevent_filters[$key])   # If a timeframe has been specified, the start time is calculated
            $filter_hashtable["StartTime"] = $start_time  
        }
        'eventID' { 
             $filter_hashtable["Id"] = $winevent_filters[$key]   
        }      
        'providername' { 
            $filter_hashtable["ProviderName"] = $winevent_filters[$key]   
        }
        'userID' { 
            $filter_hashtable["UserID"] = $winevent_filters[$key]   
        }
        'taskCategory' { 
            $filter_hashtable["TaskCategory"] = $winevent_filters[$key]   
        }
        'keyword' { 
            $filter_hashtable["Keywords"] = $winevent_filters[$key]   
        }
        'maxEvents'
        {
            $max_events = $winevent_filters[$key]              # max_events is not included in the filterhashtable but serves as an external filter 
        }
    }
}

# Retrieve the windows event logs based on the dynamically created filter hashtable
if ($max_events) {
    $events = Get-WinEvent -FilterHashtable $filter_hashtable -MaxEvents $max_events
} else {
    $events = Get-WinEvent -FilterHashtable $filter_hashtable
}

Write-Output $events
