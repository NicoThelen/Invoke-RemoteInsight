################################################
## Author: Nico Thelen                        ##
## MIT License                                ##
## www.linkedin.com/in/nico-thelen-5bbb6a289  ##
################################################

##################################################################################################################

<#
.SYNOPSIS
Invoke-RemoteInsight is a live remote forensic tool for the investigation of Windows systems. 
It is designed to give security experts a reasonable insight into running, network-connected systems without the need of 3rd-Party tools and without having to seize them. 
It is developed 100% natively in powershell and is designed to be executed on active systems, so there are minor limitations in the range of functions. 
The use case is the confirmation of true or false positives or the strengthening of an existing initial suspicion after receiving the first indicators. 
It is intended to build a bridge between Incident Response from a SOC and a very in-depth, time-consuming and cost-intensive forensic analysis in order to make the analysis of suspicious systems more efficient and reliable. 
.DESCRIPTION
Invoke-RemoteInsight.ps1 is the main program which acts as a loader and provides all basic functions. 
The user is given a "remoteshell"-like feeling by having the highest possible freedom to issue own commands but also to start prefabricated custom commands for analysis. 
Furthermore, a pre-defined config file can be transferred to the tool, which allows the tool to execute commands automatically in fire and forget mode.
This includes logging all activities, session management, processing user input, loading all necessary modules, executing the code on the remote system and handling the output. 
All activities, whether successful or not, are logged and all results and the generated files are hashed. This is intended to ensure the highest possible integrity. 
A new unique session ID is generated at each start. This is used to identify the output folder, the log file as well as the directory on the remote system and to identify the user of the tool.
A modular approach was chosen, which allows you to add your own modules as long as the syntax is adhered to. 
The scripts folder contains all modules that are loaded by the loader and executed on the remote system. 
.INPUTS
None. You can't pipe objects to the tool.
.OUTPUTS
It is not intended that the output of the tool is passed on directly via pipe.
The tool generates output both live on the console and in a specific folder. 
This can be partially influenced by the user using parameters. 
All results are written to a folder called output_*session_ID* in the same directory.
#>
##################################################################################################################

#################################################### SETTINGS ####################################################
# Generate needed variables

$random_Hex = -join ((Get-Random -Minimum 0 -Maximum 65536).ToString("X4"))
$session_ID = "$($random_Hex)_$($env:USERNAME)_$(Get-Date -Format "yyyy-MM-dd")" # Create Unique Session ID
$script_loc = $PSScriptRoot                                         # Current location of the executed script
$output_dir = "$script_loc\outputs_$session_ID"                     # Directory to store results
$log_loc = "$script_loc\log_$session_ID.log"                        # Set up logging to a file
$script_path = "$script_loc\scripts"                                # Path to the .ps1 scripts
$ext_loc = "$script_loc\ext"                                        # Path to files that are copied to the remote system
$global:output_ID = 0                                               # ID for output files

##################################################################################################################

#################################################### FUNCTIONS ###################################################

# Log actions
function logging {
    param (
        [string]$message,
        [string]$type
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $log_entry = "$timestamp, $type, $message"
    $log_entry | Out-File -FilePath $log_loc -Append
}


# Checking required settings to run the tool
function check_requirements {
    
    Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; Write-Host "Checking Powershell remoting requirements...`n"

    # Checking running winRM service
    $winrm_service_running = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrm_service_running -and $winrm_service_running.Status -eq 'Running') {
        Write-Host "[i] " -NoNewline -ForegroundColor Green; Write-Host "WinRM Service: Running"
        $service_check = $True
    } else {
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "WinRM Service: Not running"
        $service_check = $False
    }
    
    # Checking if remoting is enabled
    if (Test-WSMan -ErrorAction SilentlyContinue) {
        Write-Host "[i] " -NoNewline -ForegroundColor Green; Write-Host "PowerShell Remoting: Enabled"
        $remoting_check = $True
    } else {
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "PowerShell Remoting: Not enabled"
        $remoting_check = $False
    }

    # Checking firewall rule (German Version)
    $firewall_rule =  Get-NetFirewallRule -DisplayGroup "Windows-Remoteverwaltung" -ErrorAction SilentlyContinue
    if ($firewall_rule -and $firewall_rule.Enabled -eq 'True') {
        Write-Host "[i] " -NoNewline -ForegroundColor Green; Write-Host "Firewall: Allows WinRM traffic"
        $firewall_check = $True
    } else {
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "Firewall: Blocks WinRM traffic"
        $firewall_check = $False
    }

    # Checking winRM listener
    try {
        Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction SilentlyContinue > $null
        Write-Host "[i] " -NoNewline -ForegroundColor Green; Write-Host "WinRM Listener: Configured"
        $listener_check = $True
    }
    catch {
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "WinRM Listener: Not configured"
        $listener_check = $False
    }

    # Checking user privilege
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "[i] " -NoNewline -ForegroundColor Green; Write-Host "Current Powershell-Session: Administrator"
        $admin_check = $True
    } else {
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "Current Powershell-Session: Not administrator"
        $admin_check = $False
    }

    if ($service_check -and $remoting_check -and $firewall_check -and $listener_check -and $admin_check) {
        Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; Write-Host "All requirements are met"
        logging "initialisiation successfull, all requirements are met" "success"
    } else {
        Write-Host "`n[!] " -NoNewline -ForegroundColor Red; Write-Host "Not all requirements have been met, there may be errors or limitations in the tool"
        logging "initialisiation error, not all requirements are met" "fail"
    }

    wait_user
}


# Display banner
function welcome {
    Clear-Host
    $banner = @"
 ___                 _                  ____                      _       ___           _       _     _     
|_ _|_ ____   _____ | | _____          |  _ \ ___ _ __ ___   ___ | |_ ___|_ _|_ __  ___(_) __ _| |__ | |_   
 | || '_ \ \ / / _ \| |/ / _ \  _____  | |_) / _ \ '_ ` _  \ / _ \| __/ _ \| || '_ \/ __| |/ _ ` | '_ \| __|  
 | || | | \ V / (_) |   <  __/ |_____| |  _ <  __/ | | | | | (_) | | | __/| || | | \__ \ | (_| | | | | |_      
|___|_| |_|\_/ \___/|_|\_\___|         |_| \_\___|_| |_| |_|\___/\___\___|___|_| |_|___/_|\__, |_| |_|\__|     
                                                                                          |___/              
"@
    $console_width = $Host.UI.RawUI.WindowSize.Width

    # Calculate the maximum length of any line in the ASCII art
    $max_length = ($banner -split "`r`n" | Measure-Object -Property Length -Maximum).Maximum
    
    Write-Host ("-" * ($console_width -1)) -ForegroundColor Yellow 
    # Write each line of the ASCII art centered horizontally
    $banner -split "`r`n" | ForEach-Object {
        # Calculate padding based on the maximum line length
        $padding = [math]::Max([math]::Floor(($console_width - $max_length) / 2), 0)
        Write-Host (" " * $padding + $_)
    }
    Write-Host ("-" * ($console_width -1)) -ForegroundColor Yellow 
    Write-Host "Session ID: " -NoNewline -ForegroundColor Yellow; Write-Host $session_ID 
    if ($target_host -and $target_ip) {                
        Write-Host "Targetsystem: " -NoNewline -ForegroundColor Yellow; Write-Host "$target_host - $target_ip"
    }
    if ($user -and $sid) {                
        Write-Host "Targetuser: " -NoNewline -ForegroundColor Yellow; Write-Host "$user - $sid"
    }
} 


# Translate target IP to Hostname
function ip_to_host {
    param (
        [string]$target_ip
    )

    try {
        $hostname = [System.Net.Dns]::GetHostEntry($target_ip).HostName
        logging "User provided target IP, $target_ip" "info"
        logging "Resolving IP to hostname, $target_ip, $hostname" "info"
        return $hostname
    } catch {
        logging "User provided target IP, $target_ip, resolving to hostname failed" "fail"
        return $null
    }
}


# Translate target Hostname to IP
function host_to_ip {
    param (
        [string]$target_hostname
    )

    try {
        $ip = [System.Net.Dns]::GetHostAddresses($target_hostname) | Where-Object -Property AddressFamily -notlike "*v6*"
        logging "User provided target hostname, $target_hostname" "info"
        logging "Resolving hostname to IP, $target_hostname, $ip" "info"
        return $ip
    } catch {
        logging "User provided target hostname, $target_hostname, resolving to IP failed" "fail"
        return $null
    }
}


# Establish session to target system
function start_session {
    param (
        [string]$target_host
    )

    try {
        $session = New-PSSession -ComputerName $target_host -ErrorAction Stop
        logging "Session started successfully for $target_host, $session" "success"
        return $session
    } catch {
        logging "Failed to create session, $target_host" "fail"
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "Failed to create session for '$target_host': $_"
        return $null
    }
}


# Check connection to the target
function check_status { 
    param (
        [string]$target_host
    )

    if ($target_host) {
        Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; Write-Host "Checking connection`n"
        if (Test-Connection -ComputerName $target_host -Quiet){
            Write-Host "[i] " -NoNewline -ForegroundColor Yellow; Write-Host "$target_host is online"
            logging "Target is online, $target_host" "info" 
        } else {
            Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "$target_host is offline"
            logging "Target is offline, $target_host" "fail" 
        }
    } else {
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "No target selected"
    }
}


# Restart session to target system
function restart_session {
    param (
        [string]$target_host, 
        [object]$session
    )

    try {
        Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; Write-Host "Reconnecting.."
        Remove-PSSession $session
        logging "Session terminated successfully for $target_host" "success"
        $session = start_session $target_host
        check_status $target_host
        return $session
    } catch {
        logging "Failed to restart session, $target_host, $_" "fail"
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "Failed to restart session for '$target_host': $_"
        return $null
    }
}


# Choose/change target system
function get_target {
    while ($true) {
        Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; $target = Read-Host "Enter remote target by IP or Hostname"

        if ([System.Net.IPAddress]::TryParse($target, [ref]$null)) {
            $target_host = ip_to_host $target
            $target_ip = $target
        } else {
            $target_ip = host_to_ip $target
            $target_host = $target
        }

        logging "User chose/changed target, $target_host, $target_ip" "info"

        if ($session) {
            Remove-PSSession $session
            logging "Closed previous session, $target_host" "info"
        }

        $session = start_session $target_host
        if ($null -eq $session) {
            Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "Failed to connect to $target_host - Please try again."
        } else {
            return $session, $target_host, $target_ip
        }     
    }
}


# Choose/Change target user
function get_user {
    param(
        [string]$target_user = "null"
    )

    try {
        if ($target_user -eq "null") {
            $userinfo = Invoke-Command -Session $session -ScriptBlock {query user}
            $username = $userinfo[1] | Select-String '\w+' | ForEach-Object { $_.Matches[0].Value }
        } else {
            Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; $username = Read-Host "Enter target username"
        }
        $user = New-Object System.Security.Principal.NTAccount($username)
        $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).Value

        logging "Current user, $user, $sid" "info"
    } catch {
        logging "Failed to retrieve user, $target_host, $_" "fail"
        Write-Host "[!] " -NoNewline -ForegroundColor Red; Write-Host "Failed to get user from '$target_host': $_"
    }

    return $user, $sid
}


# Calculate Hash from command output
function calculate_Hash {
    param (
        [string]$object_to_hash
    )

    if (Test-Path -Path $object_to_hash -PathType Leaf -ErrorAction SilentlyContinue) {
        $hash = (Get-FileHash -Algorithm SHA256 $object_to_hash).hash

    } else {
        $string_to_hash = $object_to_hash -as [string]

        if (-not $string_to_hash) {
            $string_to_hash = $object_to_hash | Out-String  # Convert returned objects or arrays to string
        }

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($string_to_hash)
        $hashBytes = $sha256.ComputeHash($bytes)
        $hash = -join ($hashBytes | ForEach-Object { "{0:x2}" -f $_ })
    }
        
    return $hash
}


# Converts an file object to an actual file - file objects are returned by specific copy-file modules
function process_file_object {
    param (  
        [object]$file_object
    )   

    if ($null -ne $file_object.Content -and $null -ne $file_object.FullName) {
        $compressed_bytes = [System.Convert]::FromBase64String($file_object.Content)    # Decode Base64, GZipped content
        
        $compressed_stream = New-Object System.IO.MemoryStream (,$compressed_bytes) # Create a MemoryStream holding the compressed bytes

        $decompressed_stream = New-Object System.IO.MemoryStream    # Create a new MemoryStream to hold the decompressed data

        $gzipStream = [System.IO.Compression.GZipStream]::new($compressed_stream, [System.IO.Compression.CompressionMode]::Decompress)  # Use GZipStream to decompress the data

        # Copy decompressed data to the decompressed stream
        $gzipStream.CopyTo($decompressed_stream)
        $gzipStream.Close()
        $gzipStream.Dispose()

        $final_location = "$ext_loc\$($file_object.Name)"   # Create copy location from ext_loc and the filename of the path property

        [System.IO.File]::WriteAllBytes($final_location, $decompressed_stream.ToArray())    # Write decompressed data to a new file in the default location

        logging "Copied file object converted to file" "success"
    } else {
        logging "No file object returned" "fail"
    }
}


# Function to print and/or store the result in a file
function process_output {
    param (
        [string]$command,   
        [object]$result,
        [string]$target,
        [string]$output_type,
        [bool]$print_output
    )    

    $result_hash = calculate_Hash $result        # Calculate the hash of the result

    # Generate result file based on executed command and target and ID - without file extension
    $output_file = "$output_dir\$command-$target-$output_ID"   
 
    # Display the result header to show successfull execution and write it to the result file
    Write-Output "`n[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")] '$($command)' Executed - Result Hash: $($result_hash)"

    # Check the returned print_output flag - If the flag is true or the results comes from a default command, the result will be displayed on the terminal        
    if ($print_output) {  
        Write-Output $result
    }

    # Store result in a file based on the given output type
    switch ($output_type) {
        # Store the results as csv output
        'csv' {         
            $result | Export-csv -Path "$output_file.csv" -Force -NoTypeInformation
        } 
        # Store the results as xml output
        'xml' { 
            $result | Export-Clixml -Path "$output_file.xml"
        } 
        # Store the results as txt output
        'txt' { 
            $result | Out-File -FilePath "$output_file.txt"
        }
        # Store the results in original form without modifications or additions
        'org' { 
            $result | Out-File -FilePath $output_file
        } 
        # If the script/module returned a file object the function process_file_object will create a file from it
        'file' { 
            process_file_object $result
        }      
        # In case a invalid value is set
        default {
            logging "Invalid output type, '$output_type', '$output_ID'" "fail"
        }
    }

    logging "Output of command, '$command', '$target', '$output_type', '$output_ID', '$output_file', '$result_hash'" "info"
    $global:output_ID += 1        # Increment the output file ID
}


# Function to pause the execution until the user wants to continue
function wait_user {
    Write-Host "`n`n[i] " -NoNewline -ForegroundColor Yellow; Write-Host "Press any key to continue..."
    Read-Host
}


# Actions to perform if the tool gets terminated
function exit_routine {
    param ( 
        [object]$session
    )

    logging "Script execution ended" "info"

    Remove-PSSession $session
    logging "Remote session closed" "info"
    logging "Creating file hashes" "info" 

    Get-ChildItem -Path $output_dir -Recurse -File | ForEach-Object {           # Calculate file hash for each result file
        $file_path = $_.FullName
        $file_name = $_.Name

        $file_hash = calculate_Hash $file_path

        "$file_name, $file_hash" | Out-File -FilePath "$script_loc\integrity_$session_ID.txt" -Append
    }

    $file_hash = calculate_Hash $log_loc                                       # Calculate file hash for log file
    "$($(Get-Item -Path $log_loc).Name), $file_hash" | Out-File -FilePath "$script_loc\integrity_$session_ID.txt" -Append
}


# Display help for specific commands
function command_help {
    param (
        [string]$params
    )

    $param_Array = $params -split " "
    $command = $param_Array[0]
    $command_path = Resolve-Path "$script_path\*\$command.ps1"
    Invoke-Expression "get-help $("$command_path -ShowWindow")"      # Ignore user params, always use ShowWindow
}


# Displays help to use the tool
function tool_help {
    # Help section about locations
    $locations = @(
        "Tool:`t`t`t`t`t $script_loc"
        "Outputs:`t`t`t`t $output_dir"
        "Log:`t`t`t`t`t $log_loc"
        "Custom Scripts:`t`t`t`t $script_path"
        "External Files:`t`t`t`t $ext_loc"
    )
    # Help section about how to use the commandline in general
    $usage = @(
        "Choose between 3 types of commands:",
        "> Integrated/Local Commands:`t`t`t Used to manage / control the tool",
        "> Custom Commands:`t`t`t`t Execute the modular scripts on the remote target",
        "> Default Powershell Commands:`t`t`t Execute your own arbitrary code on the remote targets (e.g. whoami, cd, ls)",
        "",
        "Just enter a ""Integrated/Local Command"", a ""Custom Command"" or a ""Default Command"" followed by any arguments",
        "Below you can find out more about the use of ""Integrated/Local Commands"" and ""Custom Commands"" and their potential arguments",
        "",
        "Custom Commands - Special (local) parameters:",
        "> *command* -outputtype=[csv|xml|txt|org|file]:`t Determine a specific data type as the output (optional, default: txt)",
        "> *command* -printoutput:`t`t`t Switch to also display the output on the terminal (optional, default: false)",
        "> Use ""="" as separator without space",
        "",
        "Custom Commands - Syntax for remote parameters:",
        "> *command* -parameter1=argument1 -parameter2=""argument with multiple words"" -parameter3=""argument with \""escaped\"" quotation marks""",
        "> Parameters for the custom commands are structured according to the key-value principle",
        "> Use ""="" as separator without space",
        "> To use spaces in the argument (value), the string must be enclosed in quotation mark",
        "> Within the quotation marks, quotation marks can be escaped with ""\"""
    )
    # Help section about predefined integrated commands
    $integrated_Commands = @(
        "fire-and-forget *config_file*:`t`t Lets the tool execute predefined commands fully automatically",
        "change-targetsystem:`t`t`t Switch to a different remote system",
        "change-targetuser:`t`t`t Switch to a different user on the remote system",
        "tool-help:`t`t`t`t Display this help message",
        "get-help *command*:`t`t`t Display full help message for a specific command",
        "check-connection:`t`t`t Testing connection to current target",
        "restart-connection:`t`t`t Restarting the current session",
        "refresh:`t`t`t`t Refresh the terminal",
        "exit:`t`t`t`t`t Exit the tool"
    )

    # Display help message
    Write-Host "`n--------------------------------------------" -ForegroundColor Yellow 
    Write-Host "   Locations:"
    Write-Host "--------------------------------------------" -ForegroundColor Yellow 
    $locations

    Write-Host "`n--------------------------------------------" -ForegroundColor Yellow 
    Write-Host "   Usage:"
    Write-Host "--------------------------------------------" -ForegroundColor Yellow 
    $usage

    Write-Host "`n--------------------------------------------" -ForegroundColor Yellow 
    Write-Host "   Available Integrated/Local Commands:"
    Write-Host "--------------------------------------------" -ForegroundColor Yellow 
    $integrated_Commands | ForEach-Object { Write-Host $_ } 
    
    Write-Host "`n--------------------------------------------" -ForegroundColor Yellow 
    Write-Host "   Available Custom Commands:" 
    Write-Host "--------------------------------------------" -ForegroundColor Yellow 

    $custom_scripts = Get-ChildItem -Path "$script_path" -Recurse -Filter "*.ps1"
    $c_scripts_dir = @()
    foreach ($c_script in $custom_scripts) { 
        # Create a custom object with script name and its parent directory
        $c_scripts_dir += [PSCustomObject]@{
            Path = ($c_script.DirectoryName -replace [regex]::Escape("$script_path\"), "") # Relative directory
            ScriptName = $c_script.BaseName
        }
    }
    # Group scripts by their relative directory
    $grouped_Scripts = $c_scripts_dir | Group-Object -Property Path

    foreach ($group in $grouped_Scripts) {
        Write-Host "`n[" -NoNewline -ForegroundColor Yellow; Write-Host $($group.Name) -NoNewline; Write-Host "]" -ForegroundColor Yellow   # Directory/Group name
        $scripts = $group.Group | ForEach-Object { $_.ScriptName }      # Get all scripts per group

        # Format the scripts into columns
        $columnCount = 6
        $formatted_scripts = @()
        $counter = 0
        $row = ""
        foreach ($script in $scripts) {
            $row += "{0,-35}" -f $script
            $counter++
            if ($counter -ge $columnCount) {
                $formatted_scripts += $row
                $row = ""
                $counter = 0
            }
        }
        # Add remaining scripts to the output if there are any left
        if ($row) { 
            $formatted_scripts += $row 
        }

        $formatted_scripts | ForEach-Object { Write-Host $_ }
    }

    Write-Host "`n----------------" -ForegroundColor Yellow 
    Write-Host "Author: Nico Thelen"
    Write-Host "----------------" -ForegroundColor Yellow 
}


# Process the user input, seperate between command and different parameter types
function process_user_input {
    param (
        [string]$command_params
    )

    $command, $params = $command_params -split " ", 2           # Split the user input into command and parameters

    if (Test-Path "$script_path\*\$command.ps1" -ErrorAction SilentlyContinue) {  
        # Custom command (.ps1 scripts exists) that gets executed remotely 
        # Or special custom commands that are not executed remotely (no .ps1 scripts) but need special parameter handling (hashtable)

        $command_type = "custom"                               
        $output_type = "txt"
        $print_output = $false
        $param_dict = @{}

        # This regex is used to parse parameters in the format:
        # -key:value or -key:"value with spaces and \"escaped\" quotes"
        $param_regex = '(?<!\S)-([\w-]+)=(?:"((?:[^"\\]|\\.)+)"|([^\s]+))'

        if ($params) {
            $params_Array = $params -split " "                      # Split paramter string by space
            
            # Step 1: Iterate throuh parameters to find local params
            foreach ($param in $params_Array) {
                if ($param -like "-outputtype=*") {
                    # Local parameter to change output type
                    $output_type = ($param -split '=', 2)[1]
                } elseif ($param -eq "-printoutput") {
                    # Local parameter to switch terminal output on/off
                    $print_output = $true
                }
            }

            # Step 2: Process the entire parameter string as one and store each remote parameter found in the dict
            if ($params -match $param_regex) {
                foreach($match in [regex]::Matches($params, $param_regex)) {
                    $key = $match.Groups[1].Value                           # Extracting parameter name
                    if ($match.Groups[2].Success) {
                        $value = $match.Groups[2].Value -replace '\\"', '"' # Extracting argument value and remove escaping by replacing \" with "
                    } else {
                        $value = $match.Groups[3].Value                     # Extracting argument value
                    }
                    $param_dict[$key] = $value              # Creating dict entry
                }
            } else {
                return $null, $command_type, $null, $null, $null  # Parameter didnt match syntax, return error
            }
            
        } 

        return $command, $command_type, $output_type, $print_output, $param_dict    # Returns all informations and a hashtable of the provided params/args

    } elseif (($command -eq "get-help") -or ($command -eq "fire-and-forget")) {
        # get-help: Special custom command that is not executed remotely and doesnt need special parameter handling (just raw parameter return no hashtable)
        # fire-and-forget: User startet fire and forget mode and provided a config file, Inside $params is the path to the config file
        $command_type = "custom"                               
        $output_type = "txt"
        $print_output = $false

        return $command, $command_type, $output_type, $print_output, $params     # Returns all informations and the original parameter

    } else {
        # Default command (no .ps1 script exists), assume it's a normal PowerShell command that gets executed remotely    
        $command_type = "default"
        $output_type = "org"
        $print_output = $true
        
        return $command, $command_type, $output_type, $print_output, $null      # Returns all informations but no parameter (they are in $command_type)
    }
}


# Helper function to copy files from the remote client 
function copy_from_client {
    param(
        [hashtable]$remote_param,
        [object]$session
    )
    
    $file_path = $remote_param['path']
    $file_name = Split-Path -Path $file_path -Leaf

    # Calculate hash a first time
    $hash_before_copy = Invoke-Command -Session $session -ScriptBlock {param($file_path) (Get-FileHash -Algorithm SHA256 $file_path).hash} -ArgumentList $file_path
    $hashlist_before_copy = $hash_before_copy -split " "

    # Copy the file from the remote system
    if ($remote_param['recurse'] -eq "recurse") {
        Copy-Item -FromSession $session -Path $file_path -Destination $ext_loc -recurse
    } else {
        Copy-Item -FromSession $session -Path $file_path -Destination $ext_loc
    }

    # Calculate hash a second time
    $hash_after_copy = calculate_Hash "$ext_loc\$file_name"
    $hashlist_after_copy = $hash_after_copy -split " "
    
    # Calculate the hash(es) for a single file or if the path ended with "*" and compare them
    # Exclusion if parameter "recurse" was used
    if (-not $remote_param['recurse'] -eq "recurse") {
        for ($i = 0; $i -lt $hashlist_before_copy.Count; $i++) {
            if ($hashlist_before_copy[$i] -eq $hashlist_after_copy[$i]) {
                logging "Copy integrity check passed, $($hashlist_before_copy[$i])" "success"
            } else {
                logging "Copy integrity check failed, $($hashlist_before_copy[$i]), $($hashlist_after_copy[$i])" "fail"
            }
        }
    }

}


# Helper function to copy files to the remote client 
function copy_to_client {
    param(
        [hashtable]$remote_param,
        [object]$session,
        [string]$target_host
    )

    $remote_loc = "C:\Windows\Temp\$session_ID"
    $file_path = $remote_param['path']
    $file_name = Split-Path -Path $file_path -Leaf

    # Check if the diretory exists on the remote system
    $path_exists = Invoke-Command -Session $session -ScriptBlock {param($remote_loc) Test-Path $remote_loc} -ArgumentList $remote_loc
    if (-not $path_exists) { 
        # If the directory doesnt exist, create it
        logging "Creating folder to copy files, '$remote_loc', '$target_host'" "info"
        Invoke-Command -Session $session -ScriptBlock {param($remote_loc) New-Item -Path $remote_loc -ItemType Directory > $null} -ArgumentList $remote_loc
    }

    # Calculate hash a first time
    $hash_before_copy = calculate_Hash $file_path
    $hashlist_before_copy = $hash_before_copy -split " "

    # Copy the file to the remote system
    if ($remote_param['recurse'] -eq "recurse") {
        Copy-Item -ToSession $session -Path $file_path -Destination $remote_loc -recurse
    } else {
        Copy-Item -ToSession $session -Path $file_path -Destination $remote_loc  
    }

    # Calculate hash a second time
    $hash_after_copy = Invoke-Command -Session $session -ScriptBlock {param($path) (Get-FileHash -Algorithm SHA256 $path).hash} -ArgumentList "$remote_loc\$file_name"
    $hashlist_after_copy = $hash_after_copy -split " "

    # Calculate the hash(es) for a single file or if the path ended with "*" and compare them
    # Exclusion if parameter "recurse" was used
    if (-not $remote_param['recurse'] -eq "recurse") {
        for ($i = 0; $i -lt $hashlist_before_copy.Count; $i++) {
            if ($hashlist_before_copy[$i] -eq $hashlist_after_copy[$i]) {
                logging "Copy integrity check passed, $($hashlist_before_copy[$i])" "success"
            } else {
                logging "Copy integrity check failed, $($hashlist_before_copy[$i]), $($hashlist_after_copy[$i])" "fail"
            }
        }
    }
}


# Execute the commands / scripts on the remote system
function run_commands {
    param(
        [string]$command, 
        [string]$command_type,
        [string]$output_type, 
        [bool]$print_output, 
        [hashtable]$remote_param,
        [string]$command_params,        
        [object]$session,
        [string]$target_host
    )

    if ($command_type -eq "custom" -or $command_type -eq "auto") {
        # If custom command - .ps1 scripts exists and the code gets executed remotely

        try {
            if ($remote_param.Count -gt 0) {   
                # If params provided

                switch ($command) {
                    "iri-copy-from-client" {  
                        # The copy command is treated specially because it does not have to be executed on the remote system but locally
                        try {
                            copy_from_client $remote_param $session
                        } catch {
                            throw
                        }
                    }
                    "iri-copy-to-client" {
                        # The copy command is treated specially because it does not have to be executed on the remote system but locally
                        try {  
                            copy_to_client $remote_param $session $target_host
                        } catch {
                            throw
                        }
                    }
                    Default {
                        # Other custom command that must be executed remotely 
                        try {
                            $command_path = Resolve-Path "$script_path\*\$command.ps1"
                            $result = Invoke-Command -Session $session -FilePath "$command_path" -ArgumentList @($remote_param) -ErrorAction Stop    # Execute custom script with params
                        } catch {
                            throw
                        }
                    }
                }

            } else {     
                # If no params provided        
                $command_path = Resolve-Path "$script_path\*\$command.ps1"                                                   
                $result = Invoke-Command -Session $session -FilePath "$command_path" -ErrorAction Stop      # Execute custom script without params
            }   
            logging "Successfull execution, '$command_params', '$target_host'" "success"

            # If execution created output, call handle output function
            if ($result) { 
                logging "Output settings, '$output_type', '$print_output'" "info"     
                process_output $command $result $target_host $output_type $print_output
            } else {
                logging "No output generated, '$command', '$target_host'" "info"
            }
        } catch {
            Write-Host "`n[!] " -NoNewline -ForegroundColor Red; Write-Host "Error executing '$command' on '$target_host': $_"
            logging "Error executing, '$command', '$target_host', $_" "fail"
        }

        # After completion, wait for user input and refresh terminal (only if its not in FAF (auto) mode)
        if ($command_type -eq "custom") {
            wait_user
            welcome
        }

    } elseif ($command_type -eq "default") {
        # If default command - If no .ps1 script exists, assume it's a normal PowerShell command and the code gets executed remotely        

        try {
            # Pass the whole command (command + optional params) to invoke it remotely
            $result = Invoke-Command -Session $session -ScriptBlock {   
                param($command_string)
                try {  
                    Invoke-Expression $command_string
                } catch {
                    throw
                }
            } -ArgumentList $command_params -ErrorAction Stop
            logging "Successfull execution, '$command_params', '$target_host'" "success"

            # If execution created output, call handle output function
            if ($result) {
                logging "Output settings, '$output_type', '$print_output'" "info"     
                process_output $command $result $target_host $output_type $print_output
            } else {
                logging "No output generated, '$command_params', '$target_host'" "info"
            }
        } catch {
            Write-Host "`n[!] " -NoNewline -ForegroundColor Red; Write-Host "Error executing '$command_params' on '$target_host': $_"
            logging "Error executing, '$command_params', '$target_host', $_" "fail"
        }
        # After completion, the script waits for no input, because no refresh takes place, so that the potential "hands on" work is not disturbed
    } 
}


# Executes a predefined set of commands 
function fire_and_forget {
    param(
        [string]$config_path,
        [object]$session,
        [string]$target_host
    )   

    # Read the config file and convert it to powershell object  
    $json_content = Get-Content -Path $config_path -Raw | ConvertFrom-Json  

    # Iterate through each command/entry in the file
    foreach ($entry in $json_content) {

        $command = $entry.command
        $param_dict = @{}
        $command_type = "auto"
        $output_type = "txt"
        $print_output = $false

        # If parameters are set parse them
        if ($entry.PSObject.Properties.Name -contains "parameters" -and $entry.parameters) {
            $tmp_params = $entry.parameters

            # Iterate through each param and look for "outputtype"
            foreach ($prop in $tmp_params.PSObject.Properties) {
                if ($prop.Name -eq "outputtype") {               
                    $output_type = $prop.Value                           # If user provided a value, overwrite the default (txt)  
                } else {
                    $param_dict[$prop.Name] = $prop.Value
                }
            }
            logging "Attempting to execute command, '$command', '$param_dict'" "FAF"
            run_commands $command $command_type $output_type $print_output $param_dict $($command, $param_dict.ToString()) $session $target_host
        } else {
            logging "Attempting to execute command, '$command'" "FAF"
            run_commands $command $command_type $output_type $print_output $null $command $session $target_host
        }
    }
}


# Main function for controlling the process flow
function control {
    if (-not (Test-Path $output_dir)) { 
        New-Item -Path $output_dir -ItemType Directory > $null
    }

    logging "Session started, $session_ID" "info"  

    welcome                                                     # Display banner for the first time, without targetsystem and targetuser info 
    check_requirements                                          # Check requirements to run the tool
    welcome                                                     # Display banner again after requirements check to clear console
    $session, $target_host, $target_ip = get_target             # Let user choose targetsystem for the first time before starting the loop
    $user, $sid = get_user                                      # Automatically get the targetuser of the chosen targetsystem
    welcome                                                     # Display banner for the third time, now with targetsystem and targetuser info

    try {
        while ($true) {
            # Prompt user to enter command/module and optional arguments
            Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow;  Write-Host "'tool-help' for more informations, 'exit' to exit the tool"

            $command_params = Read-Host "`nInvoke-RemoteInsight@$target_host>" 

            if ([string]::IsNullOrWhiteSpace($command_params)) {
                Write-Host "`n[!] " -NoNewline -ForegroundColor Red; Write-Host "Please enter a valid command"
                continue
            }

            # Process the users input
            $command, $command_type, $output_type, $print_output, $provided_params = process_user_input $command_params   

            $continue = $false

            # Check for integrated/local commands
            switch ($command) {
                'exit' {                                            # Exit the script if the user types 'exit'
                    Write-Host "`n[i] " -NoNewline -ForegroundColor Yellow; Write-Host "Exiting script.."
                    logging "User exited the script" "info"
                    exit
                } 
                'fire-and-forget' {                                # Starting fire and forget
                    logging "User startet fire-and-forget mode" "FAF"
                    fire_and_forget $provided_params $session $target_host
                    $continue = $true
                }
                'tool-help' {                                       # Displays tool help to user
                    logging "User displays tool help" "info"
                    tool_help 
                    wait_user
                    $continue = $true
                }
                'get-help' {                                        # Displays command help to user
                    logging "User displays command help, '$provided_params'" "info"
                    command_help $provided_params 
                    wait_user
                    $continue = $true
                }
                'change-targetsystem' {                             # Changes target system
                    logging "User tries to change target" "info"
                    $session, $target_host, $target_ip = get_target
                    $continue = $true
                }
                'change-targetuser' {                               # Changes target user
                    logging "User tries to change user" "info"
                    $user, $sid = get_user $user
                    $continue = $true
                }
                'check-connection' {                                # Changes target system
                    logging "User testing connection to target" "info"
                    check_status $target_host
                    wait_user
                    $continue = $true
                }
                'restart-connection' {                              # Changes target system
                    logging "User trying to restart session" "info"
                    $session = restart_session $target_host $session
                    wait_user
                    $continue = $true
                }
                'refresh' {
                    logging "User refreshed the terminal" "info"
                    welcome
                    $continue = $true
                }
            }

            if ($continue) {
                continue
            }

            # Switch for more precise logging and interception of parameter errors for custom commands
            switch ($command_type) {
                'custom' {  
                    logging "Attempting to execute custom command, '$command_params'" "info"
                    if ($null -eq $command) {
                        logging "Invalid parameter format, $command_params" "fail"
                        Write-Host "`n[!] " -NoNewline -ForegroundColor Red; Write-Host "Invalid parameter format, expecting -parametername:argument"
                    } else {
                        run_commands $command $command_type $output_type $print_output $provided_params $command_params $session $target_host
                    }
                }
                'default' {
                    logging "Attempting to execute default command, '$command_params'" "info"
                    run_commands $command $command_type $output_type $print_output $provided_params $command_params $session $target_host
                }
            }           
        }
    } finally {     # Starting exit routine - Cleaning up potential artifacts and leftovers and generate file hashes
        exit_routine $session
    }
}

##################################################################################################################

### START TOOL ###
control
##################