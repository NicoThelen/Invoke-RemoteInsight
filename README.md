# Invoke-Remoteinsight

## Description
Invoke-RemoteInsight is a `live remote forensic tool` for the investigation of Windows systems. \
It is designed to give security experts a reasonable insight into running, network-connected systems without the need of 3rd-Party tools and without having to seize them. \
It is developed `100% natively in powershell` and is designed to be executed on active systems, so there are minor limitations in the range of functions. The user is given a `"remoteshell"-like feeling` by having the highest possible freedom. 

![IRI Terminal](https://github.com/NicoThelen/Invoke-RemoteInsight/blob/main/images/iri.png)

## Use Case

The confirmation of true or false positives or the strengthening of an existing initial suspicion after receiving the first indicators. \
It is intended to build a bridge between Incident Response from a SOC and a very in-depth, time-consuming and cost-intensive forensic analysis in order to make the analysis of suspicious systems more efficient and reliable. 
> [!WARNING]
> The tool was developed and tested in my own devlab domain. This consists of a DC and two Windows 11 domain clients as well as corresponding domain users and an analyst user with the necessary elevated rights. No guarantee if and how the tool works in other real enterprise environments. 

## Features

> [!NOTE]
> A detailed description of all functionalities can always be found in the synopsis, both for the main tool and all modules. At the end of the execution, a hash is created from all the generated outputs and these are written to an extra integrity (integrity_*sessionID*.txt) file. \
A detailed function description can also be displayed in the tool using `tool-help` or `get-help`

Much attention was paid to preserving the integrity of all actions and logging so as not to potentially compromise subsequent forensic analysis. A modular approach has been chosen that allows you to add your own modules as long as the syntax is respected.

* `logging` all users and tools activities - whether successful or not
* `session management` - generates unique session IDs to assign all actions to a case and analyst
* `processing user input` - special processing of user input to give the analyst maximum freedom
* `processing the output` - output in txt or csv or xml or the original format as well as generation of a hash and organized storage
* `Modules` with extensive functions - All modules offer enhanced, detailed functions and aggregate various data for improved analysis (e.g. all iri-analysis modules, iri-get-registry, iri-get-services, iri-get-wmi, ..)

### Types of commands

* `Integrated/Local Commands` - Used to manage/control the tool
* `Custom Commands` - Execute the modular prefabricated scripts/modules on the remote target
* `Default Powershell Commands` - Execute your own code on the remote system (e.g. whoami, cd, ls)
* `fire-and-forget` - Provide the tool a predefined config file to put the tool in a fire-and-forget mode that executes all commands

### Directory Structure

The tool uses the following directory structure:
* ext -> directory for external files (files to be copied to or received by the remote system)      
* scripts -> root directory for all modules/scripts
    * Access
    * Files
    * Network
    * Other
    * Security
    * System
* outputs_*sessionID* -> directory created at runtime, directory for all outputs
* invoke-remoteinsight.ps1
* iri-helper.ps1
* log_*sessionID*.log -> file created at runtime, logging of all activities
* integrity_*sessionID*.txt -> file created after runtime, contains hashes of all output files
  
![Dir Structure](https://github.com/NicoThelen/Invoke-RemoteInsight/blob/main/images/directory_structure.png)

## Scripts/Modules

The following modules are available and can be called up with the tool. Each of the modules has its own synopsis and its help can be displayed with `get-help *module name*`. \
The modules all offer added value compared to potentially existing similar native powershell cmdlets. Some modules run without parameters, some require one or more parameters or can be specified with optional parameters. All modules support special locale parameters.


| Access            | Files                 | Network                   | System                | Security                 | Security                       |Other
| ----------------- | --------------------- | ------------------------- | --------------------- | ------------------------ | ------------------------------ |------------------
| iri-get-accounts  | iri-copy-from-client  | iri-get-namedpipes        | iri-get-drivers       | iri-analyse-ads          | iri-get-scheduledjobs          |iri-send-message
| iri-get-groups    | iri-copy-to-client    | iri-get-netdrives         | iri-get-localdrives   | iri-analyse-persistence  | iri-get-scheduledtasks         |
| iri-get-profiles  | iri-get-dir           | iri-get-networkinfo       | iri-get-pnpdevices    | iri-analyse-processes    | iri-get-winevents              |
|                   | iri-get-file          | iri-get-office-requests   | iri-get-products      | iri-analyse-recyclebin   | iri-get-winevents-officealerts |
|                   | iri-get-filebyhash    | iri-get-smbsessions       | iri-get-systeminfo    | iri-get-ads              | iri-get-wmi                    |
|                   | iri-get-filebyname    | iri-get-smbshares         |                       | iri-get-process          | iri-get-wmi-autorecover        |
|                   | iri-get-openfiles     |                           |                       | iri-get-failservices     | iri-get-hashes                 |
|                   |                       |                           |                       | iri-get-services         | iri-get-certs                  |
|                   |                       |                           |                       | iri-get-registry         |                                |
                                                                                              

## Usage 

### Usage requirements

The tool runs natively in Powershell without the need for 3rd party software.
Also, all Powershell functions used should be part of the default repertoire, no further Powershell modules will need to be imported. \
The following requirements should be met in order to use the tool. An automatic check is carried out after the tool is started.
* Running WinRM service
* Firewall allows WinRM traffic
* WinRM listener is configured
* Tool runs with administrator rights

### Usage Hints

> [!TIP]
> When using the tool for the first time, it is recommended to use `tool-help` after the tool has been started, the target system has been selected and a connection has been established. \
> It is advisable to read the help page for a module via `get-help` in order to understand potential parameters, the information collected and how it works. This can help to analyse the results or output the result in a suitable format using -outputtype

> [!NOTE]
> Special feature - Fire-and-Forget (FAF): In order to enable uniform and standardized analyses, various "analysis routines" can be created in advance. This means that even less experienced analysts can carry out an analysis without knowledge of the tool. A example config file can be found in this repo `"example_basic_triage_fireandforget.json"`.  Fire-and-Forget only supports `Custom Commands`.

![FAF](https://github.com/NicoThelen/Invoke-RemoteInsight/blob/main/images/faf.png)

> [!NOTE]
> There are 2 options for transferring files from the remote system: `iri-get-file` and `iri-copy-from-client`:
> * `iri-copy-from-client` transfers the file in its original state
> * `iri-get-file` copies the metadata and compresses and base64 encodes the actual content
>    * It is also used in other modules (e.g. `get-filebyhash`, `get-filebyname`)
>    * In order to translate the content into the original version afterwards, the `iri-helper` should be used
>    * Alternatively, if this should be done immediately at runtime, the parameter `-outputtype=file` should be used

### Usage Flow

1. Provide a Hostname or IP as the remote system to analyse \
*>* The currently logged in user will be automatically set as target user

2. Choose between 3 types of commands \
*>* Integrated/Local Commands \
*>* Custom Commands \
*>* Default Powershell Commands 

3. Just enter one of them followed by any arguments

4. `Integrated/Local Commands`: \
*>* -forget *config_file*: Lets the tool execute predefined commands fully automatically \
*>* change-targetsystem: Switch to a different remote system \
*>* change-targetuser: Switch to a different user on the remote system \
*>* tool-help: Display this help message \
*>* get-help *command*: Display full help message for a specific command \
*>* check-connection: Testing connection to current target \
*>* restart-connection: Restarting the current session \
*>* refresh: Refresh the terminal \
*>* exit: Exit the tool

5. `Custom Commands` - Special (local) parameters: \
*>* *command* -outputtype=[csv|xml|txt|org|file] (optional, default: txt) \
*>* *command* -printoutput: (optional, default: false) \
*>* Use "=" as separator without space

6. `Custom Commands` - Syntax for remote parameters: \
*>* *command* -parameter1=argument1 -parameter2="argument with multiple words" -parameter3="argument with \\"escaped\\" quotation marks" \
*>* Parameters for the custom commands are structured according to the key-value principle \
*>* Use "=" as separator without space \
*>* To use spaces in the argument (value), the string must be enclosed in quotation mark \
*>* Within the quotation marks, quotation marks can be escaped with "\\"

7. `Default Powershell Commands`: \
*>* All types of Powershell commands can be executed \
*>* These native, non-module, commands are additionally output in the terminal by default to ensure a better flow

### Usage Examples

Get Windows Events
```powershell
# Get all Security Events with EventID 1337 and get max 69 Events
iri-get-winevents -logname=Security -eventID=1337 -maxEvents=69
# Get all Security Events between "01-01-2025 15:00-18:00"
iri-get-winevents -logname=Security -starttime="01-01-2025 15:00" -endtime="01-01-2025 18:00" 
# Get all System Events of the last 240 minutes and output it as csv
iri-get-winevents -logname=System -timeframe=240 -outputtype=csv
```
Get and analyse Windows Processes
```powershell
# Get a list of all processes + extended informations for each process
iri-get-processes
# Start a in depth analysis of a given process
iri-analyse-process -processid=1337
```
List and analyse files ADS
```powershell
# List the ADS and more detailed informations for the ByteCodeGenerator.exe
iri-get-ads -path=C:\Windows\System32\ByteCodeGenerator.exe
# List the ADS and more detailed information for all files under \System32\ (recursive)
iri-get-ads -path=C:\Windows\System32 -recurse=recurse
# List the ADS and more detailed information for files under \System32\ (recursive) with 2 or more ADS
iri-get-ads -path=C:\Windows\System32 -recurse=recurse -number=2
# List the ADS and more detailed information for files under \System32\ (recursive) with a "Zone.Identifier" ADS
iri-get-ads -path=C:\Windows\System32 -recurse=recurse -type=Zone.Identifier
# Get the ADS and its content from a given file
iri-analyse-ads -path=C:\Windows\System32\Suspicious.png
```
Take registry snapshots
```powershell
# Start the registry "snapshot" with default settings (predefined set of keys, scantype deep)
iri-get-registry 
# Start the registry "snapshot" starting from a given key (scantype normal)
iri-get-registry -path="registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows" -scan=normal
# Start the registry "snapshot" for the predefined set of keys (scantype normal)
iri-get-registry -scan=normal
```
More
```powershell
# List all accounts on the system
iri-get-accounts
# List all interesting informations regarding the remote system
iri-get-systeminfo
# List all interesting informations regarding the remote systems network properties
iri-get-networkinfo
# Get a in depth analysis of all recycle bins for all users and all drives and output it as csv
iri-analyse-recyclebin -outputtype=csv
```

## Todo
* Get Search Index Database (Windows.edb)
* Get Browser Extensions
* Run Process and capture output (to run potential 3rd Party analysis tools)
* Get Prefetch (low prio, already possible via iri-copy-from-client or iri-get-file)
* Get PowershellHistory (low prio, already possible via iri-copy-from-client or iri-get-file)
* Get PowershellProfiles (low prio, already possible via iri-copy-from-client or iri-get-file)
