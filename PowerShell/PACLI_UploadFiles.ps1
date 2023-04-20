<#
    .SYNOPSIS
    This script will upload files to the CyberArk Vault

    .DESCRIPTION
    This script will upload the file(s) specified in the configuration file to the safe(s) configured.
#>

# Setup any Using statements.
Using Module Logger
Using Module ".\Modules\PACLI\PACLI.psm1"

# Specify the input parameters.
[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ConfigFile = "\Conf\PACLI_GetFiles_Dev.xml",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [ValidateSet("None","Critical","Error","Warning","Information","Debug","Verbose","Trace")]
        [string] $LogLevel = "Verbose",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $EnableDebug,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $EnableVerbose
    )

# Import any needed modules.
Import-Module ".\Modules\Configuration.psm1" -Force
Import-Module ".\Modules\Credential.psm1" -Force
Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force
Import-Module ".\Modules\CyberArk_PACLI.psm1" -Force

#region PowerShell Debug/Verbose output
# Valid settings:  SilentlyContinue, Continue,

# Enable Debug.  By default $DebugPreference is SilentlyContinue.
#$DebugPreference = Continue
if ($EnableDebug)
{
    $DebugPreference = Continue
}

# Enable Verbose.  By default $VerbosePreference is SilentlyContinue.
#$VerbosePreference = Continue
if ($EnableVerbose)
{
    $DebugPreference = Continue
    $VerbosePreference = Continue
    $EnableDebug = $true
}

#endregion PowerShell Debug/Verbose output

#region Script Variables

# Get the current folder.  This is the current working folder.
$_currentPath = (Get-Location).Path

# Get the script folder.  This is the folder where the script lives.
$_scriptPath = $PSScriptRoot

# Get the start time.
$_startDateTime = Get-Date

#endregion Script Variables

#region Script Logging

# Setup the logging object and set the current logging level.
#  This is a custom logging module to allow easier log ouput to console or file.
$Logger = [Logger]::new($LogLevel)

#endregion Script Logging

#region Script Functions

#endregion Script Functions

#region Script Flow
$Logger.Write(("******************** {0} ********************" -f "Starting"), "Information")

# Get the configuration information from the specified XML file.
$Logger.Write(("Getting Configuration Information from :  {0}" -f $ConfigFile), "Information")
$_xmlDoc = Read-Configuration -Path $ConfigFile

# Get the Configuration element from the XML document.
$_Configuration = $_xmlDoc.Configuration

#region Configure Logging
# Check to see if any logging inforamtion was specified in the Configuration XML.
if ($_Configuration.Logging)
{
    $Logger.Write(("Setting new Logging properties :  {0}" -f $_Configuration.Logging), "Debug")

    # Setup the logging attributes.
    $null = Set-Logging -LoggingConfig $_Configuration.Logging -LogObject $Logger

    $Logger.Write(("******************** {0} ********************" -f "Starting"), "Information", "File")
    $Logger.Write(("********* Started at {0} *********" -f $_startDateTime.ToString("yyyy-MM-dd HH:mm:ss")), "Information", "File")
}
else
{
    $Logger.Write(("No Logging properties to set." ), "Information")
}
#endregion Configure Logging

$EnableDebug = $true
# Check to see if Debugging was requested and do some debug testing and output.
if ($EnableDebug)
{
    # Check configuration attributes.
    $Logger.Write(("Checking All Configuration Attributes  :  {0}" -f $ConfigFile), "Debug")

    # Get a string representing all of the XML Configuration attributes.
    $_stringConfigAttributes = Test-Configuration -ConfigFile $ConfigFile -XMLConfiguration $_xmlDoc

    # Output the string representing the XML Configuration attributes.
    $Logger.Write(("      Sorted Configuration Attributes  :  `r`n{0}" -f $_stringConfigAttributes), "Debug")
}

# Get the Actions to be performed.
$_Actions = Get-ChildNodes -Nodes $_Configuration.Actions -ParentName "Actions"

# Build list of files to get.
#  Loop over all actions
foreach ($action in $_Actions.Keys)
{
    # Get the files in the specified path and that match the file name.
    $_getFileParameters = @{
        Path = $_Actions[$action]["FilePath"]
        Filename = $_Actions[$action]["Filename"]
        MaxAge = $_Actions[$action]["MaxAge"]
        Depth = $_Actions[$action]["Depth"]
    }
    $_foundFiles = Get-Files @_getFileParameters

    # Add the files to the action.
    $_Actions[$action]["Files"] = $_foundFiles

    # Output the results
    $Logger.Write(("Current Action:  {0}" -f $action), "Debug")
    $Logger.Write((" Action Type  :  {0}" -f $_Actions[$action]["ActionType"]), "Debug")
    $Logger.Write(("   Safe Name  :  {0}" -f $_Actions[$action]["SafeName"]), "Debug")
    $Logger.Write((" Safe Folder  :  {0}" -f $_Actions[$action]["SafeFolder"]), "Debug")
    $Logger.Write(("   File Path  :  {0}" -f $_Actions[$action]["FilePath"]), "Debug")
    $Logger.Write(("   File Name  :  {0}" -f $_Actions[$action]["Filename"]), "Debug")
    $Logger.Write(("     Max Age  :  {0}" -f $_Actions[$action]["MaxAge"]), "Debug")
    $Logger.Write(("       Depth  :  {0}" -f $_Actions[$action]["Depth"]), "Debug")
    $Logger.Write(("   Overwrite  :  {0}" -f $_Actions[$action]["Overwrite"]), "Debug")
    $Logger.Write((" Found Files  :  `r`n`t{0}" -f ($_Actions[$action]["Files"] -join "`r`n`t")), "Debug")
}
Write-Host "Moving On"

# Create the first session credential request.
$_newSessionCredRequest = @{
    Authentication = $_Configuration.Authentication
    AuthSourceAttributes = $_Configuration.AuthSourceAttributes
    Stage = 1
}
$_newSessionRequest = New-CredentialRequest @_newSessionCredRequest

# Get the first session credential.
$_sessionCredential = Get-SessionCredential @_newSessionRequest

# Create the Destination object.
$_PACLI = [PACLI]::New()


# Logon to the Vault.
Write-Host ("  Name  :  {0}" -f $_sessionCredential["Credential"].Username)
Write-Host ("Password:  {0}" -f $_sessionCredential["Credential"].GetNetworkCredential().Password)
$_pacliConnection = @{
    Path = $_Configuration.PACLIInformation.FilePath
    SessionID = $_Configuration.PACLIInformation.SessionID
    Name = $_Configuration.PACLIInformation.Name
    Address = $_Configuration.PACLIInformation.Address
    Port = $_Configuration.PACLIInformation.Port
    User = $_sessionCredential["Credential"].Username
}
$connectResult = Connect-PACLI @_pacliConnection

# Upload the files to the Vault.

# Logoff the Vault.
$_pacliDisconnect = @{
    Name = $_Configuration.PACLIInformation.Name
    User = $_sessionCredential["Credential"].Username
}
$disconnectResult = Disconnect-PACLI @_pacliDisconnect

Remove-Module PACLI

$Logger.Write(("******************** {0} ********************" -f "Finished"), "Information")
#endregion Script Flow