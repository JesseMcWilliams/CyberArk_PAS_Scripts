<#
    .SYNOPSIS
    Creates an SSH key in CyberArk and downloads it in the format specified.

    .DESCRIPTION
    This script allows the user to download a CyberArk SSH key that can be used to authenticate to
    the PSMP server.

    The script does require the use of an external EXE for retrieval of the SAML response.
    The EXE can be downloaded from here:  https://github.com/allynl93/getSAMLResponse-Interactive/releases/tag/Pre-built-Binary

    .PARAMETER PVWAURL
    [string]: This is the base URL of the PVWA web server.

    .PARAMETER SSHKeyFormat
    [string]:  This is the key format to be downloaded.  Values (PEM, PPK, OpenSSH).

    .PARAMETER OutFile
    [string]:  This is the filename to be written to.  The format / extension will be appended.

    .PARAMETER OutPath
    [string]:  This is the Relative or Full path where the file should be written.

    .INPUTS 
    [string] CyberArk Password Vault Web Access URL
    [string] The SSH Key format to be downloaded
    [string] The output filename without extension
    [string] The output folder path, Relative or Fully Qualified.

    .OUTPUTS
    None

    .NOTES
    This script leverages the work of the following people.
        https://github.com/allynl93
        https://github.com/infamousjoeg
        https://github.com/pspete

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive/releases
#>
[CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $PVWAURL = "https://epv.company.com",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('PEM','PPK','OpenSSH')]
        [string] $SSHKeyFormat = "PEM",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $OutFile = "MFA_SSH_Key",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $OutPath = "C:\Temp",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('PEM','PPK','OpenSSH')]
        [int] $RequestTimeout = 30
    )

#region Get IDP
### Get the IDP URL from the PVWA ###
# Build the Headers and Body
$idpHeaders = @{
    'Accept' = 'application/json'
}

$idpBody = @{
    'SAMLResponse' = '';
    'apiUse' = $true;
    'concurrentSession' = $false
}

$logonURL = $PVWAURL + "/PasswordVault/API/auth/saml/logon"
# The url is case sensitive after API.

# Build the web request options.
$idpWebRequestOptions = @{
    UseBasicParsing = $null
    Uri = $logonURL
    TimeoutSec = $RequestTimeout
    ContentType = "application/x-www-form-urlencoded"
    Method = "POST"
    Headers = $idpHeaders
    Body = $idpBody
    SessionVariable = 'idpSession' # This will be needed for the Token request.
}
# Use a try catch block to make the request.
try
{
    Write-Host ("Getting IDP URL from:  {0}" -f $logonURL)
    $idpResult = Invoke-WebRequest @idpWebRequestOptions
    Write-Verbose ("IDP URL:  {0}" -f $idpResult)
}
catch
{
    Write-Warning ("Failed to get IDP URL from:  {0}" -f $logonURL)
    Write-Warning ("IDP Result:  {0}" -f $idpResult)
    Write-Warning $_
    Exit $LASTEXITCODE
}
### End Section ###
#endRegion

#region Get SAML
### Get SAML Response ###

Write-Host ("Getting SAML Response.")
try
{
    # Using the pre-compiled code written by allynl93.  https://github.com/allynl93
    $samlResponse = .\getSAMLResponse\getSAMLResponse.exe $idpResult
    Write-Verbose ("SAML Response:  {0}" -f $samlResponse)
}
catch
{
    Write-Warning "Failed to get SAML response."
    Write-Warning $_
}
### End Section ###
#endRegion

#region Get CyberArk Auth Token
### Get CyberArk Auth Token ###
# Build the Headers and Body
$atHeaders = @{
    'Accept' = 'application/json'
}

$atBody = @{
    'SAMLResponse' = $samlResponse;
    'apiUse' = $true;
    'concurrentSession' = $true
}

$authURL = $PVWAURL + "/PasswordVault/API/Auth/SAML/Logon"

# Build the web request options.
$atWebRequestOptions = @{
    UseBasicParsing = $null
    Uri = $authURL
    TimeoutSec = $RequestTimeout
    ContentType = "application/x-www-form-urlencoded"
    Method = "POST"
    Headers = $atHeaders
    Body = $atBody
    WebSession = $idpSession
}
# Use a try catch block to make the request.
try
{
    Write-Host ("Getting CyberArk Auth Token from:  {0}" -f $authURL)
    $atResult = Invoke-WebRequest @atWebRequestOptions

    # Convert the result into JSON.
    $atJSON = ConvertFrom-Json $atResult

    Write-Verbose ("Auth Token:  {0}" -f $atJSON)
}
catch
{
    Write-Warning ("Failed to retrieve Auth Token from:  {0}" -f $authURL)
    Write-Warning ("Auth Token Result:  {0}" -f $atResult)
    Write-Warning $_
    Exit $LASTEXITCODE
}

### End Section ###
#endRegion

#region Get SSH Key
### Get SSH Key ###
# Build the Headers and Body
$mfacHeaders = @{
    'Accept' = 'application/json'
    'Authorization' = $atJSON
}

$mfacBody = @{
    'formats' = @($SSHKeyFormat)|ConvertTo-Json
}

$mfacURL = $PVWAURL + "/PasswordVault/API/Users/Secret/SSHKeys/Cache"

# Build the web request options.
$mfacWebRequestOptions = @{
    UseBasicParsing = $null
    Uri = $mfacURL
    TimeoutSec = $RequestTimeout
    ContentType = "application/x-www-form-urlencoded"
    Method = "POST"
    Headers = $mfacHeaders
    Body = $mfacBody
    WebSession = $idpSession
}
# Use a try catch block to make the request.
try
{
    Write-Host ("Getting SSH Key from:  {0}" -f $mfacURL)
    Write-Verbose ("Authorization Token:  {0}" -f $atJSON)
    $mfacResult = Invoke-WebRequest @mfacWebRequestOptions

    # Convert the result into JSON.
    $mfacJSON = ConvertFrom-Json $mfacResult

    Write-Verbose ("SSH Key:  {0}" -f $mfacResult)
}
catch
{
    Write-Warning ("Failed to retrieve SSH Key from:  {0}" -f $mfacURL)
    Write-Warning ("SSH Key Result:  {0}" -f $mfacResult)
    Write-Warning $_
    Exit $LASTEXITCODE
}
### End Section ###
#endRegion

#region Write to File
### Write File ###

# Convert the path to a fully qualified path.
$fqPath = Resolve-Path -Path $OutPath

if (Test-Path -Path $fqPath)
{
    try
    {
        Write-Host ("Getting SSH Key details")

        # Build the output file names.
        $keyOutputFileName = $OutFile + ".KEY." + $mfacJSON.Value[0].format
        $pubOutputFileName = $OutFile + ".PUB.DER"

        # Build the output file with path.
        $keyOut = Join-Path -Path $fqPath -ChildPath $keyOutputFileName
        $pubOut = Join-Path -Path $fqPath -ChildPath $pubOutputFileName

        Write-Host ("Writing KEY to file:  {0}" -f $keyOut)
        Out-File -FilePath $keyOut -InputObject $mfacJSON.Value[0].privateKey

        Write-Host ("Writing PUB to file:  {0}" -f $pubOut)
        Out-File -FilePath $pubOut -InputObject $mfacJSON.publicKey

        Write-Host ("*** SUCCESS ***")
    }
    catch
    {
        Write-Warning ("Failed to write to file!")
        Write-Warning $_
        Exit $LASTEXITCODE
    }
}
else
{
    Write-Warning ("The given ouput folder does NOT exist!  {0}" -f $OutPath)
    Exit
}

### End Section ###
#endRegion