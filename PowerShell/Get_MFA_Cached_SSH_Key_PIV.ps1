<#
    .SYNOPSIS
    Creates an SSH key in CyberArk and downloads it in the format specified.

    .DESCRIPTION
    This script allows the user to download a CyberArk SSH key that can be used to authenticate to
    the PSMP server.

    .PARAMETER PVWAURL
    [string]: This is the base URL of the PVWA web server.

    .PARAMETER SSHKeyFormat
    [string]:  This is the key format to be downloaded.  Values (PEM, PPK, OpenSSH).

    .PARAMETER OutFile
    [string]:  This is the filename to be written to.  The format / extension will be appended.

    .PARAMETER OutPath
    [string]:  This is the Relative or Full path where the file should be written.

    .PARAMETER RequestTimeout
    [int]:  Default 30 seconds.  This is the number of seconds before timing out.

    .PARAMETER ThumbPrint
    [string]:  This is the thumbprint of the client certificate to be used during the
               authentication process.

    .INPUTS
    [string] CyberArk Password Vault Web Access URL
    [string] The SSH Key format to be downloaded
    [string] The output filename without extension
    [string] The output folder path, Relative or Fully Qualified.
    [string] The thumbprint of the certificate to be used for client authentication.

    .OUTPUTS
    None

    .NOTES
    This script leverages the work of the following people.
        https://github.com/allynl93
        https://github.com/infamousjoeg
        https://github.com/pspete

    .EXAMPLE
    Command Line:
        Get_MFA_Cached_SSH_Key_PIV.ps1 -PVWAURL "https://epv.company.com" -SSHKeyFormat "PEM" -OutFile "MFA_SSH_Key" -OutPath "C:\Temp" -ThumbPrint "1783479e4888ce0fb0910eab691727d418e1ee82"
    Output:
        Getting CyberArk Auth Token from:  https://epv.company.com/PasswordVault/API/auth/pkipn/logon
        Getting SSH Key from:  https://epv.company.com/PasswordVault/API/Users/Secret/SSHKeys/Cache
        Getting SSH Key details
        Writing KEY to file:  C:\Temp\MFA_SSH_Key.KEY.PEM
        Writing PUB to file:  C:\Temp\MFA_SSH_Key.PUB.DER
        *** SUCCESS ***
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
        [string] $OutFile = "MFA_SSH",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $OutPath = "C:\Temp",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $ThunbPrint
    )

#region Set URL
# If you are using PKI with distinguished name then this link works.
#$logonURL = $PVWAURL + "/PasswordVault/API/auth/pki/logon"

# If you are using PKI with User Principal name then this link works.
$authURL = $PVWAURL + "/PasswordVault/API/auth/pkipn/logon"
# The url is case sensitive after API.
#endRegion Set URL

# Get the client certificate.
$myCert = Get-ChildItem -Recurse -Path ("Cert:\*{0}" -f $ThunbPrint)

#region Get CyberArk Auth Token
### Get CyberArk Auth Token ###
# Build the Headers and Body
$atHeaders = @{
    'Accept' = 'application/json'
}

$atBody = @{
    username = ""
    password = ""
    newPassword = ""
    concurrentSession = $true
    secureMode = $true
    type = "pkipn"
    additionalInfo = ""
    apiUse = $true;
}

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
    Certificate = $myCert
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
