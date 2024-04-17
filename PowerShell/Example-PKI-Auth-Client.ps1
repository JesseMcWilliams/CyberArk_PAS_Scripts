<#
    This module uses PSPAS.
#>

Import-Module pspas -Force -MinimumVersion 6.0.30

$PVWAURL = 'https://epv.company.com'

#$AllMyCertificates = Get-ChildItem Cert:\CurrentUser\My

#$MyAuthCertificates = Get-ChildItem Cert:\CurrentUser\My -EKU "*Client Authentication*"

Write-Host "********************   Get Client Certificate   ********************"

$CertThumbPrint = "61c2808e62b8b62784b4650e3f14112e29485842"
$CertPath = ("Cert:\*{0}" -f $CertThumbPrint)
$SelectedCertificate = Get-ChildItem -Recurse -Path $CertPath

Write-Host "********************  Create New PAS Session  ********************"

# Create a NEW PAS Session
Write-Host ("Creating a new PAS session to:  {0}" -f $PVWAURL)
# Create New-PASSession variables.
$nps = @{
    BaseURI = $PVWAURL
    Type = "PKIPN"
    Certificate = $SelectedCertificate
}
# Nothing is returned from New-PASSession
New-PASSession @nps

# Get the PAS Session.
Write-Host ("Getting the current PAS session.")
$currentPASSession = Get-PASSession

# Clear the cookies of the PAS Session.  This is needed to avoid getting a 401 (Unauthorized)
$currentPASSession.WebSession.cookies = [System.Net.CookieContainer]::New()

try
{
    Write-Host "********** Get Accounts **********"
    $Accounts = Get-PASAccount

    if ($Accounts)
    {
        Write-Host $Accounts
    }
    
}
catch
{
    #
    Write-Warning (" ### Error Caught ###")
    if ($_.TargetObject)
    {
        #
        Write-Warning ("Exception Message:  {0}" -f $_.TargetObject.Exception.Message)
        Write-Warning ("   Response URI  :  {0}" -f $_.TargetObject.Exception.Response.ResponseUri)
        Write-Warning (" Response Method :  {0}" -f $_.TargetObject.Exception.Response.Method)
        Write-Warning ("  Response Code  :  {0}" -f [int]$_.TargetObject.Exception.Response.StatusCode)
        Write-Warning (" Response Message:  {0}" -f $_.TargetObject.Exception.Response.StatusDescription)
        Write-Warning ("Response:  {0}" -f $_.TargetObject.Exception.Response)
    }
    Write-Host $_
    
    
    #Write-Warning ("Exception Message :  {0}" -f $_.TargetObject.Exception.Message)
    Write-Warning ($_)
}

Write-Host "**********  Finished  **********"