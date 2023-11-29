using assembly "C:\Program Files\CyberArk\ApplicationPasswordSdk\NetPasswordSDK.dll"


Write-Host ("{0} : ********** Starting **********" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))


# Create the .NET request object.
Write-Host ("{0} : Creating the request object." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))
$_request = [CyberArk.AIM.NetPasswordSDK.PSDkPasswordRequest]::New()

# Set the request properties.
Write-Host ("{0} : Adding properties to the request object." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))
$_request.SetAttribute("AppDescs.AppID","Test_App")
$_request.SetAttribute("Query","Safe=Test_Safe;Object=Test_Acct")

# Make the request.
Write-Host ("{0} : Making the request" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))
$_results = [CyberArk.AIM.NetPasswordSDK.PasswordSDK]::GetPassword($_request)

# Get result properties.
Write-Host ("{0} : Getting credential properties from the request results." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))
$_credential = @{
    UserName = $_results.GetAttribute("PassProps.UserName")
    Address = $_results.GetAttribute("PassProps.Address")
    Location = $_results.GetAttribute("PassProps.Location")
    PasswordChangeInProgress = $_results.PasswordChangeInProgress
    Credential = [System.Management.Automation.PSCredential]::New($_results.GetAttribute("PassProps.UserName"),$_results.SecureContent)
}

# Output the properties.
Write-Host ("{0} : Outputting the credential properties." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))
Write-Host ("`tUserName:  {0}" -f $_credential.UserName)
Write-Host ("`tAddress:  {0}" -f $_credential.Address)
Write-Host ("`tLocation:  {0}" -f $_credential.Location)
Write-Host ("`tChange In Progress:  {0}" -f $_credential.PasswordChangeInProgress)
Write-Host ("`tCredential Username:  {0}" -f $_credential.Credential.UserName)
Write-Host ("`tCredential Password:  {0}" -f $_credential.Credential.GetNetworkCredential().Password)

Write-Host ("{0} : ********** Finished **********" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))