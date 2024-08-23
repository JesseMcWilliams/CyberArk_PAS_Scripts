@{
    Threads = @{
        Max = 3
    }
    Logging = @{
        Folder = ''
        Filename = ''
        Level = ''
    }
    CyberArk_PVWA = @{
        Port = 443
        HTTP_Scheme = 'https'
        IgnoreSSLErrors = $false
        User_Authentication = 'CyberArk'
        IIS_Application = 'PasswordVault'
        Address = 'epv.company.com'
    }
    Inputs = @{
        AllowCPMDisabled = $true
        InputFiles = $null
        OutFile = ''
        Unlock = $true
        MaxCPMWait = 1
        RotateServicePassword = $true
        Reason = 'Change Number'
        ThumbPrint = ''
    }
}

