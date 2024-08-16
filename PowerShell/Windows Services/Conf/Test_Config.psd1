<#
    Default Configuration file for Set-WindowsServiceAccount
#>
@{
    # This section holds the information needed to access the CyberArk Password Vault Web Access server.
    CyberArk_PVWA = @{
        # This is HTTP or HTTPS
        HTTP_Scheme = "https"

        # This is the IP, Short Name, or Fully Qualified Domain Name
        Address = "vault.bannermen.com"

        # This is the TCP Port that the web server is listening on.  Default 443
        Port = 443

        # This is the IIS Application name.  Default PasswordVault
        IIS_Application = "PasswordVault"

        # This is needed if using the IP address or a Self Signed certificate on the PVWA.
        IgnoreSSLErrors = $true

        # This is the type of authentication to use when authenticating to the PVWA.
        # Valid values:  "CyberArk", "LDAP", "SAML", "PKI", "PKIPN"
        User_Authentication = "PKI"
    }

    # This section holds the information needed for logging.
    Logging = @{
        # This is the logging level.
        # Valid values:  Force", "None", "Critical", "Error", "Warning", "Information", "Debug", "Verbose", "Trace"
        Level = "Trace"

        # Log Folder.  If blank, the current folder is used.  Can be Relative or Fully Qualified.
        Folder = "Logs"

        # Log Filename.  If blank, a default will be used.
        Filename = ""
    }

    # This section holds the inputs information.
    Inputs = @{
        # This is one or more files to be processed.
        InputFiles = @("Input_File_01.csv")

        # This is a single output file to write the results to.
        OutFile = ""

        # This is the Thumbprint of the x509 Client Authentication certificate to be used.
        ThumbPrint = "2c711b8dc8a909b60ee45f84bfe3e805be562e2b"

        # All CPM Disabled accounts to be considered successfull if True.
        AllowCPMDisabled = $true

        # Maximum CPM Wait time in minutes.  How long should the script wait for the CPM change process.
        MaxCPMWait = 1

        # Account checkout reason.
        Reason = "Change Number"

        # Unlock accounts that are locked.
        Unlock = $true

        # Rotate Service Account Password
        RotateServicePassword = $true
    }

    # This section holds the information about the number of threads to run.
    Threads = @{
        # Total number of background threads allowed to run.
        Max = 3


    }
}