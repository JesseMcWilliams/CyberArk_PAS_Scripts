<#
    Default Configuration file for Set-WindowsServiceAccount
#>
@{
    # This section holds the information needed to access the CyberArk Password Vault Web Access server.
    CyberArk_PVWA = @{
        # This is HTTP or HTTPS
        HTTP_Scheme = "https"

        # This is the IP, Short Name, or Fully Qualified Domain Name
        Address = "epv.company.com"

        # This is the TCP Port that the web server is listening on.  Default 443
        Port = 443

        # This is the IIS Application name.  Default PasswordVault
        IIS_Application = "PasswordVault"

        # This is needed if using the IP address or a Self Signed certificate on the PVWA.
        IgnoreSSLErrors = $true

        # This is the type of authentication to use when authenticating to the PVWA.
        # Valid values:  "CyberArk", "LDAP", "SAML", "PKI", "PKIPN"
        User_Authentication = "CyberArk"
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
        InputFiles = @(".\Dev_Test.csv", "My_New.csv")

        # This is a single output file to write the results to.
        OutFile = ""

        # This is the Thumbprint of the x509 Client Authentication certificate to be used.
        ThumbPrint = ""
    }
}