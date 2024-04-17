<#
    This script will test connectivity to all hosts specified in the CSV file provided.
    If specified the script will also attempt to logon to the target server over SSH.
#>

[cmdletbinding()]
Param(
    [parameter(
        Mandatory = $false,
        ValueFromPipeline = $true
    )]
    [string] $InputFile = "SSH_Host_List-All.csv",

    [parameter(
        Mandatory = $false,
        ValueFromPipeline = $true
    )]
    [string] $OutputFile,

    [parameter(
        Mandatory = $false,
        ValueFromPipeline = $true
    )]
    [pscredential] $TestCredential
    )

Import-Module Posh-SSH

# Functions
function Test-Connectivity
{
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Address,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $Port
    )

    Write-Verbose ("{0}      Testing Connectivity:  {1}({2})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Address, $Port)
    $_resultConnectivity = Test-NetConnection -ComputerName $Address -Port $Port

    return $_resultConnectivity
}

function Test-Logon
{
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Address,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $Port,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Protocol = "SSH",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [pscredential] $LogonCredential
    )

    $_resultSession = @{
        "SSH_Session" = $false;
        "Host_Name" = "";
        "OS" = "";
        "Sudo" = "";
        "Info" = ""
    }

    Write-Verbose ("{0}             Testing Logon:  {1}@{2}:{3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $LogonCredential.UserName,$Address, $Port)

    try
    {
        # Try to establish the session.
        $_session = New-SSHSession -ComputerName $Address -Port $Port -Credential $LogonCredential -Force -ErrorAction Stop

        # Update the return object with $true.
        Write-Verbose ("{0}         Logon Successfull:  " -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        $_resultSession.SSH_Session = $true

        # Get the Host's name.
        Write-Verbose ("{0}         Getting Host Name:  " -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        $_hostname = Invoke-SSHCommand -SessionId 0 -Command 'hostname'
        if ($_hostname.ExitStatus -eq 0)
        {
            $_resultSession.Host_Name = $_hostname.Output
        }

        # Get the Host's OS.
        Write-Verbose ("{0}           Getting OS Name:  " -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        $_os = Invoke-SSHCommand -SessionId 0 -Command 'cat /etc/os-release | grep PRETTY_NAME'
        if ($_os.ExitStatus -eq 0)
        {
            $_resultSession.OS = ($_os.Output.Split("="))[1]
        }

        # Get the allowed SUDO commands.
        $_resultSession.Sudo = Get-SUDO -Session $_session -LogonCredential $LogonCredential

    }

    catch
    {
        $_resultSession.Info = $_
    }

    finally
    {
        # Remove the SSH session.
        Remove-SSHSession -SSHSession $_session
    }
    

    return $_resultSession
}

function Get-SUDO
{
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        $Session,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [pscredential] $LogonCredential
    )
    # Get the allowed SUDO commands.
    Write-Verbose ("{0}     Getting SUDO Commands:  " -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
    $_sudo = Invoke-SSHCommand -SessionId 0 -Command 'sudo -l'
    
    if ($_sudo.ExitStatus -eq 0)
    {
        Write-Host $_sudo.Output
        return $_sudo.Output
    }
    else
    {
        $stream = $Session.Session.CreateShellStream("PS-SSH", 0, 0, 0, 0, 100)
        $user = Invoke-SSHCommand $Session -Command "whoami"
        $SSHusersName = $user.Output | Out-String
        $SSHusersName = $SSHusersName.Trim()
        $results = Invoke-SSHStreamExpectSecureAction -ShellStream $stream -Command "sudo -l" -ExpectString "[sudo] password for $($SSHusersName):" -SecureAction $LogonCredential.Password -OutVariable outStream -Verbose
        # Get output from stream.
        do
        {
            #
            $output += $stream.Read()
            Write-Host $output
        }
        while ($stream.DataAvailable)

        Start-Sleep -Seconds 5

        $VerboseOut = $stream.Read() 4>&1
        Write-Warning $VerboseOut
        
        $output += "`t'Password Required for SUDO!'"
        $output += "`t$($VerboseOut)"
        $output = $output.Replace("`r","")
        $output = $output.Replace("`n","`t")
        return $output
    }
}

# Flow
Write-Host ("{0} : **********  Starting  **********" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

# Check if an input file exists.
if (Test-Path -Path $InputFile)
{
    Write-Verbose ("{0} Input file ({1}) exists." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $InputFile)

    # Check if an output file was specified.
    if (!($OutputFile))
    {
        # Get the filename from the InputFile.
        $_inputFilename = Split-Path -Path $InputFile -Leaf

        $OutputFile = ("{0}_OUTPUT_{1}" -f (Get-Date -Format "yyyy-MM-dd_HHmm"), $InputFile)
    }

    # Check if the output file exists.
    if (!(Test-Path -Path $OutputFile))
    {
        Write-Verbose ("{0} Output file ({1}) does NOT exist!" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $InputFile)

        # Create the output file and add the header row.
        $_outputHeaders = "Hostname,Ping,SSH_Open,Username,SSH_Logon,Hostname,OS,SUDO,Info"

        Out-File -FilePath $OutputFile -InputObject $_outputHeaders
    }
    # Start the testing.
    #  Read the input file as a CSV.
    Write-Verbose ("{0} Reading Input file ({1})." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $InputFile)
    
    $_inputCSV = Import-Csv -Path $InputFile
    
    Write-Verbose ("{0} Input file read.  Found Rows:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_inputCSV.count)

    # Check if the CSV has rows
    if ($_inputCSV.count -gt 0)
    {
        # Check if the Credential was provided.
        if (!($TestCredential))
        {
            Write-Warning "No Credential Provided!"
            $TestCredential = Get-Credential -Message "Enter Logon Credential."
            #$_secPass = ConvertTo-SecureString -String "" -AsPlainText -Force
            #$TestCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "svc_cark_nxreconcile", $_secPass
        }
        
        # Loop over the CSV
        Write-Verbose ("{0} Looping over CSV." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

        # Create a loop counter.
        $_loopCount = 0

        if (!$TestCredential.UserName -eq "")
        {
            foreach ($row in $_inputCSV)
            {
                # Increment the row counter.
                $_loopCount++

                # Process the row.
                Write-Verbose ("{0} Processing Row ({1}).  Host:  {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_loopCount.tostring().PadLeft(($_inputCSV.count.ToString().length), '0'), $row.Host_FQDN)

                # Test connectivity.
                $resultConnectivity = Test-Connectivity -Address $row.Host_FQDN -Port $row.Port

                # Test logon.  Only if a credential was specified and if the connectivity test was successfull.
                if ($resultConnectivity.TcpTestSucceeded)
                {
                    $resultLogon = Test-Logon -Address $row.Host_FQDN -Port $row.Port -Protocol "SSH" -LogonCredential $TestCredential
                }

                # Write results.  "Hostname,Ping,SSH_Open,Username,SSH_Logon"
                #  Create the new line to be written.
                $_outputRow = ""
                if ($resultConnectivity)
                {
                    # Append the Connection results.
                    $_outputRow = ('"{0}","{1}","{2}"' -f $row.Host_FQDN, $resultConnectivity.PingSucceeded, $resultConnectivity.TcpTestSucceeded)

                    # Append the session results
                    if ($resultConnectivity.TcpTestSucceeded)
                    {
                        $_outputRow += (',"{0}","{1}","{2}","{3}","{4}","{5}"' -f $TestCredential.UserName, $resultLogon.SSH_Session, $resultLogon.Host_Name, $resultLogon.OS, $resultLogon.Sudo, $resultLogon.Info)
                    }

                    Write-Verbose ("{0} Writing output line:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_outputRow)
                    Out-File -FilePath $OutputFile -Append -InputObject $_outputRow
                }
            }
        }
    }
}
else
{
    Write-Error ("{0} : ERROR! The input file specified ({1}) does NOT exist!" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $InputFile)
}

Write-Host ("{0} : **********  Finished  **********" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))