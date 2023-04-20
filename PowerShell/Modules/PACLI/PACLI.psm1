<#
    .SYNOPSIS
    This PowerShell Module is for interacting with CyberArk's command line tool PACLI.

    .DESCRIPTION
    This PowerShell Module will interact with the PrivateArk Command Line Interface (PACLI), allowing
    direct integration with the CyberArk Vault.

    .EXAMPLE
    $sessionPACLI = [CyberArk_PACLI]::New()
    $sessionPACLI = [CyberArk_PACLI]::New(VaultName, VaultAddress, Username)
    $sessionPACLI = [CyberArk_PACLI]::New(VaultName, VaultAddress, UserCredential)

#>

class PACLI
{
    # Class variables
    [string]
    $PACLIPath

    [string]
    $VaultName

    [string]
    $VaultAddress

    [int]
    $VaultPort

    [string]
    $UserName

    [pscredential]
    $UserCred

    [int]
    $SessionID

    [bool]
    $Initialized

    [bool]
    $Connected

    #region Class Constructors
    PACLI(){
        $this.VaultName    = ""
        $this.VaultAddress = ""
        $this.VaultPort    = 1858
        $this.UserName     = ""
        $this.UserCred     = $null
        $this.SessionID    = 0
        $this.Initialized  = $false
        $this.Connected    = $false
    }

    PACLI(
        [string]$PACLIPath,
        [string]$VaultName,
        [string]$VaultAddress
    ){
        $this.PACLIPath    = $PACLIPath
        $this.VaultName    = $VaultName
        $this.VaultAddress = $VaultAddress
        $this.VaultPort    = 1858
        $this.UserName     = ""
        $this.UserCred     = $null
        $this.SessionID    = 0
        $this.Initialized  = $false
        $this.Connected    = $false
    }

    PACLI(
        [string]$PACLIPath,
        [string]$VaultName,
        [string]$VaultAddress,
        [string]$Username
    ){
        $this.PACLIPath    = $PACLIPath
        $this.VaultName    = $VaultName
        $this.VaultAddress = $VaultAddress
        $this.VaultPort    = 1858
        $this.UserName     = $Username
        $this.UserCred     = $null
        $this.SessionID    = 0
        $this.Initialized  = $false
        $this.Connected    = $false
    }

    PACLI(
        [string]$PACLIPath,
        [string]$VaultName,
        [string]$VaultAddress,
        [pscredential]$UserCredential
    ){
        $this.PACLIPath    = $PACLIPath
        $this.VaultName    = $VaultName
        $this.VaultAddress = $VaultAddress
        $this.VaultPort    = 1858
        $this.UserName     = $UserCredential.UserName
        $this.UserCred     = $UserCredential
        $this.SessionID    = 0
        $this.Initialized  = $false
        $this.Connected    = $false
    }

    PACLI(
        [string]$PACLIPath,
        [string]$VaultName,
        [string]$VaultAddress,
        [int]$SessionID
    ){
        $this.PACLIPath    = $PACLIPath
        $this.VaultName    = $VaultName
        $this.VaultAddress = $VaultAddress
        $this.VaultPort    = 1858
        $this.UserName     = ""
        $this.UserCred     = $null
        $this.SessionID    = $SessionID
        $this.Initialized  = $false
        $this.Connected    = $false
    }

    PACLI(
        [string]$PACLIPath,
        [string]$VaultName,
        [string]$VaultAddress,
        [string]$Username,
        [int]$SessionID
    ){
        $this.PACLIPath    = $PACLIPath
        $this.VaultName    = $VaultName
        $this.VaultAddress = $VaultAddress
        $this.VaultPort    = 1858
        $this.UserName     = $Username
        $this.UserCred     = $null
        $this.SessionID    = $SessionID
        $this.Initialized  = $false
        $this.Connected    = $false
    }

    PACLI(
        [string]$PACLIPath,
        [string]$VaultName,
        [string]$VaultAddress,
        [pscredential]$UserCredential,
        [int]$SessionID
    ){
        $this.PACLIPath    = $PACLIPath
        $this.VaultName    = $VaultName
        $this.VaultAddress = $VaultAddress
        $this.VaultPort    = 1858
        $this.UserName     = $UserCredential.UserName
        $this.UserCred     = $UserCredential
        $this.SessionID    = $SessionID
        $this.Initialized  = $false
        $this.Connected    = $false
    }
    #endregion Class Constructors

    #region Class Object Functions
    [string] ToString()
    {
        
        $_retString =      ("   PACLI Path  :  {0}" -f $this.PACLIPath)
        $_retString += ("`r`n   Vault Name  :  {0}" -f $this.VaultName)
        $_retString += ("`r`n  Vault Address:  {0}" -f $this.VaultAddress)
        $_retString += ("`r`n   Value Port  :  {0}" -f $this.VaultPort)
        $_retString += ("`r`n     Username  :  {0}" -f $this.UserName)
        $_retString += ("`r`nUser Credential:  {0}" -f $this.UserCred)
        $_retString += ("`r`n   Session ID  :  {0}" -f $this.SessionID)
        $_retString += ("`r`n Is Initialized:  {0}" -f $this.Initialized)
        $_retString += ("`r`n Is Connected  :  {0}" -f $this.Connected)

        return $_retString
    }
    #endregion Class Object Functions

    #region Connect / Disconnect
    [bool] Connect (){return $false}
    [bool] Disconnect (){return $false}
    #endregion Connect / Disconnect


}