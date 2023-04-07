<#
    .SYNOPSIS
    Handy PowerShell utilities for use in scripts.

    .DESCRIPTION
    This module should be called from a customized driver script.
    It is to reduce the size of the driver script making it easier to maintain.
    There shouldn't be any changes required to this module.
    
    Many thanks goes to the many examples provided by CyberArk, Joe Garcia, and others.

    Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force

    Written by:  Jesse McWilliams
    Written on:  2022-06

    .INPUTS
    None.  You cannot pipe objects to CyberArkFunctions.

    .OUTPUTS
    None.  This module does not have any outputs at the Global level.

	.EXAMPLE
	Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force
#>
#region General Help Functions
function Get-BoolFromString
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Text
    )
    switch -regex ($Text.Trim())
    {
        "^(1|true|yes|on|enabled)$" { $true }

        default { $false }
    }
}
function Join-Parts
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Parent,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Child,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Separator = "/"
    )

    # Write-Host ("{0} : Parent:  {1}" -f $(Get-Date -Format "yyyy-MM-dd"), $Parent)
    # Write-Host ("{0} : Child :  {1}" -f $(Get-Date -Format "yyyy-MM-dd"), $Child)
    # Get the individual parts of the parent.
    [array]$_arrayPartsParent = $Parent.Split($Separator)

    # Get the individual parts of the child.
    [array]$_arrayPartsChild = $Child.Split($Separator)

    # Join the arrays.
    [array]$_joinedArray = $_arrayPartsParent + $_arrayPartsChild

    # Clean any blank/empty entries.
    [array]$_cleanedArray = $_joinedArray | Where-Object {$_}

    # Join the array into a string using the provided separator.
    $_returnString = $_cleanedArray -Join $Separator

    # Return the joind parts as a string.
    return $_returnString
}
function Get-MaskedBody
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body
    )

    # Convert to JSON and Convert from JSON to get a deep copy.
    $jsonBody = ConvertTo-Json -InputObject $Body
    $newBody = ConvertFrom-Json -InputObject $jsonBody

    # Check if the provided Hash Table has a Password field.
    if (($newBody.Password) -or ($newBody.password))
    {
        # Check if the password is blank.
        if ($newBody.password -ne "")
        {
            # Replace the password with Stars *
            $newBody.password = "**********"
        }

    }
    # Check if the provided Hash Table has a Password field.
    if (($newBody.NewPassword) -or ($newBody.newpassword))
    {
        # Check if the password is blank.
        if ($newBody.newpassword -ne "")
        {
            # Replace the password with Stars *
            $newBody.newpassword = "**********"
        }

    }

    return $newBody
}
function Get-SanitizedURL
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Input
    )
}
function Test-IsSuccess
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int] $StatusCode,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string[]] $SuccessCodes
    )
    # Test to see if the Status Code is in the list of SuccessCodes.
    if ($StatusCode -in $SuccessCodes)
    {
        return $true
    }
    else
    {
        return $false
    }
}
function Test-SessionToken
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [AllowEmptyString()]
        [string] $Token
    )
    # Test the token.
    if (($Token) -and ($Token -ne "") -and ($Token.Length -gt 200))
    {
        # Validation passed.  Return True.
        return $true
    }
    return $false
}
function Copy-HashTable
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $InputObject
    )
    # Convert to JSON and back to get a deep copy.
    $_toJSON = ConvertTo-Json -InputObject $InputObject

    # Convert from JSON back to a hash table.
    return ConvertFrom-Json -InputObject $_toJSON
}
function Get-CertificateAttributes
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [X509Certificate] $InputObject
    )
    # Create a return Hash Table.
    $_retHT = @{}

    # Get the wanted attributes to be displayed.
    $_retHT["FriendlyName"] = $InputObject.FriendlyName
    $_retHT["Thumbprint"]   = $InputObject.Thumbprint
    $_retHT["NotAfter"]     = ($InputObject.NotAfter | Out-String)
    $_retHT["NotBefore"]    = ($InputObject.NotBefore | Out-String)
    $_retHT["HasPrivateKey"] = $InputObject.HasPrivateKey
    $_retHT["SerialNumber"] = $InputObject.SerialNumber
    $_retHT["IssuerName"]   = $InputObject.IssuerName.Name

    # Create a table to hold all key usages.
    $_retKeyUsages = @{}

    # Get all Key Usages.
    $_keyUsages = $InputObject.Extensions

    # Loop over all Key Usages and add to the return Key Usages.
    foreach ($usage in $_keyUsages)
    {
        # Check the object type.  We want X509KeyUsageExtension and X509EnhancedKeyUsageExtension
        if ($usage.GetType() -eq [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension])
        {
            # Add the usage to the output object if the name is not null.
            if ($null -ne $usage.Oid.FriendlyName)
            {
                # Adding value to the Key Usages hash table.
                $_retKeyUsages[$usage.Oid.FriendlyName] = $usage.Oid.Value
            }

        }
        elseif ($usage.GetType() -eq [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension])
        {
            # Get the enhanced key usage list.
            $_enhancedKeyUsageList = $usage.EnhancedKeyUsages

            # Loop over the Enhanced Key Usage List
            foreach ($ekule in $_enhancedKeyUsageList)
            {
                # Add the usage to the output object if the name is not null.
                if ($null -ne $ekule.FriendlyName)
                {
                    # Adding value to the Key Usages hash table.
                    $_retKeyUsages[$ekule.FriendlyName] = $ekule.Value
                }
            }
        }
    }

    # If Key Usages have been found add them to the return object.
    if (($_retKeyUsages) -and ($_retKeyUsages.Count))
    {
        $_retHT["KeyUsage"] = $_retKeyUsages
    }

    return $_retHT
}
function Get-DateTimeFromMaxAge
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $false
        )]
        [string]$MaxAge,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$Separator = ","
    )
    
    # Check to see if the Separator is in the Max Age.
    if ($MaxAge.Contains($Separator))
    {
        # Split the Max Age based on the Separator
        $_maxAges = $MaxAge.Split($Separator)
    }
    else
    {
        # Set a single Max Age.
        $_maxAges = @($MaxAge)
    }

    # Build a dictionary to hold the Max Age entries.
    $_maxAgeEntries = @{
        "Year"    = 0
        "Month"   = 0
        "Day"     = 0
        "Minute"  = 0
        "Second"  = 0
    }

    # Loop over the entries in the max ages to build the Max Age Entries hash table.
    foreach ($_age in $_maxAges)
    {
        # Use a Switch statement to build the entries.
        switch ($_age)
        {
            {$_.Contains("Y")}
                {
                    # Year
                    $_maxAgeEntries["Year"] = $_age.Replace("Y", "")
                    break;
                }
            {$_.Contains("M")}
                {
                    # Month
                    $_maxAgeEntries["Month"] = $_age.Replace("M", "")
                    break;
                }
            {$_.Contains("d")}
                {
                    # Day
                    $_maxAgeEntries["Day"] = $_age.Replace("d", "")
                    break;
                }
            {$_.Contains("m")}
                {
                    # Minute
                    $_maxAgeEntries["Minute"] = $_age.Replace("m", "")
                    break;
                }
            {$_.Contains("s")}
                {
                    # Seconds
                    $_maxAgeEntries["Second"] = $_age.Replace("s", "")
                    break;
                }
        }
    }

    # Get the current date and time.
    $_currentDate = Get-Date

    # Subtract the Max Age entries from the current date.
    $_currentDate = $_currentDate.AddYears(- ($_maxAgeEntries["Year"]))
    $_currentDate = $_currentDate.AddMonths(- ($_maxAgeEntries["Month"]))
    $_currentDate = $_currentDate.AddDays(- ($_maxAgeEntries["Day"]))
    $_currentDate = $_currentDate.AddMinutes(- ($_maxAgeEntries["Minute"]))
    $_currentDate = $_currentDate.AddSeconds(- ($_maxAgeEntries["Second"]))

    # Return the new Date and Time.
    return $_currentDate
}
#endregion General Help Functions
#region File Help Functions
function Get-Files
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $false
        )]
        [string]$Path,

		[parameter(
            Mandatory = $true,
            ValueFromPipeline = $false
        )]
        [string]$Filename,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [AllowEmptyString()]
        [string]$MaxAge,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [AllowNull()]
        [System.Nullable[int]]$Depth = 0
    )

    # Create the return list.
    $retObject = [System.Collections.ArrayList]::New()
    
    # Verify that the path exists.
    if (Test-Path -Path $Path)
    {
        # Path exists.  Get the file or files that match the file name.
        $foundObjects = Get-ChildItem -Path $Path -Include @($Filename) -Depth $Depth
        $_test = $foundObjects[0]

        # Filter by age if set.
        if (($MaxAge) -and ($MaxAge -ne ""))
        {
            # Create the date object from the Max Age attribute
            $_maxDate = Get-DateTimeFromMaxAge -MaxAge $MaxAge

            # Filter the files found based on the last write time.
            $retObject = $foundObjects | Where-Object {$_.LastWriteTime -gt $_maxDate}
        }
        else
        {
            $retObject = $foundObjects
        }
    }
    else
    {
        Write-Warning ("{0} | File Path NOT Found!  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Path)
    }

    # Return the results
    return $retObject
}
#region File Help Functions
#region Dialog Box Functions

function Get-InputFiles
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$StartLocation,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$FileFilter = "CSV files (*.csv)|*.csv|TXT files (*.txt)|*.txt|All files (*.*)|*.*"
    )

    Begin{
        # Add the windows form to this script
        Add-Type -AssemblyName System.Windows.Forms

        # Create the file browser object
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
        $FileBrowser.Filter = $FileFilter
        $FileBrowser.FilterIndex = 0
        $FileBrowser.Multiselect = $true

        # Check if a start location has been specified
        if ($StartLocation)
        {
            # Set the starting location to the requested location
            $FileBrowser.InitialDirectory = $StartLocation
        }
        else
        {
            $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        }
    }

    Process{
        # Open the file browser.  The data returned by the object is not needed.
        #  The selected files are a property of the object
        $null = $FileBrowser.ShowDialog()
        return $FileBrowser.FileNames
    }

	<#
    .SYNOPSIS
    This function will open the file dialog box and allow you to choose 1 or more files.

    .PARAMETER StartLocation
    You can specify the folder to start in.

    .OUTPUTS
    Returns an Array of strings
    The strings are the full path to the selected file(s)
    #>
}

function Get-Folder
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$StartLocation
    )

    Begin{
		# Add the windows form to this script
		Add-Type -AssemblyName System.Windows.Forms

		# Create the file browser object
		$FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog

		# Check if a start location has been specified
		if ($StartLocation)
		{
			# Set the starting location to the requested location
			$FolderBrowser.InitialDirectory = $StartLocation
		}
		else
		{
			$FolderBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
		}
	}

	Process{
		# Open the file browser.  The data returned by the object is not needed.
        #  The selected files are a property of the object
        $null = $FolderBrowser.ShowDialog()
        return $FolderBrowser.SelectedPath
	}
}

function Get-OutputFile
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$StartLocation,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$DefaultExtension = ".CSV",

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$FileFilter = "CSV files (*.csv)|*.csv|TXT files (*.txt)|*.txt|All files (*.*)|*.*"
    )

    Begin{
        # Add the windows form to this script
        Add-Type -AssemblyName System.Windows.Forms

        # Create the file browser object
        $FileBrowser = New-Object System.Windows.Forms.SaveFileDialog
		$FileBrowser.Filter = $FileFilter
        $FileBrowser.FilterIndex = 0
        $FileBrowser.DefaultExt = $DefaultExtension

        # Check if a start location has been specified
        if ($StartLocation)
        {
            # Set the starting location to the requested location
            $FileBrowser.InitialDirectory = $StartLocation
        }
        else
        {
            $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        }
    }

    Process{
        # Open the file browser.  The data returned by the object is not needed.
        #  The selected files are a property of the object
        $null = $FileBrowser.ShowDialog()
        return $FileBrowser.FileNames
    }

	<#
    .SYNOPSIS
    This function will open the file save dialog box and allow you to choose or set the output file.

    .PARAMETER StartLocation
    You can specify the folder to start in.

    .OUTPUTS
    Returns an Array of strings
    The strings are the full path to the selected file(s)
    #>

}
#endregion

#region CSV Functions
function Get-CSVFile
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $false
        )]
        [string]$CSVFile,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$CSVHeaders
    )
	
	# Process the CSV file
	try
	{
		# Read the CSV file
		return Import-Csv $file

	}
	catch
	{
		Write-Log -Message ("!ERROR! :  {0}" -f $_.Exception.Message) -Level "Error"
		throw
	}

}
#endregion