<#
    https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmldocument?view=netframework-4.8
#>

function Read-Configuration
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Path
    )

    # Create the base XML object.
    $_ConfigXML = New-Object -TypeName xml

    # Creat the fully qualified path.
    $fullyQualifiedPath = ""

    # Need to test the path to see if it is relative or fully qualified.
    if ($Path.Contains(":"))
    {
        # Fully Qualified Path.
        $fullyQualifiedPath = Resolve-Path $Path
    }
    else
    {
        # Not a Fully Qualified Path.  Check to see if it starts with a period.
        if ($Path.Substring(0,1).Equals("\"))
        {
            # Add a period to the path so that Resolve-Path can get the fully qualified path from this.
            $fullyQualifiedPath = Resolve-Path ((".{0}" -f $Path))
        }
        else
        {
            # Resolve-Path can get the fully qualified path from this.
            $fullyQualifiedPath = Resolve-Path $Path
        }
    }

    # Load the file.
    $_ConfigXML.Load($fullyQualifiedPath)

    return $_ConfigXML
}
function Show-Configuration
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [xml] $Document
    )

    # Write out all of the configuration settings.
    # Build the return dictionary.
    #$_returnArray = [System.Collections.ArrayList]::New()
    $_returnDictionary = [ordered]@{}

    #  Loop over the XML document to get all elements.
    foreach ($element in $Document)
    {
        # Get the Base URI so we can get the Filename from it.
        $_uri = $element.BaseUri

        # Use the URI Builder to get the Path from the URI.
        $_filePath = ([System.UriBuilder]::New($_uri)).Path

        # Use this function to get the Fielname without the extension.
        $_fileName = [System.IO.Path]::GetFileNameWithoutExtension($_filePath)

        # Set the Filename to the Top Level Name.
        $_topLevelName = $_fileName

        if (($element.NodeType -eq "Element") -or ($element.NodeType -eq "Document"))
        {
            # Check to see if the Element or Document has any Child Nodes.
            if ($element.HasChildNodes)
            {
                # Get Child Nodes from the Element.
                $configChildren = Get-ChildNodes -Nodes $element.ChildNodes -ParentName $_topLevelName -ForceParentName $true

                # Add the returned dictionary to the current dictionary to be returned.
                $_returnDictionary[$_topLevelName] = $configChildren
            }
        }
        elseif ($element.NodeType -eq "Text")
        {
            # Get the data from the element and add it to the return dictionary.
            $_returnDictionary[$ParentName] = $element.Data
        }
    }

    # Flatten and Order the Hash Table.
    $_flatOrderDictionary = ConvertTo-FlatHashTable -InputObject $_returnDictionary

    return $_flatOrderDictionary
}
function Get-ChildNodes
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [object] $Nodes,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ParentName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [bool] $ForceParentName = $false
    )

    # Build the return dictionary.
    $_returnDictionary = @{}

    # Loop over the XML Element to get all elements.
    foreach ($element in $Nodes)
    {
        # Check to see if the current item in the provided Nodes is an Element.
        if ($element.NodeType -eq "Element")
        {
            if ($ForceParentName)
            {
                if ($ParentName -ne "")
                {
                    #$_elementName = ("{0}.{1}" -f $ParentName, $element.Name)
                    $_elementName = $element.Name
                }
                else
                {
                    $_elementName = $element.Name
                }
            }
            else
            {
                $_elementName = $element.Name
            }
            

            # Check to see if the current item has Child Nodes.
            if ($element.HasChildNodes)
            {
                # Get Child Nodes
                $configChildren = Get-ChildNodes -Nodes $element.ChildNodes -ParentName $_elementName -ForceParentName $ForceParentName

                # Add the dictionaries.
                $_returnDictionary[$_elementName] = $configChildren
            }
        }
        # Check to see if the current item is Text.
        elseif ($element.NodeType -eq "Text")
        {
            # Add element to the return dictionary
            return $element.Data
        }
    }

    # Return the dictionary.
    if ($ForceParentName)
    {
        return $_returnDictionary
    }
    if ($_returnDictionary.ContainsKey($ParentName))
    {
        return $_returnDictionary[$ParentName]
    }
    else
    {
        return $_returnDictionary
    }
}
function Set-Logging
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.Xml.XmlElement] $LoggingConfig,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [Logger] $LogObject
    )

    # Check the Logging Level
    if ($LoggingConfig.Level)
    {
        Write-Debug ("Setting Logging Level :  {0}" -f $LoggingConfig.Level)
        $LogObject.SetLoggingLevel($LoggingConfig.Level)
    }
    # Check the Logging Folder
    if ($LoggingConfig.Folder)
    {
        Write-Debug ("Setting Logging Folder:  {0}" -f $LoggingConfig.Folder)
        # Make sure the path is resolved.
        $Folder = $LoggingConfig.Folder

        # Test to see if the path exists.
        if (-not (Test-Path -Path $Folder))
        {
            # The path doesn't exist.  Try adding the current script directory.
            $newFolder = Join-Path -Path $PSScriptRoot -ChildPath $Folder

            # Test the newly formed path.
            if (-not (Test-Path -Path $newFolder))
            {
                # Folder doesn't exist.  Create it.
                $null = New-Item -Path $newFolder -ItemType Directory
            }
        }
        else
        {
            $newFolder = (Get-Item -Path $Folder).FullName
        }

        # Test to see if it exists now.
        if ($newFolder)
        {
            Write-Debug ("Setting Logging Folder:  {0}" -f $newFolder)
            # Set the new path.
            $LogObject.SetLoggingPath($newFolder)
        }
    }
    # Check the Logging File
    if ($LoggingConfig.File)
    {
        Write-Debug ("Setting Logging File  :  {0}" -f $LoggingConfig.File)
        # Check if the logging file has a date formatter.
        if ($LoggingConfig.File.Contains("]"))
        {
            # Split the logging filename on the ]
            $_tmpLogFile = $LoggingConfig.File.Split("]")

            # Assign the first and last half.
            $_firstHalf = $_tmpLogFile[0]
            $_lastHalf = $_tmpLogFile[1]

            # Check to see which half has the formatter.
            if ($_firstHalf.Contains("["))
            {
                # Strip the bracket.
                $tmpFName = $_firstHalf.Replace("[", "")

                # Set the date and time.
                $tmpFName = Get-Date -Format $tmpFName

                # Join the halves.
                $_newLogFile = $tmpFName + $_lastHalf
            }
            elseif ($_lastHalf.Contains("["))
            {
                # Strip the bracket.
                $tmpFName = $_lastHalf.Replace("[", "")

                # Set the date and time.
                $tmpFName = Get-Date -Format $tmpFName

                # Join the halves.
                $_newLogFile = $tmpFName + $_firstHalf
            }
            else
            {
                # You shouldn't end up here.
                $_newLogFile = $LoggingConfig.File
            }
        }
        else
        {
            $_newLogFile = $LoggingConfig.File
        }
        Write-Debug ("Setting Logging File  :  {0}" -f $_newLogFile)
        $LogObject.SetLoggingFile($_newLogFile)
    }
    # Check the Logging Destination
    if ($LoggingConfig.Destination)
    {
        Write-Verbose ("Setting Logging Destination:  {0}" -f $LoggingConfig.Destination)
        $LogObject.SetLogDestination($LoggingConfig.Destination)
    }
    Write-Debug ("New Log File Set:  {0}" -f $_newLogFile)
    return $null
}
function Get-NewURI
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Schema,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Address,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int] $Port,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Path
    )

    # Create the URI object
    return [System.UriBuilder]::New($Schema, $Address, $Port, $Path)
}
function Test-Configuration
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $ConfigFile,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [xml] $XMLConfiguration
    )
    # Call the show function.  It will return a sorted dictionary of all attributes found in the config file.
    $allConfigurationItemsSorted = Show-Configuration -Document $XMLConfiguration

    # Convert the sorted and ordered dictionary to a string to output.
    return ($allConfigurationItemsSorted | Format-Table -AutoSize | Out-String -Width 1024)
}
function ConvertTo-FlatHashTable
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $InputObject,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ParentName
    )
    # Flatten a nested Hash Table
    # Build the return dictionary.
    $_returnDictionary = @{}

    # Loop over the hashtable.
    foreach ($element in $InputObject.Keys)
    {
        # Build the Element Name to be used as the Key in the returned dictionary.
        if ($ParentName -ne "")
        {
            $_elementName = ("{0}.{1}" -f $ParentName, $element)
        }
        else
        {
            $_elementName = $element
        }

        # Get the Element Value.
        $_elementValue = $InputObject[$element]

        # Check to see if Value is another table.
        if ($_elementValue.GetType() -eq [System.String])
        {
            # Add the dictionaries.
            $_returnDictionary[$_elementName] = $_elementValue
        }
        elseif ($_elementValue.GetType() -eq [System.Collections.Hashtable])
        {
            # Nested Hash Table
            $_returnDictionary += ConvertTo-FlatHashTable -InputObject $_elementValue -ParentName $_elementName
        }
        else
        {
            Write-Warning ("Unknown Value Type!  Element Name ({0}) : Value ({1}) : Type ({2})" -f $element, $_elementValue, $_elementValue.GetType())
        }
    }

    # Sort the results before returning the data.
    #  Create the dictionary to hold the sorted attributes.
    $_sortedDic = [ordered]@{}

    # Loop over the sorted results and add to the return dictionary.
    foreach ($sortedEntry in $($_returnDictionary.GetEnumerator() | Sort-Object -Property key))
    {
        # Add the values to the new dictionary.
        $_sortedDic[$sortedEntry.Key] = $sortedEntry.Value
    }

    # Return the sorted dictionary.
    return $_sortedDic
}
