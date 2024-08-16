<#
    .SYNOPSIS
    Manages services on a remote computer in the list provided.

    .DESCRIPTION
    This script consumes a CSV file containing the remote servers and the services to be managed.

    .PARAMETER Input
    [object]:  This is the object after importing a CSV file that contains the Servers, Services, 
               Actions, and Accounts.

    .PARAMETER AdminIDs
    [hashtable]:  This is a hash table containing the PSCredential objects needed for authenticating
                  to the servers.

    .PARAMETER ServiceIDs
    [hashtable]:  This is a hash table containing the PSCredential objects needed to run the services

    .INPUTS
    None
#>

# Import required modules.
#  Logger is a custom module that needs to be manually installed.
Using module Logger

#  Utilities is a custom module that needs to be manually installed.
Using module Utilities

# Setup the command line parameters.
[CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false
            )]
        [object] $Session,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [object] $AdminIDs,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [object] $ServiceIDs,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet("Start", "Stop", "ReStart", "Update", "Disable", "Automatic", "Delayed", "Manual")]
        [string] $Action,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [Logger] $Logger
    )

