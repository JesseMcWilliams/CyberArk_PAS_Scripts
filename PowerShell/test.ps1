Write-Host ("******************** {0} : {1} ********************" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), "Starting")
# Create the XML filename.
$outputFileName = ".\testXML.xml"

$fullyQualifiedPath = (Resolve-Path $outputFileName)

Write-Host ("{0} |  Create the initial object." -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
# Create a data structure.
$parentTable = [PSCustomObject]@{
    Actions = @(
        [PSCustomObject]@{
            Action = "Push"
            SafeName = "Z_Vault_Conf_Files"
            SafeFolder = "Modules"
            FilePath = "C:\Users\Jesse\My Drive\Scripts\CyberArk_PAS_Scripts\CyberArk_PAS_Scripts\PowerShell\Modules"
            Files = @("*.cred", "CyberArk_PACLI_CredFile.cred.entropy")
        },
        [PSCustomObject]@{
            Action = "Push"
            SafeName = "Z_Vault_Conf_Files"
            SafeFolder = "Logs"
            FilePath = "C:\Users\Jesse\My Drive\Scripts\CyberArk_PAS_Scripts\CyberArk_PAS_Scripts\PowerShell\Modules"
            Files = @("*")
        }
    )
    MoreActions = @(
        @{Attrib = "Attrib 1"}
        @{Attrib = "Attrib 2"}
    )
    Files = @("File 1", "File 2")
}

Write-Host ("{0} |  Create the XML file from the initial object" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Host ("{0} |  Write File:  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $fullyQualifiedPath)
# Create the XML file.
$outXMLString = ConvertTo-Xml -InputObject $parentTable -As String -Depth 4 

Out-File -FilePath $fullyQualifiedPath -InputObject $outXMLString

#Read the XML file.
Write-Host ("{0} |  Create the New XML Object." -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
# Create the base XML object.
$_ConfigXML = [System.Xml.XmlDocument]::New()

Write-Host ("{0} |   Read File:  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $fullyQualifiedPath)
# Load the file.
$_ConfigXML.Load($fullyQualifiedPath)

Write-Host ("{0} | XML Ojbect Type:  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_ConfigXML.GetType())
Write-Host ("{0} |     XML Ojbect :  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_ConfigXML.Attributes)
Write-Host ("******************** {0} : {1} ********************" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), "Finished")