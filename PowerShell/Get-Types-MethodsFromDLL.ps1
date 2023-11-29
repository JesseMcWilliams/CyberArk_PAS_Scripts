#using assembly "C:\Program Files (x86)\CyberArk\ApplicationPasswordSdk\NetPasswordSDK.dll"


Write-Host ("{0} : ********** Starting **********" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))

$dllPath = "C:\Program Files\CyberArk\ApplicationPasswordSdk\NetPasswordSDK.dll"

$assembly = [System.Reflection.Assembly]::LoadFile($dllPath)

$types = $assembly.GetTypes()

foreach ($type in $types)
{
    #
    if ($type.FullName.Length -gt 8)
    {
        #
        Write-Output ("`tType:  {0}" -f $type.FullName)

        $methods = $type.GetMethods([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::Static)

        foreach ($method in $methods)
        {
            #
            Write-Output ("`t`tMethod:  {0}" -f $method.Name)
            Write-Verbose " "
        }
    }
    
}
Write-Host ("{0} : ********** Finished **********" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.z"))