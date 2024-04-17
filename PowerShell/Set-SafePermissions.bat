CLS
@Echo Off

set PVWAURL=https://192.168.184.128
set AuthMethod=CyberArk
set TemplateSafe=Z_Template_Safe_Permissions
set RoleNamePrefix=RG_
set InputFiles=!Input_SafePermissions.csv !Input_SafePermissions_Remove.csv

Echo Launching PowerShell script!
PowerShell -NoProfile -ExecutionPolicy Bypass -File ".\Set-SafePermissions.ps1" ^
-PVWAURL "%PVWAURL%" -AuthMethod "%AuthMethod%" -TemplateSafe "%TemplateSafe%" ^
-RoleNamePrefix "%RoleNamePrefix%" -InputFiles %InputFiles% -SkipCertificateCheck
