@Echo Off
CLS

set PVWAURL=https://epv.company.com
set AuthMethod=CyberArk
set InputFiles=!Input_SafePermissions.csv

Echo Launching PowerShell script!
PowerShell -NoProfile -ExecutionPolicy Bypass -File ".\Set-AccountAction.ps1" ^
-PVWAURL "%PVWAURL%" -AuthMethod "%AuthMethod%" -InputFiles %InputFiles% -SkipCertificateCheck