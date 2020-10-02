ConvertFrom-StringData @'
###PSLOC
WinRmNotRunning = The WinRM service is not running or not configured, to configure WinRm on this machine use the command winrm quickconfig from an elevated command prompt
KeyvaultLogon = To access credentials stored in keyvault, pleasde authenticate to Azure
NoAzureCntext = No AzContext found to access keyvault
LogonToEnv = Connecting to environment {0} enter credentials when propmted
LogonPep = Connecting to pep on environment {0} enter credentials when propmted
TrustedHost = The WinRm TrustedHosts on this workstation is not configured  to allow connect to ERCS IP addresses for this stamp . Use Connect-Pep session with -Force from an elevated PowerShell session or add the required entries and try again
ForceAdmin = Using the Force Switch requires running as Admin
'@