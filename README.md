# Az.Secrets
PowerShell module to automate the management of expiring App Registrations and Keyvault secrets in Azure

## Requirements :
-	PowerShell Core version >= 7.3.9
-	The following modules :
  - Microsoft.Graph
  - Az.KeyVault
  - Az.Accounts
 
The following modules are optional but recommended to allow full usage of the module :
To send email notifications
- Send-MailKitMessage

If using a local vault for Azure authentication:
- Microsoft.PowerShell.SecretManagement
- Microsoft.PowerShell.SecretStore
 
To install all requirements: 
`Install-Module @("Microsoft.Graph";"Microsoft.PowerShell.SecretManagement";"Microsoft.PowerShell.SecretStore";"Send-MailKitMessage";“Az.Accounts”;”Az.KeyVault”)`

## Installation
Extract **Az.Secrets** to one of your **PSModulePath** folder. 
 
 To check valid paths : `$env:PSModulePath -split ';'`

Import the module with : `Import-Module Az.Secrets`

## Usage
Read **Az.Secrets.psm1** for functions parameters and examples
