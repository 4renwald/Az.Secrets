function Get-AzAppSecrets {
<#
.SYNOPSIS

Retrieve Azure App Registration secrets set to expire within a user-defined timeframe.

.DESCRIPTION

Authenticates to your Azure tenant through Microsoft's Graph API, using your provided Service Principal credentials.
Queries the App Registrations for secrets information and parse them by the end date.
Will export the results to a .CSV file in a set location if set. 
Will send notifications to the App Registations Owner(s) if set, using the Send-Nofitication function.

.PARAMETER tenantId
Specifies the Azure tenant ID of your organization.

.PARAMETER daysToExpire
Specifies the timeframe for comparing secret expiration dates.

.PARAMETER appName
Specifies the names of App Registrations to query secrets informations. If not set, it will query all App Registrations.

.PARAMETER export
Specifies the path and name of the CSV file used to export the results.

.PARAMETER spCreds
Specifies credentials used for the Service Principal when authenticating to Microsoft's Graph API.
Cannot be used with Certificate Thumbprint and/or Certificate Name.

.PARAMETER useVault
Specifies if using a Secret Store vault when authenticating to Microsoft's Graph API.

.PARAMETER securePasswordPath
Specifies the path of the secure password file used to unlock the Secret Store Vault.

.PARAMETER vaultCreds
Specifies the Service Principal's credential name in the Secret Store vault for authenticating to Microsoft's Graph API.
Cannot be used with Certificate Thumbprint and/or Certificate Name.

.PARAMETER appId
Specified the ID of the service principal used to authentifcate to Microsoft's Graph API.
Is necessary if used with the Certificate Thumbprint/Name methods for authentication.

.PARAMETER certificateThumbprint
Specifies the Certificate Thrumbprint used when authenticating to Microsoft's Graph API.
Cannot be used with Service Principal credentials and/or Certificate Name.

.PARAMETER certificateName
Specifies the Certificate name used when authenticating to Microsoft's Graph API.
Cannot be used with Service Principal credentials and/or Certificate Thumbprint.

.PARAMETER notify
Specifies if email notifications will be sent to the App Registrations Owner(s).

.PARAMETER emailCreds
Specifies the credentials used for sending email notifications to App Registrations Owner(s).
Only use if you need to provide credentials for authentication
Cannot be used with $email parameter

.PARAMETER email
Specifies the sender email used for sending notifications
Use if you don't need authentication of your smtp server when sending notifications
Cannot be used with $emailCreds parameter

.PARAMETER smtpServer
Specifies the SMTP Server used for sending email notifications.
Used when "notify" is set to $true.

.PARAMETER port
Specifies the port number used for sending email notifications.
Used when "notify" is set to $true.

.OUTPUTS

Table of secrets that will expire within a user-defined timeframe.

.EXAMPLE

Example using every parameters
PS> Get-AzAppSecrets -tenantId $tenantId -daysToExpire 30 -spCreds $spCreds -notify $true -emailCreds $emailCreds -smtpServer smtp-mail.outlook.com -port 587 -export .\results.csv

.EXAMPLE

When using the Secure Store vault:
PS> Get-AzAppSecrets -tenantId $tenantId -daysToExpire 30 -useVault $true -spCreds az-sp-apps -securePasswordPath C:\securedFolder\passwd.xml -appName 'app-test' -notify $true -emailCreds $emailCreds -smtpServer smtp-mail.outlook.com -port 587 -export \.results.csv

#>
    param(
        [Parameter()][string] $tenantId, $appId, $export, $certificateThumbprint, $certificateName, $securePasswordPath, $email, $smtpServer, $port,
        [Parameter()][string[]] $appName,
        [Parameter()][int] $daysToExpire,
        [Parameter()][System.Management.Automation.PSCredential] $emailCreds, $spCreds,
        [Parameter()][bool] $notify, $useVault
    )
    # Start of the function

    try {
        if ($null -eq $tenantId -or $tenantId -eq "") {
            $tenantId = $(Write-Host "Enter the Azure tenant ID : " -ForegroundColor Cyan -NoNewLine; Read-Host)
        }

        if ($null -eq $daysToExpire -or $daysToExpire -eq "")  {
            $daysToExpire = $(Write-Host "Enter the number of days before the secrets expire : " -ForegroundColor Cyan -NoNewLine; Read-Host)        
        }

        # Will authenticate using the Secret Store vault if the parameter is set to true
        if ($true -eq $useVault)  {
            
            # If the path of the secure password file used to unlock the Secret Store Vault has not been declared, the function will ask for it
            if ($null -eq $securePasswordPath) {
                $securePasswordPath = $(Write-Host "Enter path for vault secret file (xml) : " -ForegroundColor Cyan -NoNewLine; Read-Host)      
            }
            
            # If the spCreds var has not been declared, the function will ask for it
            if ($null -eq $spCreds) {
                $spCreds = $(Write-Host "Enter the name of the secret in the vault to use for authentication with Service Principal) : " -ForegroundColor Cyan -NoNewLine; Read-Host) 
            }
            # Steps for unlocking the Secret Store vault, retrieving the creds for the service principal and setting them as the securePassword variable
            $password = Import-CliXml -Path $securePasswordPath
            Unlock-SecretStore -Password $password
            $securePassword = Get-Secret -Name $spCreds

            # Authenticating to the Azure tenant as the Service Principal using the Secret Store vault
            Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $securePassword -NoWelcome
        }
        # If a Certificate Thumbprint has been passed in the parameters, it will be used for authentication to Graph's API
        elseif ($null -ne $certificateThumbprint) {
            
            # If the appId parameter has not been declared, the function will ask for it
            if ($null -eq $appId)  {
                $appId = Read-Host $(Write-Host "Enter the application ID of the Service Principal used to connect to Azure : " -ForegroundColor Cyan -NoNewLine; Read-Host) 
            }
            
            # Authenticating to the Azure tenant as the Service Principal using the Certificate Thumbprint
            Connect-MgGraph -ClientId $appId -TenantId $tenantId -CertificateThumbprint $certificateThumbprint -NoWelcome
        }
        # If a Certificate Name has been passed in the parameters, it will be used for authentication to Graph's API
        elseif ($null -ne $certificateName) {
            
            # If the appId parameter has not been declared, the function will ask for it
            if ($null -eq $appId)  {
                $appId = Read-Host $(Write-Host "Enter the application ID of the Service Principal used to connect to Azure : " -ForegroundColor Cyan -NoNewLine; Read-Host) 
            }
            
            # Authenticating to the Azure tenant as the Service Principal using the Certificate Name
            Connect-MgGraph -ClientId $appId -TenantId $tenantId -CertificateName $certificateName -NoWelcome
        }
        # If none of the above parameters is used, this will be the default behavior
        else {

            # If the spCreds var has not been declared, the function will ask for it, as a PSCredential object
            if ($null -eq $spCreds)  {
                $spCreds = $(Write-Host "Enter the Service Principal credentials to authenticate to Azure : " -ForegroundColor Cyan -NoNewLine; Get-Credential) 
            }
            
            # Authenticating to the Azure tenant as the Service Principal using the provided credentials
            Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $spCreds -NoWelcome
        }
        
        # Catch the error while the authentication process and display the error message while terminating the process
        } catch {
            Write-Error 'Error while authenticating to Azure'
            throw $_.Exception
        }
    # End of the authentication process

    # Initialize an empty array that will store the final results
    $expiringSecrets = @()
    
    # If a list of specific applications to query through Graph has been specified, this logic will be used 
    if ($null -ne $appName) {
        # Will start processing each provided applications individually
        foreach ($app in $appName) {
            # Query the needed informations regarding the application through Graph and store them in the appInfos variable
            $appInfos = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?filter=startswith(displayName,'$app')?`$select=id,appId,displayName,passwordCredentials" -OutputType PSObject

            # Declare a variable that contains the information regarding the secrets retrived in the previous step
            $appSecrets = $appInfos.PSObject.Properties.Value.PasswordCredentials

            # Declare a variable containing the ID of the application retrieved in the previous step
            $appId = $appInfos.PSObject.Properties.Value.Id

            # Declare an empty array that will store the list of owners of the application
            $ownersList = @()

            # Query the application owners, the result contains the object ID of the owners
            $owners = Get-MgApplicationOwner -applicationId $appId

            # Query and exctract the email of all the owners based on their ID retrieved in the previous step and add them to the ownersList array
            foreach ($ownerId in $owners)  {
                $owner = Get-MgUser -UserId $ownerId.Id
                $ownersList += $owner.Mail
            }

            # Start of the parsing process of the retrieved secrets informations of the currently processing application
            foreach ($secret in $appSecrets) {

                # Process the secret only if the expiration date is set to be in the number of days set, or less
                if ($secret.EndDateTime -lt (Get-Date).AddDays($daysToExpire)) {

                    # Populate the expiringSecrets array with all the information needed for each secret set to expire
                    $expiringSecrets += @(
                        [pscustomobject]@{
                            'SecretName' = $secret.displayName
                            'SecretId' = $secret.keyId
                            'ApplicationName' = $app
                            'ApplicationId' = $appId
                            'Expiration' = $secret.endDateTime.ToString('yyyy-MM-dd')
                            'RemainingDays' = ($secret.endDateTime - (Get-Date)).Days
                            'Owner' = $ownersList.Trim('{}') -join ';'
                        }
                    )
                }
            }
        }
    }
    # Default behavior if specific applications were not declared. Will query every App Registrations on the tenant
    else {
        # Query the needed informations regarding all the applications through Graph and store them in the appInfos variable
        $appInfos = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials' -OutputType PSObject
        
        # Will start processing each provided applications individually
        foreach ($app in $appInfos.value)  {
            
            # Declare an empty array that will store the list of owners of the application
            $ownersList = @()

            # Query the application owners, the result contains the object ID of the owners
            $owners = Get-MgApplicationOwner -applicationId $app.Id

            # Query and exctract the email of all the owners based on their ID retrieved in the previous step and add them to the ownersList array
            foreach ($ownerId in $owners)  {
                $owner = Get-MgUser -UserId $ownerId.Id -ErrorAction SilentlyContinue
                $ownersList += $owner.Mail
            }

            # Declare a variable containing the ID of the application retrieved in the previous step
            $appName = $app.displayName

            # Declare a variable containing the secrets of the application retrieved in the previous step
            $appSecrets = $app.passwordCredentials

            # Start of the parsing process of the retrieved secrets informations of the currently processing application
            foreach ($secret in $appSecrets) {

                # Process the secret only if the expiration date is set to be in the number of days set, or less
                if ($secret.EndDateTime -lt (Get-Date).AddDays($daysToExpire)) {

                    # Populate the expiringSecrets array with all the information needed for each secret set to expire
                    $expiringSecrets += [pscustomobject]@{
                        'SecretName' = $secret.displayName
                        'SecretId' = $secret.keyId
                        'ApplicationName' = $appName.Trim('{}')
                        'ApplicationId' = $app.appId
                        'Expiration' = $secret.EndDateTime.ToString('yyyy-MM-dd')
                        'RemainingDays' = ($secret.EndDateTime - (Get-Date)).Days
                        'Owner' = $ownersList -join ';'
                        }
                    }
                }
            }
        }
    # End of data parsing

    # Display end results
    $expiringSecrets | Select-Object -Property SecretName,RemainingDays,Expiration,Owner,SecretId,ApplicationName,ApplicationId

    # If the export parameter is declared and not empty, will proceed with the export of the results
    if ($null -ne $export -and $export -ne '') {
        
        # Start of the export process
        try {

            # Construct the CSV based on the expiringSecrets variable then export it to the location specified in the parameter
            $expiringSecrets | Select-Object SecretName,SecretId,ApplicationName,ApplicationId,Expiration,RemainingDays,@{Name='Owner'; Expression={$_.Owner -join ';'}} | Export-CSV -Path "$export"
            Write-Host "Report successfully export to $export" -ForegroundColor Green
        
        # Catch the error while export process and display the error message while terminating the process
        } catch {
            Write-Error "Error while exporting the results to : $export"
            throw $_.Exception
        }
    }

    # If the notify parameter is set to true, the Send-Notification function will be called
    if ($true -eq $notify) {
        Send-Notification 
    }

    # When all the tasks are done executing, try disconnecting from Graph's API
    try {

        # Disconnect from Graph's API
        Disconnect-MgGraph | Out-Null

    # Catch the error while disconnecting and display the error message while terminating the process
    } catch {
        Write-Error 'Error while disconnecting MgGraph'
        throw $_.Exception
    }
}

function Send-Notification {
<#
.SYNOPSIS

Send email notifications to each App Registrations Owners with list of expiring/expired secrets

.DESCRIPTION

Generates a recipient list based off the results of the Get-AzAppSecrets function.
Sends emails to the owners of each applications using the provided credentials (if needed).
Cannot be called when importing the module.

#>
    # If the smtp server is not declared, the function will ask for it
    if ($null -eq $smtpServer)  {
        $smtpServer = $(Write-Host "Enter the SMTPServer : " -ForegroundColor Cyan -NoNewLine; Read-Host) 
    }

    # If the port number is not declared, the function will ask for it
    if ($null -eq $port)  {
        $port = $(Write-Host "Enter the port number for SMTP connection (default is 587) : " -ForegroundColor Cyan -NoNewLine; Read-Host)
    }

    # Generate a list of expiring secrets based on the owners
    $secretsList = $expiringSecrets | Group-Object Owner

    # Add each owners to a recipient list 
    foreach ($owner in $secretsList) {
        $recipientList = [MimeKit.InternetAddressList]::new()
        foreach ($emailAddress in $owner.Name -split ';') {
            $recipientList.Add([MimeKit.InternetAddress]$emailAddress)
        }

        # Declare a App Name variable to make sure the name does not appear multiple times in the subject and body of the email
        $uniqueAppName = $owner.Group | Select-Object -ExpandProperty ApplicationName -Unique

        # Declare the subject of the email
        $subject = [string]"Secrets expiration notice for Azure App : $($uniqueAppName)"

        # Generate the body of the email that will be sent to the owners
        $htmlBody = [string]@"
        <div style="font-size: 14px;">
        Hi,<br><br>
        
        This email is to notify you that one or more secrets for the application $($uniqueAppName)  will expire in $daysToExpire days or less.<br><br>
        
        Here is the information regarding the secrets :
        <table style="border-collapse: collapse; width: 100%; border: 1px solid black;">
        <tr>
            <th style="border: 1px solid black; padding: 8px;">Secret name</th>
            <th style="border: 1px solid black; padding: 8px;">ID</th>
            <th style="border: 1px solid black; padding: 8px;">Application Name</th>
            <th style="border: 1px solid black; padding: 8px;">Expiration date</th>
            <th style="border: 1px solid black; padding: 8px;">Remaining Days</th>
        </tr>
        $(foreach ($secret in $owner.Group)  {
            @"
            <tr>
            <td style="border: 1px solid black; padding: 8px;">$($secret.SecretName)</td>
            <td style="border: 1px solid black; padding: 8px;">$($secret.SecretId)</td>
            <td style="border: 1px solid black; padding: 8px;">$($secret.ApplicationName)</td>
            <td style="border: 1px solid black; padding: 8px;">$($secret.Expiration)</td>
            <td style="border: 1px solid black; padding: 8px;">$($secret.RemainingDays)</td>
        </tr>
"@})
        </table><br><br>
        </div>
"@

    # If email credentials were provided (not always needed), will send the email using them
    if ($null -ne $emailCreds)  {

        # Try sending the email using the provided credentials
        try {
            Write-Host "Sending email notification to $($recipientList)" -ForegroundColor Green

            # Send the email using the Send-MailKitMessage module with all the needed parameters
            Send-MailKitMessage -SMTPServer $smtpServer -Port $port -From $emailCreds.UserName -RecipientList $recipientList -Subject $subject -HTMLBody $htmlBody -Credential $emailCreds
        
        # Catch the error while sending the email and display the error message while terminating the process
        } catch {
            Write-Error "Error while sending email notification to $recipientList"
            throw $_.Exception
        }
    }

    # If no email credentials were provided, this will be the default action
    else  {

        # If the email used for sending the notifications is not declared, the function will ask for it
        if ($null -eq $email)  {
            $email = $(Write-Host 'Please enter the sender address for the email notifications' -ForegroundColor Cyan -NoNewLine; Read-Host) 
        }
        
        # Try sending the email
        try {
            Write-Host "Sending email notification to $($recipientList)" -ForegroundColor Green

            # Send the email using the Send-MailKitMessage module with all the needed parameters
            Send-MailKitMessage -SMTPServer $smtpServer -Port $port -From $email -RecipientList $recipientList -Subject $subject -HTMLBody $htmlBody
        
        # Catch the error while sending the email and display the error message while terminating the process
        } catch {
            Write-Error "Error while sending email notification to $recipientList"
            throw $_.Exception
        }
    }
    }
}

function Get-AzKVExpiringSecrets {

<#
.SYNOPSIS
    Retrieves secrets expiring in a specified number of days or less from Azure Key Vault.

.DESCRIPTION
    The Get-AzKVExpiringSecrets function retrieves secrets expiring in a specified number of days or less from Azure Key Vault.
    It provides options to filter by vault name, secret name, certificate name, and key name.
    The function can generate a report of the expiring secrets and send it via email.

.PARAMETER vaultName
    Specifies the name of the Azure Key Vault(s) to retrieve secrets from.

.PARAMETER secretName
    Specifies the name of the secret(s) to retrieve. Requires the vaultName parameter to be provided.

.PARAMETER certName
    Specifies the name of the certificate(s) to retrieve. Requires the vaultName parameter to be provided.

.PARAMETER keyName
    Specifies the name of the key(s) to retrieve. Requires the vaultName parameter to be provided.

.PARAMETER report
    Indicates whether to generate a report of the expiring secrets. Default is $false.

.PARAMETER emailCreds
    Specifies the credentials for sending the report via email. If not provided, the user will be prompted to enter the email address and password.

.PARAMETER RecipientList
    Specifies the recipients of the report, separated by commas. If not provided, the user will be prompted to enter the recipients.

.PARAMETER daysToExpire
    Specifies the number of days within which the secrets should expire.

.OUTPUTS
    The function outputs a table of expiring secrets and, if the report parameter is set to $true, generates a CSV report and sends it via email.

.EXAMPLE
    Get-AzKVExpiringSecrets -vaultName "myvault" -daysToExpire 30
    Retrieves secrets expiring in 30 days or less from the "myvault" Azure Key Vault.

.EXAMPLE
    Get-AzKVExpiringSecrets -vaultName "vault1", "vault2" -secretName "secret1", "secret2" -daysToExpire 7 -report -emailCreds $creds -RecipientList "user1@example.com", "user2@example.com"
    Retrieves secrets with the specified names from the "vault1" and "vault2" Azure Key Vaults that expire in 7 days or less.
    Generates a report, sends it via email using the provided credentials, and sends it to the specified recipients.

#>

    param(
        [Parameter()][string[]] $vaultName, # Name of the Azure Key Vault(s) to retrieve secrets from
        [Parameter()][string[]] $secretName, # Name of the secret(s) to retrieve
        [Parameter()][string[]] $certName, # Name of the certificate(s) to retrieve  
        [Parameter()][string[]] $keyName, # Name of the key(s) to retrieve
        [Parameter()][bool] $report, # Indicates whether to generate a report of the expiring secrets
        [Parameter()][System.Management.Automation.PSCredential] $emailCreds, # Credentials for sending the report via email
        [Parameter()][string[]] $RecipientList, # Recipients of the report
        [Parameter(Mandatory=$true)][int] $daysToExpire # Number of days within which the secrets should expire
    )

    # Output message to indicate that the function is retrieving secrets expiring in a specified number of days or less
    Write-output "Getting secrets expiring in $daysToExpire days or less..."
    
    $allItems = @() # Array to store all secrets, certificates, and keys
    $secrets = @() # Array to store secrets
    $certificates = @() # Array to store certificates
    $keys = @() # Array to store keys

    try {
        # Retrieve all secrets, certificates, and keys from the specified vaults. Example: Get-AzKVExpiringSecrets -daysToExpire 30 -vaultName "vault1", "vault2"
        if ($null -ne $vaultName -and $null -eq $secretName -and $null -eq $certName -and $null -eq $keyName) {
            # Iterate through each vault
            foreach ($vault in $vaultName) {
                $secrets += Get-AzKeyVaultSecret -VaultName $vault # Retrieve all secrets from the specified vaults
                $certificates += Get-AzKeyVaultCertificate -VaultName $vault # Retrieve all certificates from the specified vaults
                $keys += Get-AzKeyVaultKey -VaultName $vault # Retrieve all keys from the specified vaults
            }
        }

        # Retrieve the specified secrets, certificates, and keys from the specified vaults. Example: Get-AzKVExpiringSecrets -daysToExpire 30 -vaultName "vault1", "vault2" -secretName "secret1" -keyName "key1", "key2"
        elseif ($null -ne $secretName -or $null -ne $certName -or $null -ne $keyName) {
            # Check that the vault name is provided when specifying a secret name
            if ($null -eq $vaultName) {
                Write-Error "Vault name must be provided when specifying a secret name."
                return
            }

            if($null -ne $secretName) { # Check if secret name is provided
                foreach ($vault in $vaultname) { # Iterate through each vault
                    # Retrieve the specified secrets from the specified vaults and add them to the $secrets array
                    foreach ($secret in $secretName) {
                        $secrets += Get-AzKeyVaultSecret -VaultName $vault -Name $secret
                    }
                }
            }

            if($null -ne $certName) { # Check if certificate name is provided
                foreach ($vault in $vaultname) { # Iterate through each vault
                    # Retrieve the specified certificates from the specified vaults and add them to the $certificates array
                    foreach ($cert in $certName) {
                        $certificates += Get-AzKeyVaultCertificate -VaultName $vault -Name $cert
                    }
                }
            }

            if($null -ne $keyName) { # Check if key name is provided
                foreach ($vault in $vaultname) { # Iterate through each vault
                    # Retrieve the specified keys from the specified vaults and add them to the $keys array
                    foreach ($key in $keyName) {
                        $keys += Get-AzKeyVaultKey -VaultName $vault -Name $key
                    }
                }
            }
        }

        # Retrieve all secrets, certificates, and keys from all vaults. Example: Get-AzKVExpiringSecrets -daysToExpire 30
        else {
            # Retrieve all secrets, certificates, and keys from all vaults
            $vaultNames = Get-AzKeyVault | Select-Object -ExpandProperty VaultName
            # Iterate through each vault and add all secrets, certificates, and keys to the $secrets, $certificates, and $keys arrays
            foreach ($vault in $vaultNames) {
                $secrets += Get-AzKeyVaultSecret -VaultName $vault 
                $certificates += Get-AzKeyVaultCertificate -VaultName $vault
                $keys += Get-AzKeyVaultKey -VaultName $vault
            }
        }

        # Add each item to the $allItems array if it is not already present
        # This is done to avoid duplicates because the certificates are in the $secrets and $keys array as well
        foreach ($item in $certificates) {
            if ($item.Name -notin $allItems.Name) {
                $allItems += $item
            }
        }

        foreach ($item in $secrets) {
            if ($item.Name -notin $allItems.Name) {
                $allItems += $item
            }
        }

        foreach ($item in $keys) {
            if ($item.Name -notin $allItems.Name) {
                $allItems += $item
            }
        }
    }
    catch {
        Write-Error "An error occurred while retrieving secrets, certificates, and keys: $_"
    }

    $output = @() # Array to store the expiring secrets, keys and certificates

    # Iterate through each item in the $allItems array and add it to the $output array if it is expiring in the specified number of days or less
    foreach ($item in $allItems) {
        # Check if the item has an expiration date
        if (-not [string]::IsNullOrEmpty($item.Name)) {
            $expirationDate = $item.Expires
            $daysTillExpiration = ($expirationDate - (Get-Date)).Days
            
            # Add the item to the $output array if it is expiring in the specified number of days or less
            if ($daysTillExpiration -le $daysToExpire) {
                $output += [pscustomobject]@{
                    Name = $item.Name
                    ExpirationDate = $expirationDate
                    DaysTillExpiration = $daysTillExpiration
                    VaultName = $item.VaultName
                    Type = ($item.id -split "/")[3] # Get the type of the item (secret, certificate, or key). This is used in the Renew-AzKVExpiringSecrets function
                }
            }
        }
    }
    
    $output | Select-Object -Property Name,ExpirationDate,DaysTillExpiration,VaultName,Type # Output the expiring secrets, keys, and certificates
    
    try {
            # Generate a report of the expiring secrets and send it via email if the report parameter is set to $true
            if ($true -eq $report) {
                $output | Export-Csv -Path "ExpiringSecretsReport.csv" -NoTypeInformation

                # Output message to indicate that the report has been generated
                Write-output "Report generated."

                # Prompt user for email credentials if not provided
                if ($null -eq $emailCreds) {
                    $emailCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $(Write-Host "Enter the email address to send the report from:" -NoNewline; Read-Host), $(Write-Host "Enter the password for the email address:" -NoNewline; Read-Host -AsSecureString) 
                }

                # Prompt user for recipients if not provided
                if ($null -eq $RecipientList) {
                    $RecipientList = $(Write-Host  "Enter the recipients of the report (separated by commas):" -NoNewline; Read-Host)
                }
                

                # Generate email body
                $body = @"
                <html>
                <head>
                <style>
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 5px;
                    text-align: left;
                }
                </style>
                </head>
                <body>
                <h2>Expiring Secrets Report</h2>
                <p>The following secrets are expiring in $daysToExpire days or less:</p>
                <table style="width:100%">
                <tr>
                    <th>Name</th>
                    <th>Expiration Date</th>
                    <th>Days Till Expiration</th>
                    <th>Vault Name</th>
                    <th>Type</th>
                </tr>
"@
                # Add each item to the email body
                foreach ($item in $output) { 
                    $body += @"
                    <tr>
                        <td>$($item.Name)</td>
                        <td>$($item.ExpirationDate)</td>
                        <td>$($item.DaysTillExpiration)</td>
                        <td>$($item.VaultName)</td>
                        <td>$($item.Type)</td>
                    </tr>
"@
                }
                $body += @"
                </table>
                </body>
                </html>
"@

                # Declare variables for email parameters
                $SMTPServer = "smtp.office365.com"
                $Port = 587
                $Subject = "Expiring Secrets Report"
                $HTMLBody = $body

                # Convert the list of recipients to MimeKit.InternetAddress objects
                $Recipients = [MimeKit.InternetAddressList]::new()

                # Iterate through each recipient and add it to the $recipients array
                foreach ($recipient in $RecipientList -split ",") {
                    $recipients.Add([MimeKit.InternetAddress]$recipient)
                }

                # Create a list of attachments and add the report to it
                $AttachmentList = [System.Collections.Generic.List[string]]::new()
                $AttachmentList.Add("ExpiringSecretsReport.csv")


                # Send the report via email using Send-MailKitMessage function
                Send-MailKitMessage -SMTPServer $SMTPServer -Port $Port -From $emailCreds.UserName -RecipientList $Recipients -Subject $Subject -HTMLBody $HTMLBody -Credential $emailCreds -AttachmentList $AttachmentList
            }
        }
    catch {
        Write-Error "An error occurred while generating the report: $_"
    }
}


function Update-AzKVExpiringSecrets {

<#
.SYNOPSIS
Renews expiring secrets and keys in Azure Key Vault.

.DESCRIPTION
The Update-AzKVExpiringSecrets function is used to renew expiring secrets and keys in Azure Key Vault. It takes a CSV file containing the secrets to renew and the number of days from today's date for expiration.

.PARAMETER filePath
The path to the CSV file containing the secrets to renew.

.PARAMETER expirationDate
The number of days from today's date for expiration.

.EXAMPLE
Update-AzKVExpiringSecrets -filePath "C:\Secrets.csv" -expirationDate 30
This example renews the secrets and keys specified in the "Secrets.csv" file, setting the expiration date to 30 days from today's date.

#>


    param (
        [Parameter(Mandatory = $true)][string] $filePath, # Path to CSV file containing the secrets to renew
        [Parameter(Mandatory=$true)][int] $expirationDate # Number of days from today's date
    )

    try {
    # Check if the CSV file exists at the specified path if not, return an error
    if (-not (Test-Path $filePath)) {
        Write-Error "File not found. $filePath"
        return
    }


    # Import the CSV file
    $KeyVaultObjects = Import-Csv $filePath

    # Itirate through each row in the CSV file
    foreach ($row in $KeyVaultObjects) {
        
        # Renew the key with the specified expiration date if the type is "keys"
        if ($row.Type -eq "keys") {
            # Create a new version of the key with the specified expiration date
            Add-AzKeyVaultKey -VaultName $row.VaultName -Name $row.Name -Destination Software -Expires (Get-Date).AddDays($expirationDate) | Out-Null
            # Output message to indicate that the key has been renewed
            Write-Host "Key: $($row.Name) renewed for $((Get-Date).AddDays($expirationDate))."
        }

        # Renew the secret with the specified expiration date if the type is "secrets"
        elseif ($row.Type -eq "secrets") {
            # Prompt user for the new secret value
            $newSecretValue = Read-Host "Enter the new secret value:" -AsSecureString
            # Set the secret value to the new secret value and set the expiration date to the specified number of days from today's date
            Set-AzKeyVaultSecret -VaultName $row.VaultName -Name $row.Name -SecretValue (ConvertTo-SecureString -String $newSecretValue -AsPlainText -Force) -Expires (Get-Date).AddDays($expirationDate) | Out-Null
            # Output message to indicate that the secret has been renewed
            Write-Host "Secret: $($row.Name) renewed for $((Get-Date).AddDays($expirationDate))."
        }

    }

    
    } 
    catch {
        Write-Error "An error occurred while renewing the secrets and keys: $_"
    }

}