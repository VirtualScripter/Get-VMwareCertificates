<#
    .NOTES
        Author: Mark McGill, VMware
        Last Edit: 2/27/2023
        Version 1.0.6
    .SYNOPSIS
        Retrieves Certificate information from VMware products
    .SYNTAX
        Get-VMwareCertificates -Type <product> -Server <fqdn> -User <username> -Password <password>
    .EXAMPLE
        Get-VMwareCertificates -Type vCenter -Server "vcsa-01a.corp.local" -User "administrator@vsphere.local" -Password "VMware1!"
        # The URL type can be used to retrieve certificates from any URL. Port is optional, and username and password are not needed
        Get-VMwareCertificates -Type URL -Server "www.vmware.com" 
        Get-VMwareCertificates -Type URL -Server "www.mydomain.com" -Port 4443
#>
Function Get-VMwareCertificates
{
    #Requires -Version 6.0
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)][ValidateSet("vCenter","Horizon","LogInsight","NSX","vRA","vROps","URL")]$type,
        [Parameter(Mandatory=$true)]$server,
        [Parameter(Mandatory=$false)]$User,
        [Parameter(Mandatory=$false)]$Password,
        [Parameter(Mandatory=$false)]$Port #only needed for the URL type
    )

    $na = "N/A"
    $columns = "Server", "Type", "Subject", "Thumbprint", "IssuedTo", "IssuedBy", "ValidFrom", "ValidTo"

    Function ConvertFrom-UnixDate ($unixDate) 
    {
        $ErrorActionPreference = "Stop"
        Try
        {
            $date = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliSeconds($unixDate))
            $ErrorActionPreference = "Continue"
            Return $date
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "Error converting Unix Date/Time. Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
 
    Function Convert-PemCertificate ($certText)
    {
        try 
        {
            $tempFile = "$env:TEMP\temp.pem"
            $certText | Out-File -FilePath $tempFile -ErrorAction Stop
            $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($tempFile) -ErrorAction Stop
            Remove-Item -Path $tempFile -Force -ErrorAction Stop
            return $certificate
        }
        catch 
        {
            Throw "ERROR converting certifcate for $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }

    Function Get-VCSACertificates
    {
        [cmdletbinding()]
        Param
        (
            [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$vcenters,
            [Parameter(Mandatory=$true)]$user,
            [Parameter(Mandatory=$false)]$password,
            [Parameter(Mandatory=$false)][switch]$includeHosts,
            [Parameter(Mandatory=$false)][switch]$all
        )
        Begin
        {
            Try
            {
                $userName = $user.Split("@")[0]
                $domain = ($user.Split("@")[1]).Split(".")
                $userDn = "cn=$userName,cn=users,dc=$($domain[0]),dc=$($domain[1])"
                $baseDn = "dc=$($domain[0]),dc=$($domain[1])"
        
                If($password -eq $null)
                {
                    $securePassword = Read-Host -Prompt "Enter password for administrator account" -AsSecureString
                }
                Else
                {
                    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
                    Clear-Variable password
                }
        
                #create credentials for rest api
                $restAuth = $user + ":" + $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)))
                $encoded = [System.Text.Encoding]::UTF8.GetBytes($restAuth)
                $encoded=[System.Text.Encoding]::UTF8.GetBytes($restAuth)
                $encodedAuth=[System.Convert]::ToBase64String($encoded)
                $headersAuth = @{"Authorization"="Basic $($encodedAuth)"}
                #create credentials for ldap auth
                $ldapCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $userDN, $securePassword -ErrorAction Stop
            }
            Catch
            {
                Throw "Error creating authentication: $($_.Exception.Message)"
            }
            $certificates = @()
        } #end Begin
    
        Process
        {
            foreach($vcenter in $vcenters)
            {
                #query vCenter rest api for machine_cert
                $uriAuth = "https://$vcenter/rest/com/vmware/cis/session"
                $uriTls = "https://$vcenter/rest/vcenter/certificate-management/vcenter/tls"
                try 
                {
                    If($PSEdition -eq "Core")
                    {
                        $sessionId = (Invoke-RestMethod -Uri $uriAuth -Method Post -Headers $headersAuth -SkipCertificateCheck -ErrorAction Stop).Value
                        $tlsHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $tlsHeaders.Add("vmware-api-session-id", "$sessionId")
                        $machineCert = (Invoke-RestMethod -Uri $uriTls -Method Get -Headers $tlsHeaders -SkipCertificateCheck -ErrorAction Stop).Value
                        Write-Verbose "Successfully queried $vcenter API"
                    }
                    #accounts for Powershell version 5
                    elseif ($PSEdition -eq "Desktop") 
                    {
                        add-type @"
                        using System.Net;
                        using System.Security.Cryptography.X509Certificates;
                        public class TrustAllCertsPolicy : ICertificatePolicy {
                            public bool CheckValidationResult(
                                ServicePoint srvPoint, X509Certificate certificate,
                                WebRequest request, int certificateProblem) {
                                return true;
                            }
                        }
"@
                        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                        $sessionId = (Invoke-RestMethod -Uri $uriAuth -Method Post -Headers $headersAuth -ErrorAction Stop).Value
                        $tlsHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                        $tlsHeaders.Add("vmware-api-session-id", "$sessionId")
                        $machineCert = (Invoke-RestMethod -Uri $uriTls -Method Get -Headers $tlsHeaders -ErrorAction Stop).Value
                        Write-Verbose "Successfully queried $vcenter API 5"
                    }

                    $certificate = "" | Select $columns
                    $certificate.Server = $vcenter
                    $certificate.Type = "vCenter MACHINE_CERT"
                    $certificate.Subject = $machineCert.subject_dn
                    $certificate.Thumbprint = $machineCert.thumbprint
                    $certificate.IssuedTo = $vCenter
                    $certificate.IssuedBy = $machineCert.issuer_dn
                    $certificate.ValidFrom = $machineCert.valid_from
                    $certificate.ValidTo = $machineCert.valid_to
                }
                Catch
                {
                    If ($_.Exception.Message -match "Response status code does not indicate success")
                    {
                        $certificate = Get-CertificateInformation $vcenter 443 "vCenter MACHINE_CERT"
                    }
                    else 
                    {
                        Throw "Error querying $vcenter API: $($_.Exception.Message)"
                    }
                }
                
                $certificates += $certificate
    
                #retrieve certificate information from ldap
                [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
                $ldapConnect = New-Object System.DirectoryServices.Protocols.LdapConnection $vcenter
                $ldapConnect.SessionOptions.SecureSocketLayer = $false
                $ldapConnect.SessionOptions.ProtocolVersion = 3
                $ldapConnect.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    
                Try 
                {
                    $ErrorActionPreference = 'Stop'
                    $ldapConnect.Bind($ldapCreds)
                    $ErrorActionPreference = 'Continue'
                    Write-Verbose "Successfully connected to LDAP"
                }
                Catch 
                {
                    Throw "Error binding to LDAP on $vcenter : $($_.Exception.Message)"
                }
    
                $query = New-Object System.DirectoryServices.Protocols.SearchRequest 
                $query.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
                $query.DistinguishedName = $baseDN
                $query.Filter = "(&(userCertificate=*)(!(objectClass=STSTenantTrustedCertificateChain)))"
                $query.Attributes.Add("userCertificate") | Out-Null
                $query.Attributes.Add("objectClass") | Out-Null
    
                Try 
                {
                    $ErrorActionPreference = 'Stop'
                    $request = $ldapConnect.SendRequest($query) 
                    $ErrorActionPreference = 'Continue'
                    Write-Verbose "Successfully sent query to LDAP"
                }
                Catch 
                {
                    Throw "Error sending LDAP request - $($_.Exception.Message)"
                }
    
                $services = $request.Entries
                Write-Verbose "Query returned $($services.Count) services"
                foreach ($service in $services)
                {
                    $objectClasses = $service.Attributes['objectClass']
                    foreach ($objectClass in $objectClasses)
                    {
                        $convert = [System.Text.Encoding]::ASCII.GetString($objectClass)
                        If ($convert -match "vmw")
                        {
                            $type = $convert.Replace("vmw","")
                        }
                    }#end foreach objectClass
    
                    $serviceCerts = $service.Attributes['userCertificate']
                    foreach ($cert in $serviceCerts)
                    {
                        $certificate = "" | Select $columns
                        $X509Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([byte[]]$cert))
                        $certificate.Server = $vCenter
                        $certificate.Type = "vCenter $type"
                        $certificate.Subject = $X509Cert.Subject
                        $certificate.Thumbprint = $X509Cert.Thumbprint
                        $certificate.IssuedTo = $vCenter
                        $certificate.IssuedBy = $X509Cert.Issuer
                        $certificate.ValidFrom = $X509Cert.NotBefore
                        $certificate.ValidTo = $X509Cert.NotAfter
                        $certificates += $certificate
                    }#end foreach $cert
                }#end foreach service
                #filter out STSRelyingParty Certs
                If ($all -ne $true)
                {
                    $certificates = $certificates | Where{$_.Type -ne "STSRelyingParty" -and $_.Type -ne "STSTenantTrustedCertificateChain"} | Sort-Object -Property Type
                }
                
                #gets host certificates if -includeHosts is specified
                If ($includeHosts)
                {
                    Write-Verbose "Retrieving host certificate information"
                    If ($global:DefaultVIServer.Name -ne $vCenter -or $global:DefaultVIServer.IsConnected -eq $false)
                    {
                        Try
                        {
                            $vCenterCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$securePassword -ErrorAction Stop
                            Connect-VIServer $vcenter -Credential $vCenterCreds -ErrorAction Stop | Out-Null
                            Write-Verbose "Successfully connected to $vCenter using existing credentials"
                        }
                        Catch
                        {
                            Connect-VIServer $vcenter
                            Write-Verbose "Successfully connected to $vCenter"
                        }
                    }
                    Try
                    {
                        $vmHosts = Get-View -ViewType HostSystem -Property Name,Config.Certificate -Server $vCenter -Filter @{'Runtime.ConnectionState'='connected';'Runtime.PowerState'='poweredOn'} -ErrorAction Stop
                    }
                    Catch
                    {
                        Throw "Error getting host information from $vCenter - $($_.Exception.Message)"
                    }
                    Write-Verbose "Getting certificates from $($vmHosts.Count) hosts"
                    Write-Verbose "$($vmHosts.Name)"
    
                        foreach ($vmHost in $vmHosts)
                        {
                            Try
                            {
                                $cert = $vmHost.Config.Certificate
                                $certificate = "" | Select $columns
                                $X509Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([byte[]]$cert)) -ErrorAction Stop
                                $certificate.Server = $vCenter
                                $certificate.Type = "vCenter Host"
                                $certificate.Subject = $X509Cert.Subject
                                $certificate.Thumbprint = $X509Cert.Thumbprint
                                $certificate.IssuedTo = $vmHost.Name
                                $certificate.IssuedBy = $X509Cert.Issuer
                                $certificate.ValidFrom = $X509Cert.NotBefore
                                $certificate.ValidTo = $X509Cert.NotAfter
                                $certificates += $certificate
                                }
                            Catch
                            {
                                Write-Host "Error retrieving certificate information from $($vmHost.Name) - $($_.Exception.Message)" -ForegroundColor Red
                            }
                        }#end foreach vmHost
    
                    If ($vCenterCreds -ne $null)
                    {
                        Remove-Variable vCenterCreds
                    }
                }#end if
            }#end foreach vCenter
        }#end Process
        End
        {
            Remove-Variable ldapConnect
            Remove-Variable securePassword
            Remove-Variable ldapCreds        
            #Remove duplicate certificates - added for version 1.4
            $certificates = $certificates | Sort-Object -Property Thumbprint -Unique
            Return $certificates
        }
    }
      
    Function Get-vROPsCertificates($fqdn,$userName,$password)
    {
        Try
        {
            #api explorer: https://<servername>/suite-api/doc/swagger-ui.html
            $ErrorActionPreference = "Stop"
            #call rest api to get authentication token
            $authUri = "https://$fqdn/suite-api/api/auth/token/acquire"
            $certificateUri = "https://$fqdn/suite-api/api/certificate"
            $authHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $authHeaders.Add("Content-Type", "application/json")
            $authHeaders.Add("Accept", "application/json") 
            $authBody = @{
                        "username" = $userName;
                        "password" = $password
            } | ConvertTo-Json
            $token = (Invoke-RestMethod -uri $authUri -Headers $authHeaders -Body $authBody -Method Post -SkipCertificateCheck).Token
            
            #call rest api to get vROPs licensing
            $certificateHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $certificateHeaders.Add("Content-Type", "application/json")
            $certificateHeaders.Add("Authorization", "vRealizeOpsToken $token")
            $certificateHeaders.Add("Accept", "application/json")
            $certificates = (Invoke-RestMethod -uri $certificateUri -Headers $certificateHeaders -Method GET -SkipCertificateCheck).Certificates
            $certificateDetails = @()
            foreach($certificate in $certificates)
            {
                # Returns "Thumbprint", "IssuedTo", "IssuedBy", "ExpirationDate"
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "vROPs"
                $details.Subject = "$($certificate.issuedTo), $($certificate.issuedBy)"
                $details.Thumbprint = $certificate.thumbprint
                $details.IssuedTo = $certificate.issuedTo
                $details.IssuedBy = $certificate.issuedBy
                $details.ValidFrom = $na
                #accounts for date returned not being a valid System.DateTime format
                $validTo = ($certificate.expires).Split(" ")
                $details.ValidTo = "$($validTo[0]), $($validTo[1]) $($validTo[2]), $($validTo[5]), $($validTo[3])"
                $certificateDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $certificateDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving vROPs certificates from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
      
    Function Get-LogInsightCertificates($fqdn,$username,$password)
    {
        $ErrorActionPreference = "Stop"
        Try
        {
            $baseUri = "https://$fqdn/api/v1"
            $sessionUri = "$baseUri/sessions"
            $certificateUri = "$baseUri/certificate"
            $sessionBody = @{
                username = $username ;
                password = $password 
            } | ConvertTo-Json
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("Accept","application/json")
            $headers.Add("Content-Type","application/json")
            $sessionId = (Invoke-RestMethod $sessionUri -Headers $headers -Body $sessionBody -Method Post -SkipCertificateCheck).sessionId
            
            $headers.Add("Authorization","Bearer $sessionId")
            $certificates = Invoke-RestMethod -uri $certificateUri -Headers $headers -Method Get -SkipCertificateCheck
            #returns Owner(Subject), issuer,serialNum,validityPeriod
            $certificateDetails = @()
            
            foreach($certificate in $certificates)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "LogInsight"
                $details.Subject = $fqdn
                $details.Thumbprint = $na
                $details.IssuedTo = $certificate.owner.commonName
                $details.IssuedBy = $certificate.owner.issuer
                #accounts for date returned not being a valid System.DateTime format
                $validFrom = ($certificate.validityPeriod.from).Split(" ")
                $details.ValidFrom = "$($validFrom[0]), $($validFrom[1]) $($validFrom[2]), $($validFrom[5]), $($validFrom[3])"
                $validTo = ($certificate.validityPeriod.until).Split(" ")
                $details.ValidTo = "$($validTo[0]), $($validTo[1]) $($validTo[2]), $($validTo[5]), $($validTo[3])"
                $certificateDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $certificateDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving LogInsight certificates from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
      
    Function Get-vRACertificates($fqdn)
    {
        $ErrorActionPreference = "Stop"
        #uses plink to ssh to vRA server since it no longer can retrieve license info via API
        Try
        {
            $vraResponse = plink -load $fqdn -no-antispoof "vracli certificate ingress --list"
            If ($vraResponse -notcontains "-----BEGIN CERTIFICATE-----")
            {
                Throw "ERROR retrieving vRA certificates from $fqdn. Command did not return a certificate. Line $($_.InvocationInfo.ScriptLineNumber)"
            }
            $certificates = Convert-PemCertificate $vraResponse
            $certificateDetails = @()
                    
            foreach($certificate in $certificates)
            {
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "vRealize Automation"
                $details.Subject = $certificate.Subject
                $details.Thumbprint = $certificate.Thumbprint
                $details.IssuedTo = $certificate.Subject
                $details.IssuedBy = $certificate.Issuer
                $details.ValidFrom = $certificate.NotBefore
                $details.ValidTo = $certificate.NotAfter
                $certificateDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $certificateDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving vRA certificates from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
         
    Function Get-NSXCertificates($fqdn,$userName,$password)
    {
        #nsx-t api explorer: https://<nsx-server>/policy/api.html
        Try
        {
            $ErrorActionPreference = "Stop"
            $certificateUri = "https://$fqdn/api/v1/trust-management/certificates"
            $secPassword = ConvertTo-SecureString $password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($userName,$secPassword)
            $response = Invoke-RestMethod -uri $certificateUri -Authentication Basic -SkipCertificateCheck -Credential $creds -Method GET
            $certificates = $response.results.pem_encoded | Where  {$_ -notmatch "PRIVATE KEY"}
            $certificateDetails = @()
            foreach ($certificate in $certificates)
            {
                $certificate = Convert-PemCertificate $certificate
                $details = "" | Select $columns
                $details.Server = $fqdn
                $details.Type = "NSX"
                $details.Subject = $certificate.Subject
                $details.Thumbprint = $certificate.Thumbprint
                $details.IssuedTo = $certificate.Subject
                $details.IssuedBy = $certificate.Issuer
                $details.ValidFrom = $certificate.NotBefore
                $details.ValidTo = $certificate.NotAfter
                $certificateDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $certificateDetails
        }
        Catch
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving NSX certificates from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }

    Function Get-HorizonCertificates($fqdn,$userName,$password)
    {
        #API explorer: https://<fqdn-of-connectionserver>/rest/swagger-ui.html
        $ErrorActionPreference = "Stop"
        $baseUri = "https://$fqdn/rest"
        $userName = $userName.Split('@')
        If ($userName.count -ne 2)
        {
            Throw "UserName must be in SPN format (ie, administrator@corp.local)"
        }
        $user = $userName[0]
        $domain = $userName[1]
        try 
        {
            $authBody = @{
                "username" = $user;
                "domain" = $domain;
                "password" = $password
            } | ConvertTo-Json

            $authResponse = Invoke-RestMethod -Uri "$baseUri/login" -Method Post -Body $authBody -ContentType "application/json" -SkipCertificateCheck
            $authHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $authHeaders.Add("Authorization","Bearer $($authResponse.access_token)")
            $certificates = Invoke-RestMethod -Uri "$baseUri/monitor/connection-servers" -Method Get -Headers $authHeaders -SkipCertificateCheck
            $certificateDetails = @()
            foreach ($certificate in $certificates)
            {
                $details = "" | Select $columns       
                $details.Server = $certificate.Name
                $details.Type = "Horizon"
                $details.Subject = $fqdn
                $details.Thumbprint = $na
                $details.IssuedTo = $na
                $details.IssuedBy = $na
                $details.ValidFrom = ConvertFrom-UnixDate $certificate.certificate.valid_from
                $details.ValidTo = ConvertFrom-UnixDate $certificate.certificate.valid_to
                $certificateDetails += $details
            }
            $ErrorActionPreference = "Continue"
            Return $certificateDetails
        }
        catch 
        {
            $ErrorActionPreference = "Continue"
            Throw "ERROR retrieving Horizon certificates from $fqdn. $($_.Exception.Message). Line $($_.InvocationInfo.ScriptLineNumber)"
        }
    }
    Function Get-CertificateInformation($fqdn,$port)
    {
        #not currently in use
        #used to query a url directly for certificate info if it can't be done via API or other method
        If ($port -eq $null)
        {
            $port = 443
        }
        $tcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
        try {
            $tcpClient.Connect($fqdn, $port)
            $tcpStream = $tcpClient.GetStream()

            $callback = { param($sender, $cert, $chain, $errors) return $true }

            $sslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($tcpStream, $true, $callback)
            try {

                $sslStream.AuthenticateAsClient('')
                $certificate = $sslStream.RemoteCertificate

            } finally {
                $sslStream.Dispose()
            }

        } finally {
            $tcpClient.Dispose()
        }

        if ($certificate) {
            if ($certificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate
            }
                $details = "" | Select $columns       
                $details.Server = $fqdn
                $details.Type = "URL"
                $details.Subject = $certificate.Subject
                $details.Thumbprint = $certificate.Thumbprint
                $details.IssuedTo = $fqdn
                $details.IssuedBy = $certificate.Issuer
                $details.ValidFrom = $certificate.NotBefore
                $details.ValidTo =$certificate.NotAfter
            return $details
        }
    }
      
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    #///////////////////////////////CODE BODY ////////////////////////////////
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    #call the appropriate action based on product type
    switch ($type)
    {
        "vCenter" 
        {
            $results = Get-VCSACertificates -vCenter $server -user $user -password $password -includeHosts -all
        }
        "LogInsight" 
        {
            $results = Get-LogInsightCertificates $server $user $password
        }
        "Horizon"
        {
            $results = Get-HorizonCertificates $server $user $password
            #Needs to be Horizon v7.10 or higher, or you need to use the "URL" option to retrieve the certificate
        }
        "NSX" 
        {
            $results = Get-NSXCertificates $server $user $password
        }
        "vRA" 
        {
            $results = Get-vRACertificates $server $user $password
        }
        "vROps" 
        {
            $results = Get-vROPsCertificates $server $user $password
        }
        "URL"
        {
            $results = Get-CertificateInformation $server $port
        }
    }
    Return $results
}
