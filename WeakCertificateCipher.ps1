# This script looks for weak certificates stored in Active Directory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Execution')]
    [string]$ForestName,

    [Parameter(Mandatory=$true, ParameterSetName='Execution')]
    [string[]]$DomainNames
)

$Global:self = @{
    ID = 86
    UUID = '966491f1-e550-48ae-aae5-2fc1b0ae4a60'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000086'
    Name = 'Weak certificate cipher'
    ScriptName = 'WeakCertificateCipher'
    Description = 'This indicator looks for certificates stored in Active Directory with key size smaller than 2048 bits or utilizes DSA encryption.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'Weak certificates can be abused by attackers to gain access to systems that use certificate authentication.'
    ResultMessage = 'Found {0} certificates with weak configuration.'
    Remediation = 'Problematic certificates need to be revoked and re-issued. Child certificates must also be re-issued. Expired certificates should also be purged from trusted certificates stores. When issuing certificates, ensure the following requirements: Use RSA or ECDSA for certificate signatures (avoid DSA), RSA key length is at least 2048 bits, and an up-to-date library is used to generate the RSA key.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'KeyLength'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'SignatureAlgorithmOID'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SubjectName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ValidTo'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Certificate-based Authentication') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_certificates_vuln') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()
$failedCerts = 0

try {
    # Lowercase domain names
    $DomainNames = $DomainNames | ForEach-Object { $_.ToLower() }

    # Convert ForestName to lowercase
    $ForestName = $ForestName.ToLower()

    # Get forest distinguished name
    $forestDN = "CN=Configuration,$($ForestName)" # Example placeholder for actual DN retrieval
    
    # Define filter for certificates
    $filter = "(&(|(objectCategory=certificationAuthority)(objectCategory=pKIEnrollmentService)(objectCategory=samDomain))(caCertificate=*))"

    # Define search parameters
    $searchParams = @{
        Filter = $filter
        Properties = "cacertificate"
        SearchBase = "LDAP://CN=Configuration,$forestDN"
        SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    }

    # Function to perform AD search
    function Search-ADConfig {
        param (
            [string]$ForestName,
            [string[]]$DomainNames,
            [hashtable]$SearchParams
        )

        $results = @()
        $unavailableDomains = @()

        foreach ($domain in $DomainNames) {
            try {
                $directorySearcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domain")
                $directorySearcher.Filter = $SearchParams.Filter
                $directorySearcher.PropertiesToLoad.AddRange($SearchParams.Properties)
                $directorySearcher.SearchRoot = [ADSI]$SearchParams.SearchBase
                $directorySearcher.SearchScope = $SearchParams.SearchScope
                
                $searchResults = $directorySearcher.FindAll()
                $results += $searchResults
            }
            catch {
                $unavailableDomains += $domain
            }
        }

        return @{ Results = $results; UnavailableDomains = $unavailableDomains }
    }

    $searchResults = Search-ADConfig -ForestName $ForestName -DomainNames $DomainNames -SearchParams $searchParams
    $results = $searchResults.Results
    $unavailableDomains = $searchResults.UnavailableDomains

    # DSA OIDs
    $deniedAlgorithmsOIDs = @("1.2.840.10040.4.3", "1.2.840.10040.4.1")

    # Check certificates
    $checkedCertificates = [System.Collections.ArrayList]@()
    foreach ($result in $results) {
        $certificates = $result.Properties["cacertificate"] -as [System.Collections.ArrayList]
        foreach ($caCertificate in $certificates) {
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(,$caCertificate)
                if ($checkedCertificates.Contains($cert.Thumbprint)) {
                    continue
                }
                if (($cert.SignatureAlgorithm.Value -in $deniedAlgorithmsOIDs -or ($cert.PublicKey.Key.KeySize -and $cert.PublicKey.Key.KeySize -lt 2048)) -and $cert.NotAfter -gt (Get-Date)) {
                    $thisOutput = [PSCustomObject][Ordered]@{
                        SubjectName = $cert.Subject
                        SignatureAlgorithmOID = $cert.SignatureAlgorithm.Value
                        KeyLength = $cert.PublicKey.Key.KeySize
                        ValidTo = $cert.NotAfter
                    }
                    [void]$outputObjects.Add($thisOutput)
                    $failedCerts++
                }
                [void]$checkedCertificates.Add($cert.Thumbprint)
            }
            catch {
                $thisOutput = [PSCustomObject][Ordered]@{
                    SubjectName = $result.DistinguishedName
                    SignatureAlgorithmOID = "Failed to parse certificate"
                    KeyLength = ""
                    ValidTo = ""
                }
                [void]$outputObjects.Add($thisOutput)
                $failedCerts++
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            ResultObjects = $outputObjects
            ResultMessage = "Found $($outputObjects.Count) certificates with weak configuration."
            Remediation = "Problematic certificates need to be revoked and re-issued. Child certificates must also be re-issued. Expired certificates should also be purged from trusted certificates stores. When issuing certificates, ensure the following requirements: Use RSA or ECDSA for certificate signatures (avoid DSA), RSA key length is at least 2048 bits, and an up-to-date library is used to generate the RSA key."
            Status = 'Failed'
            Score = 0
        }
    }
    elseif ($unavailableDomains.Count -eq $DomainNames.Count) {
        $res = [PSCustomObject]@{
            Status = 'Error'
            ResultMessage = "Unable to retrieve the Configuration partition. The following domains were unavailable: $($unavailableDomains -join ', ')"
            Remediation = "None"
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
        Remediation = "None"
    }
}

return $res
