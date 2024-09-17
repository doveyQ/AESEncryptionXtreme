[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [string]$ForestName,

    [Parameter(Mandatory=$True)]
    [string[]]$DomainNames
)

$Global:self = @{
    ID = 27
    UUID = 'ad0f14a9-580c-4709-b8d2-c1be16b22a3e'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000027'
    Name = 'Users with Kerberos pre-authentication disabled'
    ScriptName = 'UsersWithPreAuth'
    Description = 'This indicator identifies users with Kerberos pre-authentication disabled, which exposes them to potential ASREP-Roasting attacks, such as Kerberoasting. For more information, visit <a href="https://social.technet.microsoft.com/wiki/contents/articles/23559.kerberos-pre-authentication-why-it-should-not-be-disabled.aspx" target="_blank">this link</a>.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '3d'
    Impact = 5
    LikelihoodOfCompromise = 'Accounts with Kerberos pre-authentication disabled are more susceptible to ASREP-Roasting attacks.'
    ResultMessage = 'Found {0} users with pre-authentication disabled.'
    Remediation = 'Enable pre-authentication on all user accounts if possible. Otherwise, consider reducing the privileges of these accounts.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_kerberos_properties_preauth_priv', 'vuln2_kerberos_properties_preauth') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

# Helper function to check domain availability
function Test-DomainAvailability {
    param ([string]$DomainName)
    try {
        # Check connectivity to the domain (e.g., DNS resolution)
        $dnsResult = Resolve-DnsName -Name $DomainName -ErrorAction Stop
        return $true
    } catch {
        Write-Error "Domain $DomainName is unavailable: $_"
        return $false
    }
}

# Helper function to retrieve the Distinguished Name for a domain
function Get-DomainDN {
    param ([string]$DomainName)
    try {
        $domainEntry = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$DomainName").FindOne().GetDirectoryEntry()
        return $domainEntry.distinguishedName
    } catch {
        Write-Error "Failed to get DN for domain ${DomainName}: $_"
        return $null
    }
}

# Initialize results array
$outputObjects = [System.Collections.ArrayList]@()
$failedDomainCount = 0

try {
    if ($PSBoundParameters['ForestName'] -and $PSBoundParameters['DomainNames']) {
        $ForestName = $ForestName.ToLower()
        $DomainNames = $DomainNames | ForEach-Object { $_.ToLower() }
    }

    $unavailableDomains = [System.Collections.ArrayList]@()

    foreach ($domain in $DomainNames) {
        if (-not (Test-DomainAvailability -DomainName $domain)) {
            [void]$unavailableDomains.Add($domain)
            continue
        }

        $DN = Get-DomainDN -DomainName $domain

        if ($DN) {
            # LDAP filter to find users with pre-authentication disabled
            $searchFilter = "(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(objectCategory=person))"
            $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$DN", $searchFilter, @("distinguishedName"))
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $results = $searcher.FindAll()

            if ($results.Count -gt 0) {
                $failedDomainCount++
                foreach ($result in $results) {
                    $thisOutput = [PSCustomObject]@{
                        DistinguishedName = $result.Properties["distinguishedName"][0]
                    }
                    [void]$outputObjects.Add($thisOutput)
                }
            }
        }
    }

    # Reporting results
    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            Score = 0
            Remediation = $self.Remediation
            Status = 'Failed'
            ResultObjects = $outputObjects
        }
        if ($outputObjects.Count -gt 0) {
            $res.ResultMessage += " ($($outputObjects.Count) objects found with pre-authentication disabled)."
        }
    } else {
        $res = [PSCustomObject]@{
            ResultMessage = "No users with pre-authentication disabled found."
            Remediation = "None"
            Score = 100
            Status = "Pass"
        }
    }

    # Handle unavailable domains
    if ($unavailableDomains.Count -gt 0) {
        $res.Status = 'Error'
        $res.Score = '0'
        $res.ResultMessage += " Failed to run because the following domains were unavailable: $($unavailableDomains -join ', ')"
    }
} catch {
    return [PSCustomObject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
        Remediation = "None"
    }
}

return $res
