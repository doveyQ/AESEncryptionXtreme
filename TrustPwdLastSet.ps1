[CmdletBinding()]
Param( 
    [Parameter(Mandatory=$True)]
    [String]$ForestName,

    [Parameter(Mandatory=$True)]
    [String[]]$DomainNames
)

# Helper function to get domain SID
function Get-DomainSID {
    param ([string]$DomainName)
    try {
        $domain = New-Object DirectoryServices.DirectorySearcher([ADSI]"").GetDirectoryEntry().Children.FindByProperty("name", $DomainName)
        $domainSID = $domain.SID
        return $domainSID
    } catch {
        Write-Error "Unable to get SID for domain $DomainName"
        return $null
    }
}

# Helper function to get forest DN
function Get-ForestDN {
    param ([string]$ForestName)
    try {
        $forest = New-Object DirectoryServices.ActiveDirectory.Forest($ForestName)
        return $forest.RootDomain.DistinguishedName
    } catch {
        Write-Error "Unable to get forest DN for $ForestName"
        return $null
    }
}

# Helper function to get domain objects
function Get-DomainObjects {
    param (
        [string]$SearchBase,
        [string[]]$Attributes
    )

    $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"", "(objectClass=trustedDomain)", $Attributes)
    $searcher.SearchRoot = [ADSI]"LDAP://$SearchBase"
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    return $searcher.FindAll()
}

# Initialize results array
$outputObjects = @()
$failedDomainCount = 0

try {
    # Threshold for filtering just the recent changes
    $daysToRemove = 365
    $temp = (Get-Date).AddDays(-$daysToRemove)
    $lastOriginatingChangeThreshold = $temp.ToString("yyyy-MM-ddTHH:mm:ssZ")

    # The attribute we search for
    $propertyFilter = "unicodepwd"

    $attributes = @("msds-replattributemetadata", $propertyFilter, "samaccountname", "pwdlastset")
    $minDwVersion = 0

    foreach ($domain in $DomainNames) {
        $domainFailCount = 0
        $DN = (Get-ForestDN -ForestName $ForestName) # Use forest DN to search
        if (-not $DN) {
            throw "Unable to get forest DN for $ForestName"
        }

        $searchBase = "CN=TrustedDomains,$DN"
        $results = Get-DomainObjects -SearchBase $searchBase -Attributes $attributes

        foreach ($result in $results) {
            try {
                $entry = $result.GetDirectoryEntry()
                foreach ($attr in $entry.Properties["msds-replattributemetadata"]) {
                    $attr = $attr -replace "`0$", "" # Remove NULL Byte
                    $attrMetaData = [xml]$attr | Select-Object -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction SilentlyContinue
                    if ($attrMetaData) {
                        if ($attrMetaData.pszAttributeName.ToLower() -match $propertyFilter.ToLower()) {
                            if ($attrMetaData.ftimeLastOriginatingChange -lt $lastOriginatingChangeThreshold -and $attrMetaData.dwVersion -gt $minDwVersion) {
                                $domainFailCount++
                                $lastChange = [datetime]::Parse($attrMetaData.ftimeLastOriginatingChange)
                                $daysSinceLastSet = ((Get-Date) - $lastChange).Days
                                if ($entry.Properties["pwdlastset"][0] -ne 0) {
                                    $passwordLastSet = [datetime]::FromFileTime($entry.Properties["pwdlastset"][0])
                                }
                                else {
                                    $passwordLastSet = "Never"
                                }
                                $thisOutput = [pscustomobject][ordered] @{
                                    DistinguishedName = $entry.Properties["distinguishedName"][0]
                                    SamAccountName = $entry.Properties["samaccountname"][0]
                                    PwdLastSet = $passwordLastSet
                                    AttributeLastChanged = $lastChange
                                    DaysSinceLastChange = $daysSinceLastSet
                                }
                                $outputObjects += $thisOutput
                                break
                            }
                        }
                    }
                }
            }
            catch {
                if ($entry.Properties["pwdlastset"][0] -lt $temp.ToFileTimeUtc()) {
                    $domainFailCount++
                    $lastChange = "Enumeration failed."
                    if ($entry.Properties["pwdlastset"][0] -ne 0) {
                        $passwordLastSet = [datetime]::FromFileTime($entry.Properties["pwdlastset"][0])
                        $daysSinceLastSet = ((Get-Date) - $passwordLastSet).Days
                    }
                    else {
                        $passwordLastSet = "Never"
                        $daysSinceLastSet = "Never"
                    }
                    $thisOutput = [pscustomobject][ordered] @{
                        DistinguishedName = $entry.Properties["distinguishedName"][0]
                        SamAccountName = $entry.Properties["samaccountname"][0]
                        PwdLastSet = $passwordLastSet
                        AttributeLastChanged = $lastChange
                        DaysSinceLastChange = $daysSinceLastSet
                    }
                    $outputObjects += $thisOutput
                }
            }
        }
        if ($domainFailCount) {
            $failedDomainCount++
        }
    }

    # Calculate the score
    if ($failedDomainCount -gt 0) {
        $res = [pscustomobject]@{
            ResultMessage = "Found $($outputObjects.Count) trusted domain objects whose password has not changed in the last $daysToRemove days."
            Score = 100 - (($failedDomainCount / $DomainNames.Count) * 100)
            Remediation = "Old passwords on trust accounts usually indicate that the trust is no longer valid. Verify that the trust account is no longer needed and then delete it."
            Status = "Failed"
            ResultObjects = $outputObjects
        }
    }
    else {
        $res = [pscustomobject]@{
            ResultMessage = "No evidence of exposure"
            Remediation = "None"
            Score = 100
            Status = "Pass"
        }
    }
}
catch {
    $res = [pscustomobject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
        Remediation = "None"
    }
}

return $res
