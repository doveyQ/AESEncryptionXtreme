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

# Initialize results array
$outputObjects = @()
$failedDomainCount = 0

try {
    # GPLink rights GUIDs
    $guidHT = @{
        "f30e3bbe-9ff0-11d1-b603-0000f80367c1" = "gpLink"
        "00000000-0000-0000-0000-000000000000" = "All Properties"
    }

    $rightsFilter = "GenericWrite|WriteProperty|GenericAll|WriteDacl|WriteOwner"

    # forest-wide Allowed SIDs
    $allowedSIDs = @("S-1-5-18", "S-1-5-32-544")

    $forestDN = Get-ForestDN -ForestName $ForestName
    $searchDN = "CN=Sites,CN=Configuration,$forestDN"

    $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"", "(objectClass=site)", @("ntsecuritydescriptor"))
    $searcher.SearchRoot = [ADSI]"LDAP://$searchDN"
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $results = $searcher.FindAll()

    if ($results.Count -gt 0) {
        foreach ($domain in $DomainNames) {
            $domainSID = Get-DomainSID -DomainName $domain
            if ($domainSID) {
                $allowedSIDs += "$domainSID-512"
            }
        }

        foreach ($result in $results) {
            $site = $result.GetDirectoryEntry()
            $usersACL = @{}

            if ($site.ntsecuritydescriptor) {
                $bytes = $site.ntsecuritydescriptor
                $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $securityDescriptor.SetSecurityDescriptorBinaryForm($bytes)

                foreach ($access in $securityDescriptor.Access) {
                    if ($guidHT.ContainsKey($access.ObjectType.Guid)) {
                        try {
                            $identityAccount = New-Object System.Security.Principal.NTAccount($access.IdentityReference.Value)
                            $identitySID = $identityAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        }
                        catch {
                            $identitySID = $access.IdentityReference.Value
                        }

                        if (!($allowedSIDs.Contains($identitySID))) {
                            if ($access.AccessControlType -eq "Allow") {
                                if ($access.ActiveDirectoryRights.ToString() -match $rightsFilter) {
                                    if ($usersACL.ContainsKey($access.IdentityReference.Value)) {
                                        $usersACL[$access.IdentityReference.Value] += ";" + $access.AccessControlType.ToString() + ": " + $access.ActiveDirectoryRights.ToString() + " on: " + $guidHT[$access.ObjectType.Guid]
                                    }
                                    else {
                                        $usersACL[$access.IdentityReference.Value] = $access.AccessControlType.ToString() + ": " + $access.ActiveDirectoryRights.ToString() + " on: " + $guidHT[$access.ObjectType.Guid]
                                    }
                                }
                            }
                        }
                    }
                }
                if ($usersACL.Count -gt 0) {
                    $failedDomainCount++
                    foreach ($result in $usersACL.GetEnumerator()) {
                        $outputObjects += [pscustomobject]@{
                            DistinguishedName = $site.distinguishedName
                            Identity = $result.Key
                            Access = $result.Value
                        }
                    }
                }
            }
        }
    }

    if ($failedDomainCount -gt 0) {
        [pscustomobject]@{
            ResultMessage = "Found $($outputObjects.Count) objects with write permissions on the GPLink attribute at the AD Site level."
            Score = 0
            Remediation = "Unprivileged users should not be able to link GPOs at the AD Site level. Doing so essentially gives them the ability to escalate their access, change domain-level security posture, and use GPOs to affect all systems and users in AD."
            Status = "Failed"
            ResultObjects = $outputObjects
        }
    }
    else {
        [pscustomobject]@{
            ResultMessage = "No evidence of exposure"
            Remediation = "None"
            Score = 100
            Status = "Pass"
        }
    }
}
catch {
    [pscustomobject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
        Remediation = "None"
    }
}
