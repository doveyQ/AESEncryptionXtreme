[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ForestName,

    [Parameter(Mandatory=$true)]
    [string[]]$DomainNames
)

# Helper function to get domain DN
function Get-DomainDN {
    param ([string]$DomainName)
    try {
        $domain = New-Object DirectoryServices.DirectorySearcher([ADSI]"").GetDirectoryEntry().Children.FindByProperty("name", $DomainName)
        return $domain.DistinguishedName
    } catch {
        Write-Error "Unable to get DN for domain $DomainName"
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

# Helper function to perform Zerologon check
function Check-ZeroLogon {
    param (
        [string]$HostName,
        [string]$FQDN,
        [bool]$IsRODC
    )

    $checkResult = "NotVulnerable"
    try {
        $ClientChallenge = [byte[]](0..15 | ForEach-Object { 0x00 })
        $ServerChallenge = [byte[]](0..15 | ForEach-Object { 0x00 })
        $NegotiateFlags = [ulong]0x212fffff
        $ChannelType = if ($IsRODC) { 2 } else { 6 }

        for ($i = 0; $i -lt 2000; $i++) {
            if (Test-Connection -ComputerName $FQDN -Count 1 -Quiet) {
                $ChallengeStatus = [System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()
                if ($ChallengeStatus -eq 0) {
                    $AuthStatus = [System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()
                    if ($AuthStatus -eq 0) {
                        $checkResult = $FQDN
                        break
                    }
                }
            }
        }
    } catch {
        Write-Error "Error checking Zerologon vulnerability: $_"
    }
    return $checkResult
}

# Initialize results array
$outputObjects = @()
$failedDomainCount = 0

try {
    $forestDN = Get-ForestDN -ForestName $ForestName
    if (-not $forestDN) { throw "Unable to get forest DN" }

    $dcs = @()
    foreach ($domain in $DomainNames) {
        $domainDN = Get-DomainDN -DomainName $domain
        if ($domainDN) {
            # Get list of domain controllers
            $searchParams = @{
                baseDN = $domainDN
                filter = "(&(objectCategory=computer)(dnshostname=*)(|(primaryGroupID=516)(primaryGroupID=521)))"
                attributes = @("dnshostname", "primaryGroupID")
            }
            $dcs += Get-ADObject @searchParams
        } else {
            Write-Warning "Domain $domain is unavailable."
        }
    }

    foreach ($dc in $dcs) {
        $fqdn = $dc.dnshostname
        $hostname = $fqdn.Split(".")[0]
        $pgid = $dc.primaryGroupID
        $isRODC = ($pgid -eq "521")
        
        $result = Check-ZeroLogon -HostName $hostname -FQDN $fqdn -IsRODC $isRODC
        if ($result -ne "NotVulnerable") {
            $outputObjects += [pscustomobject]@{
                HostName = $result
            }
            $failedDomainCount++
        }
    }

    if ($failedDomainCount -gt 0) {
        [pscustomobject]@{
            ResultMessage = "Found $($outputObjects.Count) DCs that are vulnerable to ZeroLogon."
            Score = 0
            Remediation = "Patch your servers and make sure that all Microsoft security updates are applied."
            Status = "Failed"
            ResultObjects = $outputObjects
        }
    } else {
        [pscustomobject]@{
            ResultMessage = "No evidence of vulnerability."
            Remediation = "None"
            Score = 100
            Status = "Pass"
        }
    }
} catch {
    [pscustomobject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
        Remediation = "None"
    }
}
