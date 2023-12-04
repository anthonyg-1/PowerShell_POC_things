function Get-CveInformation {
    [CmdletBinding(DefaultParameterSetName = 'CveID')]
    [Alias('gcvei', 'cvei')]
    [OutputType([CveInformation])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = "CveID")][ValidateLength(8, 24)][String]$CveID
    )
    BEGIN {
        # For NIST's API throttling:
        [int]$secondsToWait = 60

        [Uri]$baseUri = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

        # Output class definition:
        class CveInformation {
            [string]$CveID
            [Nullable[DateTime]]$Published
            [Nullable[DateTime]]$LastModified
            [string]$Description
            [float]$BaseScore
            [string]$BaseSeverity
            [float]$ExploitabilityScore
            [float]$ImpactScore
            [string]$AttackVector
            [string]$AttackComplexity
            [string]$PrivilegesRequired
            [string]$UserInteraction
            [string]$ConfidentialityImpact
            [string]$IntegrityImpact
            [string]$AvailabilityImpact
        }
    }
    PROCESS {
        $targetUri = "{0}{1}" -f $baseUri, $cveId
        $response = Invoke-RestMethod -Method Get -Uri $targetUri

        Start-Sleep -Seconds $secondsToWait

        $cveData = $response.vulnerabilities.cve

        $published = $cveData.published
        $lastModified = $cveData.lastModified
        $description = $cveData.descriptions | Where-Object lang -eq "en" | Select-Object -ExpandProperty value

        $metrics = $cveData.metrics
        $exploitabilityScore = $metrics.cvssMetricV31.exploitabilityScore
        $cvssData = $metrics.cvssMetricV31.cvssData
        $impactScore = $metrics.cvssMetricV31.impactScore

        $cveInfo = [CveInformation]::new()
        $cveInfo.CveID = $cveId
        $cveInfo.Published = $published
        $cveInfo.LastModified = $lastModified
        $cveInfo.Description = $description
        $cveInfo.BaseScore = $cvssData.baseScore
        $cveInfo.BaseSeverity = (($null -ne $cvssData.baseSeverity) ? $cvssData.baseSeverity.ToLower() : $null)
        $cveInfo.ExploitabilityScore = $exploitabilityScore
        $cveInfo.ImpactScore = $impactScore
        $cveInfo.AttackVector = (($null -ne $cvssData.attackVector) ? $cvssData.attackVector.ToLower() : $null)
        $cveInfo.AttackComplexity = (($null -ne $cvssData.attackComplexity) ? $cvssData.attackComplexity.ToLower() : $null)
        $cveInfo.PrivilegesRequired = (($null -ne $cvssData.privilegesRequired) ? $cvssData.privilegesRequired.ToLower() : $null)
        $cveInfo.UserInteraction = (($null -ne $cvssData.userInteraction) ? $cvssData.userInteraction.ToLower() : $null)
        $cveInfo.ConfidentialityImpact = (($null -ne $cvssData.confidentialityImpact) ? $cvssData.confidentialityImpact.ToLower() : $null)
        $cveInfo.IntegrityImpact = (($null -ne $cvssData.integrityImpact) ? $cvssData.integrityImpact.ToLower() : $null)
        $cveInfo.AvailabilityImpact = (($null -ne $cvssData.availabilityImpact) ? $cvssData.availabilityImpact.ToLower() : $null)

        return $cveInfo
    }
}
