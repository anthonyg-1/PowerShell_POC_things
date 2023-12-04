function Get-CveInformation {
    [CmdletBinding(DefaultParameterSetName = 'CveID')]
    [Alias('gcvei', 'cvei')]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = "CveID")][ValidateLEngth(8, 24)][String]$CveID
    )
    BEGIN {
        # For NIST's API throttling:
        [int]$secondsToWait = 60
        [Uri]$baseUri = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
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

        [PSCustomObject]@{
            CveID                 = $cveId
            Published             = $published
            LastModified          = $lastModified
            Description           = $description
            BaseScore             = $cvssData.baseScore
            BaseSeverity          = (($null -ne $cvssData.baseSeverity) ? $cvssData.baseSeverity.ToLower() : $null)
            ExploitabilityScore   = $exploitabilityScore
            ImpactScore           = $impactScore
            AttackVector          = (($null -ne $cvssData.attackVector) ? $cvssData.attackVector.ToLower() : $null)
            AttackComplexity      = (($null -ne $cvssData.attackComplexity) ? $cvssData.attackComplexity.ToLower() : $null)
            PrivilegesRequired    = (($null -ne $cvssData.privilegesRequired) ? $cvssData.privilegesRequired.ToLower() : $null)
            UserInteraction       = (($null -ne $cvssData.userInteraction) ? $cvssData.userInteraction.ToLower() : $null)
            ConfidentialityImpact = (($null -ne $cvssData.confidentialityImpact) ? $cvssData.confidentialityImpact.ToLower() : $null)
            IntegrityImpact       = (($null -ne $cvssData.integrityImpact) ? $cvssData.integrityImpact.ToLower() : $null)
            AvailabilityImpact    = (($null -ne $cvssData.availabilityImpact) ? $cvssData.availabilityImpact.ToLower() : $null)
        }
    }
}
