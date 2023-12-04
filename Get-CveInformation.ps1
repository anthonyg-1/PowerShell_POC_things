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
        [int]$secondsToWait = 30

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

        $impactScore = $metrics.cvssMetricV31.impactScore

        [PSCustomObject]@{
            CveID               = $cveId
            Published           = $published
            LastModified        = $lastModified
            Description         = $description
            ExploitabilityScore = $exploitabilityScore
            ImpactScore         = $impactScore
        }
    }
}
