#requires -Version 7
#requires -Module PSTcpIp

$domainListFilePath = "domains.txt"
$outputFilePath = "KenticoDetection.csv"

function Test-Kentico {
    [CmdletBinding()]
    [Alias('tk')]
    [OutputType([bool], [KenticoAuditResult])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][Alias('u')][Uri]$Uri,

        [Parameter(Mandatory = $false, Position = 1)][Alias('d')][Switch]$Detailed
    )
    BEGIN {
        class KenticoAuditResult {
            [Uri]$BaseUri
            [bool]$KenticoDetected
            [bool]$SoapEndpointFound
            [Uri]$SoapEndpointUri
            [bool]$LogonPageFound
            [Uri]$LogonPageUri
            [bool]$HandlerFound
            [Uri]$HandlerUri
        }
    }
    PROCESS {
        [bool]$kenticoDetected = $false

        # SOAP endpoint test first:
        $soapUri = "{0}{1}" -f $Uri, "CMSPages/Staging/SyncServer.asmx?wsdl"
        [bool]$soapEndpointExists = $false
        try {
            $soapEndpointExists = ($null -ne (Invoke-WebRequest -Method Get -Uri $soapUri -ErrorAction Stop | Select-Object -ExpandProperty Content | Select-String -Pattern "SyncServer"))
        }
        catch {
            $soapEndpointExists = $false
        }

        # Logon page next:
        $logonUri = "{0}{1}" -f $Uri, "CMSPages/logon.aspx"
        [bool]$logonPageExists = $false
        try {
            $logonPageExists = ($null -ne (Invoke-WebRequest -Method Get -Uri $logonUri -ErrorAction Stop | Select-Object -ExpandProperty Content | Select-String -Pattern "Administration"))
        }
        catch {
            $logonPageExists = $false
        }

        # Handler next:
        $handlerUri = "{0}{1}" -f $Uri, "CMSModules/MediaLibrary/CMSPages/MultiFileUploader.ashx"
        [bool]$handlerExists = $false
        try {
            $handlerExists = ($null -ne (Invoke-WebRequest -Method Get -Uri $handlerUri -ErrorAction Stop | Select-Object -ExpandProperty Content | Select-String -Pattern "You cannot upload files with the '' extension"))
        }
        catch {
            $handlerExists = $false
        }

        $kenticoAuditResult = [KenticoAuditResult]::new()
        $kenticoAuditResult.BaseUri = $Uri
        $kenticoAuditResult.KenticoDetected = $kenticoDetected

        if ($kenticoDetected) {
            if ($soapEndpointExists) {
                $kenticoAuditResult.SoapEndpointFound = $true
                $kenticoAuditResult.SoapEndpointUri = $soapUri
            }

            if ($logonPageExists) {
                $kenticoAuditResult.LogonPageFound = $true
                $kenticoAuditResult.LogonPageUri = $logonUri
            }

            if ($handlerExists) {
                $kenticoAuditResult.HandlerFound = $true
                $kenticoAuditResult.HandlerUri = $handlerUri
            }
        }

        if ($PSBoundParameters.ContainsKey("Detailed")) {
            return $kenticoAuditResult
        }
        else {
            return $kenticoDetected
        }
    }
}


$domainList = Get-Content -Path $domainListFilePath

$discoveredTargets = $domainList | Invoke-DnsEnumeration | Test-TcpConnection -Port 80, 443 -WhereConnected

$kenticoScanResults = $discoveredTargets | ForEach-Object {

    [string]$baseUri = ""
    if ($_.Port -eq 443) {
        $baseUri = "https://{0}" -f $_.HostName
    }
    else {
        $baseUri = "http://{0}" -f $_.HostName
    }

    Test-Kentico -Uri $baseUri -Detailed
} | Where-Object KenticoDetected

Clear-Host

Write-Output -InputObject $kenticoScanResults
$kenticoScanResults | Export-Csv -Path $outputFilePath
