function Get-ShodanInformation {
    [CmdletBinding(DefaultParameterSetName = 'IPAddress')]
    [Alias('nrich', 'shodan', 'Get-ShodanInfo')]
    [OutputType([ShodanInfo])]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "IPAddress")][ValidateNotNullOrEmpty()][Alias('i', 'ip')][System.Net.IPAddress]$IPAddress,
        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'Name', 'h')][String]$HostName
    )
    BEGIN {
        $moduleDependency = "PSTcpIp"
        if ($null -eq (Get-Module -ListAvailable $moduleDependency)) {
            $argumentExceptionMessage = "The following module dependency was not found: $moduleDependency"
            $ArgumentException = New-Object -TypeName System.ArgumentException -ArgumentList $argumentExceptionMessage
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        [Uri]$baseUri = "https://internetdb.shodan.io"

        # For Shodan's API throttling:
        [int]$secondsToWait = 1

        # output class:
        class ShodanInfo {
            [string]$IPAddress
            [string[]]$HostNames
            [int[]]$Ports
            [string[]]$CPEs
            [bool]$HasVulnerabilities
            [string[]]$Vulnerabilities
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$TlsCertificate
        }

    }
    PROCESS {
        $shodanInfo = $null

        Start-Sleep -Seconds $secondsToWait

        [string]$targetHostName = ""
        [string]$targetIpAddress = ""
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$tlsCert = $null

        if ($PSBoundParameters.ContainsKey("IPAddress")) {
            $targetIpAddress = $IPAddress.ToString()

            $tlsCert = Get-TlsCertificate -HostName $targetIpAddress -ErrorVariable gtlsErr 2>$null

            $tlsCert = Get-TlsCertificate -HostName $targetIpAddress 2>$null
        }
        else {
            $tcpConnectionTestResults = Test-TcpConnection -DNSHostName $HostName -Port 80, 443 -ShowConnectedOnly
            $targetHostName = $HostName
            $targetIpAddress = $tcpConnectionTestResults | Select-Object -ExpandProperty IPAddress -First 1

            $tlsCert = Get-TlsCertificate -HostName $targetHostName 2>$null
        }

        $targetUri = "{0}{1}" -f $baseUri, $targetIpAddress

        if ($targetIpAddress) {
            try {
                $response = Invoke-RestMethod -Method Get -Uri $targetUri -SkipCertificateCheck -ErrorAction Stop

                $shodanInfo = [ShodanInfo]::new()
                $shodanInfo.IPAddress = $targetIpAddress
                $shodanInfo.HostNames = $response.hostnames
                $shodanInfo.Ports = $response.ports
                $shodanInfo.CPEs = $response.CPEs
                $shodanInfo.HasVulnerabilities = ($response.vulns -ge 1)
                $shodanInfo.Vulnerabilities = $response.vulns
                $shodanInfo.TlsCertificate = $tlsCert
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }
        }
        else {
            $webExceptionMessage = "Unable to connect to the following host: $targetHostName"
            $WebException = New-Object -TypeName System.Net.WebException -ArgumentList $webExceptionMessage
            Write-Error -Exception $WebException -Category ConnectionError -ErrorAction Continue
        }

        return $shodanInfo
    }
}
