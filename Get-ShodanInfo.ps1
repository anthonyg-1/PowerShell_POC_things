
function Get-ShodanInfo {
    [CmdletBinding()]
    [Alias('nrich', 'shodan')]
    [OutputType([PSCustomObject])]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "HostName")][ValidateLength(1, 250)][Alias('ComputerName', 'Name', 'h')][String]$HostName
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
        [int]$secondsToWait = 60
    }
    PROCESS {
        Start-Sleep -Seconds $secondsToWait

        $tcpConnectionTestResults = Test-TcpConnection -DNSHostName $HostName -Port 80, 443 -ShowConnectedOnly

        $targetHostName = $HostName

        $targetIpAddress = $tcpConnectionTestResults | Select-Object -ExpandProperty IPAddress -First 1
        if ($targetIpAddress) {
            $targetUri = "{0}{1}" -f $baseUri, $targetIpAddress

            try {
                $response = Invoke-RestMethod -Method Get -Uri $targetUri -SkipCertificateCheck -ErrorAction Stop

                [PSCustomObject]@{
                    IPAddress       = $targetIpAddress
                    HostNames       = $response.hostnames
                    Ports           = $response.ports
                    CPEs            = $response.CPEs
                    Vulnerabilities = $response.vulns
                    TlsInformation  = (Get-TlsCertificate -HostName $targetHostName)
                }
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
    }
}
