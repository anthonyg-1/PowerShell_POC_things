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
        $moduleDependency = "PSTcpIp"
        if ($null -eq (Get-Module -Name $moduleDependency -ListAvailable)) {
            $argExcepMessage = "Unable to find the following module dependency: {0}" -f $moduleDependency
            $ArgumentException = New-Object -TypeName System.ArgumentException -ArgumentList $argExcepMessage
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        class KenticoAuditResult {
            [Uri]$BaseUri
            [bool]$NetworkAccessConfirmed
            [string]$IPAddress
            [string]$HostName
            [int]$Port
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

        $connectionTestResults = Test-TcpConnection -DNSHostName $Uri.Host -Port $Uri.Port
        [bool]$canConnect = $connectionTestResults.Connected

        $kenticoAuditResult = [KenticoAuditResult]::new()
        $kenticoAuditResult.BaseUri = $Uri.AbsoluteUri
        $kenticoAuditResult.HostName = $Uri.Host
        $kenticoAuditResult.Port = $Uri.Port

        # if target is not found our incaccessible, short circuit via return:
        if (-not($canConnect)) {
            if ($PSBoundParameters.ContainsKey("Detailed")) {
                return $kenticoAuditResult
            }
            else {
                return $kenticoDetected
            }
        }

        # Connection confirmed, proceed with enumeration:
        $kenticoAuditResult.NetworkAccessConfirmed = $true
        $kenticoAuditResult.IPAddress = $connectionTestResults.IPAddress

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

        if ($soapEndpointExists -or $logonPageExists -or $handlerExists) {
            $kenticoDetected = $true
        }

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
