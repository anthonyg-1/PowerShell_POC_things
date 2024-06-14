function Invoke-WebCrawl {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [Alias('iwc')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)][Alias('Uri', 'u', 'bu')][Uri]$BaseUri,
        [Parameter(Mandatory = $false, Position = 1)][Alias('d')][int]$Depth = 2,
        [Parameter(Mandatory = $false, Position = 2)][Alias('h')][System.Collections.Hashtable]$Headers,
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = "Include")][Alias('i', 'il')][String[]]$IncludeHosts,
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = "Exclude")][Alias('e', 'el')][String[]]$ExcludeHosts
    )
    BEGIN {
        if (($PSVersionTable.PSVersion.Major -lt 7) -and ($PSVersionTable.PSVersion.Minor -lt 4)) {
            $ArgumentException = [ArgumentException]::new("This function requires PowerShell version 7.4.0 or higher")
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        function Get-WebLinkStatus {
            param (
                [Parameter(Mandatory = $true)][Uri]$Uri,
                [Parameter(Mandatory = $false)][int]$Depth = 2,
                [Parameter(Mandatory = $false)][System.Collections.Hashtable]$Headers,
                [Parameter(Mandatory = $false)][String[]]$IncludeHosts,
                [Parameter(Mandatory = $false)][String[]]$ExcludeHosts,
                [hashtable]$Visited = @{}
            )

            PROCESS {
                $targetUri = $Uri.AbsoluteUri

                # Avoid visiting the same URL more than once:
                if ($Visited.ContainsKey($targetUri)) {
                    return
                }

                $Visited[$targetUri] = $true

                $iwrParams = @{Uri        = $Uri
                    Method                = "Get"
                    UseBasicParsing       = $true
                    SkipCertificateCheck  = $true
                    SkipHttpErrorCheck    = $true
                    ErrorAction           = "Stop"
                    AllowInsecureRedirect = $true
                }

                if ($PSBoundParameters.ContainsKey("Headers")) {
                    $iwrParams.Add("Headers", $Headers)
                }

                $parsedUri = [Uri]::new($targetUri)
                $targetHost = $parsedUri.Host

                [PSObject]$response = $null
                [int]$statusCode = 0
                [string]$statusDescription = ""
                try {
                    $response = Invoke-WebRequest @iwrParams
                    $statusCode = $response.StatusCode
                    $statusDescription = $response.StatusDescription
                }
                catch {
                    $statusCode = 520
                    $statusDescription = $_.Exception.Message
                }

                $webCrawlResult = ([PSCustomObject]@{
                        BaseUri           = $BaseUri.AbsoluteUri
                        Uri               = $targetUri
                        HostName          = $targetHost
                        StatusCode        = $statusCode
                        StatusDescription = $statusDescription
                    })

                Write-Output -InputObject $webCrawlResult

                # If the depth is 0, we stop here
                if ($Depth -le 0) {
                    return
                }

                # Extract links from the HTML content:
                $links = $response.Links | Where-Object { $_.href -match "^http" } | Select-Object -ExpandProperty href
                foreach ($link in $links) {
                    # Recursively visit each link

                    $parsedUri = [Uri]::new($link)
                    $targetHost = $parsedUri.Host

                    if ($PSBoundParameters.ContainsKey("IncludeHosts")) {
                        if ($targetHost -in $IncludeHosts) {
                            Get-WebLinkStatus -Uri $link -Depth ($Depth - 1) -Visited $Visited -Headers $Headers -IncludeHosts $IncludeHosts
                        }
                    }
                    elseif ($PSBoundParameters.ContainsKey("ExcludeHosts")) {
                        if ($targetHost -notin $ExcludeHosts) {
                            Get-WebLinkStatus -Uri $link -Depth ($Depth - 1) -Visited $Visited -Headers $Headers -ExcludeHosts $ExcludeHosts
                        }
                    }
                    else {
                        Get-WebLinkStatus -Uri $link -Depth ($Depth - 1) -Visited $Visited -Headers $Headers
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters.ContainsKey("IncludeHosts")) {
            Get-WebLinkStatus -Uri $BaseUri -Depth $Depth -Headers $Headers -IncludeHosts $IncludeHosts
        }
        elseif ($PSBoundParameters.ContainsKey("ExcludeHosts")) {
            Get-WebLinkStatus -Uri $BaseUri -Depth $Depth -Headers $Headers -ExcludeHosts $ExcludeHosts
        }
        else {
            Get-WebLinkStatus -Uri $BaseUri -Depth $Depth -Headers $Headers
        }
    }
}
