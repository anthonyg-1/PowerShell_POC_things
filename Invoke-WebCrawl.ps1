function Invoke-WebCrawl {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [Alias('iwc')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)][Alias('u', 'bu')][Uri]$BaseUri,
        [Parameter(Mandatory = $false, Position = 1)][Alias('d')][int]$Depth = 2,
        [Parameter(Mandatory = $false, Position = 2)][Alias('h')][System.Collections.Hashtable]$Headers,
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = "Include")][Alias('i', 'il')][String[]]$IncludeList,
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = "Exclude")][Alias('e', 'el')][String[]]$ExcludeList
    )
    BEGIN {
        if (($PSVersionTable.PSVersion.Major -lt 7) -and ($PSVersionTable.PSVersion.Minor -lt 4)) {
            $ArgumentException = [ArgumentException]::new("This function requires PowerShell version 7.4.0 or higher")
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        function Get-WebLinkStatus {
            param (
                [Parameter(Mandatory = $true, Position = 0)][Uri]$Uri,
                [Parameter(Mandatory = $false, Position = 1)][int]$Depth = 2,
                [Parameter(Mandatory = $false, Position = 2)][System.Collections.Hashtable]$Headers,
                [Parameter(Mandatory = $false, Position = 3)][String[]]$IncludeList,
                [Parameter(Mandatory = $false, Position = 3)][String[]]$ExcludeList,
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

                # $reponse = $null
                try {
                    $response = Invoke-WebRequest @iwrParams
                }
                catch {
                    [PSCustomObject]@{
                        BaseUri           = $BaseUri.AbsoluteUri
                        Uri               = $targetUri
                        StatusCode        = 520
                        StatusDescription = $_.Exception.Message
                    }
                }


                [PSCustomObject]@{
                    BaseUri           = $BaseUri.AbsoluteUri
                    Uri               = $targetUri
                    StatusCode        = $response.StatusCode
                    StatusDescription = $response.StatusDescription
                }


                # If the depth is 0, we stop here
                if ($Depth -le 0) {
                    return
                }

                # Extract links from the HTML content
                $links = $response.Links | Where-Object { $_.href -match "^http" } | Select-Object -ExpandProperty href
                foreach ($link in $links) {
                    # Recursively visit each link

                    $parsedUri = [Uri]::new($link)
                    $targetHost = $parsedUri.Host

                    if ($PSBoundParameters.ContainsKey("IncludeList")) {
                        if ($targetHost -in $IncludeList) {
                            Get-WebLinkStatus -Uri $link -Depth ($Depth - 1) -Visited $Visited -Headers $Headers -IncludeList $IncludeList
                        }
                    }
                    elseif ($PSBoundParameters.ContainsKey("ExcludeList")) {
                        if ($targetHost -notin $ExcludeList) {
                            Get-WebLinkStatus -Uri $link -Depth ($Depth - 1) -Visited $Visited -Headers $Headers -ExcludeList $ExcludeList
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
        if ($PSBoundParameters.ContainsKey("IncludeList")) {
            Get-WebLinkStatus -Uri $BaseUri -Depth $Depth -Headers $Headers -IncludeList $IncludeList
        }
        elseif ($PSBoundParameters.ContainsKey("ExcludeList")) {
            Get-WebLinkStatus -Uri $BaseUri -Depth $Depth -Headers $Headers -ExcludeList $ExcludeList
        }
        else {
            Get-WebLinkStatus -Uri $BaseUri -Depth $Depth -Headers $Headers
        }
    }
}
