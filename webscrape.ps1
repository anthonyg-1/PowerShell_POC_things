#require -Version 7
#requires -Module PowerHTML
#requires -Module PSTcpIp

# Target URIs:
$uris = "https://mysite.com", "https://mysecondsite.com"

# Things to search for as regex:
$searchStrings = @("\w*PASSWORD*")

$validatedUris = @()
$uris | ForEach-Object {
    if ([Uri]::IsWellFormedUriString($_, 1)) {
        $uri = [Uri]::new($_)
        if (Test-TcpConnection -DNSHostName $uri.Authority -Port $uri.Port -Quiet) {
            $validatedUris += $uri
        }
    }
}

$results = @()
foreach ($rootUri in $validatedUris) {
    # Get and deserialize HTML response:
    $data = Invoke-WebRequest -Uri $rootUri
    $htmlObjects = $data.Content | ConvertFrom-Html

    # Find all JavaScript relative paths:
    $targetStrings = @()
    $htmlObjects.SelectNodes("//script") | ForEach-Object {
        $targetStrings += $_.OuterHtml | Select-String -Pattern "src="
    }

    # Construct JavaScript file absolute paths:
    $targetJsUris = @()
    $targetStrings | ForEach-Object {
        $textData = $_

        $targetUri = ""
        $textData -split "`n" | ForEach-Object {
            $childPath = ($_ -split '"')[1]
            $targetUri = "{0}{1}" -f $rootUri, $childPath
        }

        if ([Uri]::IsWellFormedUriString($targetUri, 1)) { $targetJsUris += $targetUri }
    }

    # Iterate through each file, search for bad strings, create object and add to results array:
    $targetJsUris | ForEach-Object {
        $targetUri = [Uri]::new($_)

        if (Test-TcpConnection -DNSHostName $targetUri.Authority -Port $targetUri.Port -Quiet) {
            $response = Invoke-RestMethod -Uri $targetUri
            if ($null -ne $response) {
                $searchStrings | ForEach-Object {
                    $result = Select-String -InputObject $response -Pattern $_ -AllMatches

                    if ($null -ne $result) {
                        $result.Matches | ForEach-Object {
                            $resultObject = [PSCustomObject]@{RootUri = $rootUri; FullPath = $targetUri; Found = $_.Value }

                            $searchResult = $results |
                            Where-Object -FilterScript { ($_.FullPath -eq $resultObject.FullPath) -and ($_.Found -eq $resultObject.Found) }

                            if ($null -eq $searchResult) {
                                $results += $resultObject
                            }
                        }
                    }
                }
            }
        }
    }
}

Clear-Host

Write-Output -InputObject $results
