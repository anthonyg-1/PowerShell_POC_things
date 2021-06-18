#requires -Version 7
#requires -Module PSTcpIp
#requires -Module PowerHTML

# Target URIs:
$uris = @("https://mysite.com")

# Bad strings we want to look for:
$searchStrings = @("SECRET", "PASSWORD")

$results = @()
foreach ($rootUri in $uris) {

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

        $targetJsUris += $targetUri
    }

    # Iterate through each file, search for bad strings, create object and add to results array:
    $targetJsUris | ForEach-Object {
        $targetUri = [Uri]::new($_)

        if (Test-TcpConnection -DNSHostName $targetUri.Authority -Port $targetUri.Port -Quiet) {
            $response = Invoke-RestMethod -Uri $targetUri
            if ($null -ne $response) {
                $searchStrings | ForEach-Object {
                    if ($response -match $_) {
                        $results += [PSCustomObject]@{Uri = $targetUri; Found = $_ }
                    }
                }
            }
        }
    }
}

Clear-Host

Write-Output -InputObject $results
