#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Exports DNS Client Event ID 3020 query results, aggregated by name, to a JSON file
    and clears the DNS Client Operational log.

.DESCRIPTION
    Reads all Event ID 3020 entries from the "Microsoft-Windows-DNS-Client/Operational" log,
    extracts the resolved name and response addresses, deduplicates responses, aggregates
    by name, writes the results to a timestamped JSON file, then clears the log.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-DNS-Client/Operational'

# Collect events
try {
    $events = Get-WinEvent -LogName $logName -FilterXPath "*[System[EventID=3020]]" -ErrorAction Stop
} catch [Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Warning "No Event ID 3020 entries found in $logName. Nothing to export."
        exit 0
    }
    throw
}

# Parse and aggregate by query name
$aggregated = @{}

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e', $xml.DocumentElement.NamespaceURI)

    $eventData = $xml.SelectNodes('//e:EventData/e:Data', $ns)

    $name = $null
    $results = $null

    foreach ($node in $eventData) {
        switch ($node.GetAttribute('Name')) {
            'QueryName'    { $name    = $node.'#text' }
            'QueryResults' { $results = $node.'#text' }
        }
    }

    if (-not $name) { continue }

    if (-not $aggregated.ContainsKey($name)) {
        $aggregated[$name] = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
    }

    if ($results) {
        # QueryResults is semicolon-delimited; each token may have trailing whitespace
        # and may include type prefixes like "type: 1 " before the address.
        foreach ($token in $results.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)) {
            $value = $token.Trim()
            if ($value -and $value -ne '') {
                [void]$aggregated[$name].Add($value)
            }
        }
    }
}

# Build output array
$output = foreach ($kvp in $aggregated.GetEnumerator() | Sort-Object Name) {
    [PSCustomObject]@{
        name      = $kvp.Key
        responses = @($kvp.Value | Sort-Object)
    }
}

# Write JSON with RFC 3339 timestamp in filename
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH-mm-ssZ')
$outFile = Join-Path $OutputDirectory "dns-client-3020_$timestamp.json"

$output | ConvertTo-Json -Depth 4 | Set-Content -Path $outFile -Encoding UTF8

Write-Host "Exported $($aggregated.Count) names to $outFile"

# Clear the log
wevtutil cl $logName
Write-Host "Cleared $logName"
