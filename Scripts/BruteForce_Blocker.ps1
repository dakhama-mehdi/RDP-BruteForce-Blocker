

#region parameters

#region Parameters

# Time window (in minutes)
# Defines how far back to look for failed logon events
$Minutes = 30
$ms = [int](New-TimeSpan -Minutes $Minutes).TotalMilliseconds

# Cache used to store IP geolocation results (performance optimization)
$IPCache = @{}

# === Detection thresholds ===

# Number of failed attempts required to trigger a block (global threshold)
$threshold = 10

# Filter on specific failure reasons (leave empty to disable)
# Example: @("User does not exist")
$filterReason = @("User does not exist")
# Number of identical failure reasons required to trigger a block
# Only used if $filterReason is defined
$reasonThreshold = 7

# Filter by Country 
# List of trusted countries (will apply higher tolerance) Example: @("France")
$trustedCountries = @("France")
# Higher threshold for trusted countries (to reduce false positives)
$trustedThreshold = 10
# Lower threshold for foreign countries (more aggressive protection)
$thresetrange = 4

# === Trusted sources ===

# List of IP publics addresses that will never be blocked
$trustedIPs = @(
    "176.188.73.62",
    "8.8.8.8",
    "127.0.0.1",
    "::1"
)

# === Internal network detection ===

# Regex used to detect private/local IP ranges (not processed)
# Covers: 127.x.x.x, 10.x.x.x, 192.168.x.x, 172.16-31.x.x, IPv6 local 
# $privateIPRegex = '^(127\.(1[6-9]|2[0-9]|3[0-1]\.|::1)' # if you want to block also private IP
$isPrivateIP = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1)'

#endregion Parameters

#endregion parameters

#region Function 

$StatusMap = @{
    "0xc0000064" = "User does not exist"
    "0xc000006a" = "Wrong password"
    "0xc000006d" = "Bad username or password"
    "0xc0000072" = "Account disabled"
    "0xc0000234" = "Account locked out"
}

function Resolve-Status {
    param($Code)
    if ($StatusMap.ContainsKey($Code)) { $StatusMap[$Code] } else { $Code }
}

function Get-IPLocation {
    param($ip)

    # Skip local / empty
    if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -match "^(127\.|192\.168\.|10\.)") {
        return [PSCustomObject]@{
            Country = "Local"
            City    = "Local"
        }
    }

    # Cache check
    if ($IPCache.ContainsKey($ip)) {
        return $IPCache[$ip]
    }

    try {
        $url = "http://ip-api.com/json/$ip"
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 3

        if ($response.status -eq "success") {

            $location = [PSCustomObject]@{
                Country = $response.country
                City    = $response.city
            }
        }
        else {
            $location = [PSCustomObject]@{
                Country = "Unknown"
                City    = "Unknown"
            }
        }
    }
    catch {
        $location = [PSCustomObject]@{
            Country = "Error"
            City    = "Error"
        }
    }

    # Store in cache
    $IPCache[$ip] = $location

    return $location
}

#endregion Function

#region event

$xpath = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3']]"

# Get events
   $result = Get-WinEvent -FilterXPath $xpath -LogName Security | ForEach-Object {

    $Event = ([xml]$_.ToXml()).Event

    $data = @{}
    $Event.EventData.Data | ForEach-Object {
        $data[$_.Name] = $_.'#text'
    }

    $obj = [PSCustomObject]$data

    # Filter trusted IPs + invalid
    if ($obj.IpAddress -and
        $obj.IpAddress -ne '-' -and
        $obj.IpAddress -notmatch $isPrivateIP -and
        $obj.IpAddress -notin $trustedIPs) {

        $loc = Get-IPLocation $obj.IpAddress

        [PSCustomObject]@{
            UserName  = $obj.TargetUserName
            IpAddress = $obj.IpAddress
            Country  = $loc.Country
            City      = $loc.City
            Date      = [datetime]$Event.System.TimeCreated.SystemTime
            Reason    = Resolve-Status $obj.SubStatus
            SubStatus = $obj.SubStatus
        }
    }
}

   $ruleName = "Block-BruteForce-RDP"

    if (-not $result) {
    Write-Host "No events found, exiting..."
    return
    }

# Check if rule exists
$rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

if (-not $rule) {

    Write-Host "Creating firewall rule..."

    # Create rule with dummy IP (mandatory)
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress "1.2.3.4" `
        -Profile Any

    $currentIPs = @()
}
else {
    $currentIPs = ($rule | Get-NetFirewallAddressFilter).RemoteAddress
}

#endregion event

#region filtres

$history = $combined = $null
$history = Import-Csv "C:\temp\single_attempts.csv"

$combined = @($result + $history)

# Group by IP
$groups = $combined | Group-Object IpAddress 

# Grouping
$ipToBlock = foreach ($g in $groups) {

    $ip = $g.Name
    $events = $g.Group
    $total = $events.Count

    $block = $false

    # 1. Base condition (always active)
    if ($total -ge $threshold) {
        $block = $true
    }

    # 2. Reason filter (only if defined)
    if ($filterReason) {
        $reasonGroups = $events | Group-Object Reason

        foreach ($r in $reasonGroups) {
            if ($r.Name -in $filterReason -and $r.Count -ge $reasonThreshold) {
                $block = $true
            }
        }
    }

    # 3. Geo filter (only if defined)
    if ($trustedCountries) {

    $country = $events[0].Country

    if ($country -and $country -notin @("Unknown","Error")) {

        $isForeign = $country.Trim() -notin $trustedCountries

        if ($isForeign -and $total -ge $thresetrange) {
            $block = $true
        } 

        $isTrusted = $country.Trim() -in $trustedCountries

        # If trusted country → allow higher threshold
        if ($isTrusted -and $total -lt $trustedThreshold) {
            $block = $false
        }
    }
    }

    if ($block) {
        $ip
        $logLine += "Block prevent $ip - Reason: $($events[0].Reason) - $($events[0].Country)/$($events[0].City) - Count: $total - Date: $($events[0].Date)`r`n"
        Write-Host Block prevent $ip et $events[0].reason $events[0].Country $events[0].City et $total a $events[0].date -ForegroundColor Cyan 
    }

    if ($total -le $threshold) {
    $ipNotBlocked += $g.Group
    }

}

if ($ipNotBlocked) {
$ipNotBlocked | Export-Csv "C:\temp\single_attempts.csv" -NoTypeInformation -Encoding UTF8
$ipNotBlocked = $null
}
#endregion filtres

#region blockip

# Ensure arrays
$currentIPs = @($currentIPs)
$newIPs = @($ipToBlock)

# Merge + deduplicate
$allIPs = ($currentIPs + $newIPs) | Where-Object { $_ } | Sort-Object -Unique

# Remove dummy IP if present
$allIPs = $allIPs | Where-Object { $_ -ne "1.2.3.4" }

# Update firewall rule
Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $allIPs

# Logging
$date = Get-Date
$logLine | Out-File -Append C:\Temp\Log_RDP_block.txt
"[$date] Blocked IPs: $($newIPs -join ', ')" | Out-File -Append C:\Temp\Log_RDP_block.txt

Write-Host "Updated firewall with: $($newIPs -join ', ')"

#endregion blockip