
<#
.SYNOPSIS
Detects potential brute force attempts from Windows Security logs.

.DESCRIPTION
This script analyzes failed logon events (Event ID 4625) over a defined time window.
It extracts key information such as username, source IP address, timestamp, and failure reason.
The goal is to quickly identify suspicious authentication activity.

.PARAMETER Hours
Defines the time window (in hours) to search for failed logon events.

.EXAMPLE
.\Find-BruteForce.ps1 -Hours 10

.NOTES
Author: Mehdi Dakhama
Status: Work in progress
#>

# Time in hours
$hours = 10
$IPCache = @{}

# Convert to milliseconds
$ms = [int](New-TimeSpan -Hours $hours).TotalMilliseconds

# Error code mapping
$StatusMap = @{
    "0xc0000064" = "User does not exist"
    "0xc000006a" = "Wrong password"
    "0xc000006d" = "Bad username or password"
    "0xc000006e" = "Account restriction"
    "0xc000006f" = "Invalid logon hours"
    "0xc0000070" = "Invalid workstation"
    "0xc0000071" = "Password expired"
    "0xc0000072" = "Account disabled"
    "0xc0000193" = "Account expired"
    "0xc0000234" = "Account locked out"
}

# Resolve function
function Resolve-Status {
    param($Code)

    if ($StatusMap.ContainsKey($Code)) {
        return $StatusMap[$Code]
    }
    else {
        return $Code
    }
}

function Get-IPLocation {
    param($ip)

    # Check cache first
    if ($IPCache.ContainsKey($ip)) {
        return $IPCache[$ip]
    }

    try {
        $url = "http://ip-api.com/json/$ip"
        $response = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 3

        if ($response.status -eq "success") {
            $location = "$($response.country) - $($response.city)"
        }
        else {
            $location = "Unknown"
        }
    }
    catch {
        $location = "Error"
    }

    # Store in cache
    $IPCache[$ip] = $location

    return $location
}

# XPath filter
$xpath = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3']]"

# Retrieve events
$result = Get-WinEvent -FilterXPath $xpath -LogName Security | ForEach-Object {

    $Event = ([xml]$_.ToXml()).Event  

    # Convert EventData to hashtable
    $data = @{}
    $Event.EventData.Data | ForEach-Object {
        $data[$_.Name] = $_.'#text'
    }

    $obj = [PSCustomObject]$data

    # Final object
    [PSCustomObject]@{
        UserName    = $obj.TargetUserName
        IpAddress   = $obj.IpAddress
        Date        = [datetime]$Event.System.TimeCreated.SystemTime
        Reason      = Resolve-Status $obj.SubStatus
        SubStatus   = $obj.SubStatus
        Location  = Get-IPLocation $obj.IpAddress
        #ProcessName = $obj.LogonProcessName
        #Protocol    = $obj.AuthenticationPackageName
        #Status      = $obj.Status
    }
}

# Display
$result | Format-Table -AutoSize
