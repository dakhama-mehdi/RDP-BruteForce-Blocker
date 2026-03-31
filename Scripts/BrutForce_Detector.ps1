#change new update 

Add-Type -AssemblyName PresentationFramework

# ===== XAML =====
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Brute Force Detector"
        Height="500" Width="1100"
        WindowStartupLocation="CenterScreen"
        Background="#1E1E1E">

    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

       <StackPanel Orientation="Horizontal">

    <Button x:Name="btnScan" Content="Scan" Width="100" Margin="0,0,10,0"/>

    <Button x:Name="btnExportcsv" Content="Export CSV" Width="100" Margin="0,0,10,0"/>

    <TextBlock Text="Time Range:" VerticalAlignment="Center" Foreground="White" Margin="0,0,10,0"/>

    <ComboBox x:Name="cbHours" Width="80" SelectedIndex="3" Margin="5">
        <ComboBoxItem Content="1 hour"/>
        <ComboBoxItem Content="2 hours"/>
        <ComboBoxItem Content="4 hours"/>
        <ComboBoxItem Content="10 hours"/>
        <ComboBoxItem Content="24 hours"/>
        <ComboBoxItem Content="48 hours"/>
        <ComboBoxItem Content="30 days"/>
        <ComboBoxItem Content="40 days"/>
        <ComboBoxItem Content="60 days"/>
    </ComboBox>

    <!-- SEARCH -->
    <TextBox x:Name="txtSearch"
             Width="200"
             Height="25"
             VerticalAlignment="Center"
             ToolTip="Search..."/>

    <Button x:Name="btnExport" Content="Rapport HTML" Width="100" Margin="20,0,20,0"/>

    <TextBlock Text="Mode" VerticalAlignment="Center" Foreground="White" Margin="0,0,0,0"/>

    <ComboBox x:Name="cbMode" Width="120" SelectedIndex="0" Margin="5">
    <ComboBoxItem Content="Bruteforce (4625)" />
    <ComboBoxItem Content="Successful Logon (4624)" />
    </ComboBox>

    <TextBlock Text="Max Events" VerticalAlignment="Center" Foreground="White" Margin="10,0,0,0"/>

    <ComboBox Name="cbMaxEvents" Width="80" SelectedIndex="0" Margin="5">
    <ComboBoxItem Content="4000" />
    <ComboBoxItem Content="8000" />
    <ComboBoxItem Content="10000" />
    <ComboBoxItem Content="20000" />
    <ComboBoxItem Content="40000" />
    <ComboBoxItem Content="Unlimited" />
</ComboBox>

</StackPanel>

<TabControl Grid.Row="1" Margin="0,10,0,0">
  
    <!-- TAB 1 : EVENTS -->
    <TabItem>
    <TabItem.Header>
        <TextBlock Text="Event" Width="80" TextAlignment="Center"/>
    </TabItem.Header>
        <DataGrid x:Name="dgResults"
                  Margin="5"
                  AutoGenerateColumns="true"
                  ColumnWidth="*"
                  HorizontalScrollBarVisibility="Auto"
                  IsReadOnly="True">


        </DataGrid>
    </TabItem>

    <!-- TAB 2 : STATS -->
<!-- TAB 2 : STATS -->
<TabItem>
<TabItem.Header>
        <TextBlock Text="Statistic" Width="80" TextAlignment="Center"/>
    </TabItem.Header>
    <Grid Background="#1E1E1E" Margin="10">

        <Grid.RowDefinitions>
            <RowDefinition Height="0.9*"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- CARD 1 -->
        <Border Grid.Row="0" Grid.Column="0" Margin="5" Background="#007ACC" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Total Attempts" Foreground="White" FontSize="18"/>
                <TextBlock x:Name="lblTotal" Text="0" Foreground="White" FontSize="26" FontWeight="Bold"/>
            </StackPanel>
        </Border>

        <!-- CARD 2 -->
        <Border Grid.Row="0" Grid.Column="1" Margin="5" Background="#E74C3C" CornerRadius="8" Padding="6">
           <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">

        <TextBlock x:Name="lblUniqueIP" Text="Attacker IPs: 0" Foreground="White" FontSize="18"
                   FontWeight="Bold" HorizontalAlignment="Center"/>
        <TextBlock x:Name="lblBlockedIP" Text="Blocked: 0" Foreground="White" FontSize="18"
                   FontWeight="Bold" HorizontalAlignment="Center"/>
        </StackPanel>
        </Border>

         <!-- CARD 3 -->
        <Border Grid.Row="0" Grid.Column="2" Margin="5" Background="#1ABC9C" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top Reason"  FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopReason" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- CARD 4 -->
        <Border Grid.Row="1" Grid.Column="0" Margin="5" Background="#8E44AD" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top Country" FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopCountry" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- CARD 5 -->
        <Border Grid.Row="1" Grid.Column="1" Margin="5" Background="#34495E" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top IP" FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopIP" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- CARD 6 -->
        <Border Grid.Row="1" Grid.Column="2" Margin="5" Background="#E67E22" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top User" FontWeight="Bold" Foreground="White" FontSize="18"/>
                <StackPanel x:Name="spTopUser" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>



    </Grid>
</TabItem>
</TabControl>

       <TextBlock x:Name="lblSummary"
           Grid.Row="2"
           Text="Ready"
           Foreground="White"
           HorizontalAlignment="Left"/>

       <TextBlock Grid.Row="2"
           Text=" v1.0 | Dakhama Mehdi | ADCore"
           Foreground="White"
           FontSize="12"
           HorizontalAlignment="Right"
           Margin="0,0,10,0"/>

    </Grid>
</Window>
"@
# ===== LOAD XAML (FIX IMPORTANT) =====
$reader = New-Object System.IO.StringReader($xaml)
$xmlReader = [System.Xml.XmlReader]::Create($reader)
$Window = [Windows.Markup.XamlReader]::Load($xmlReader)

# ===== FIND CONTROLS =====
$btnScan   = $Window.FindName("btnScan")
$btnExport = $Window.FindName("btnExport")
$btnExportCSV = $Window.FindName("btnExportcsv")
$cbHours   = $Window.FindName("cbHours")
$cbMaxEvents   = $Window.FindName("cbMaxEvents")
$cbMode   = $Window.FindName("cbMode")
$dgResults = $Window.FindName("dgResults")
$lblSummary= $Window.FindName("lblSummary")
$txtSearch = $Window.FindName("txtSearch")
$lblTotal      = $Window.FindName("lblTotal")
$spTopIP       = $Window.FindName("spTopIP")
$spTopUser     = $Window.FindName("spTopUser")
$spTopCountry  = $Window.FindName("spTopCountry")
$spTopReason   = $Window.FindName("spTopReason")
$lblUniqueIP  = $Window.FindName("lblUniqueIP")
$lblBlockedIP = $Window.FindName("lblBlockedIP")

# ===== TEST DATA =====

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

$script:fullData = $null 

function Resolve-Status {
    param($value)

    $uint = [System.BitConverter]::ToUInt32(
        [System.BitConverter]::GetBytes([int32]$value), 0
    )

    $code = "0x{0:X8}" -f $uint

    if ($StatusMap.ContainsKey($code)) {
        [PSCustomObject]@{
            Code    = $code
            Message = $StatusMap[$code]
        }
    }
    else {
        [PSCustomObject]@{
            Code    = $code
            Message = "Unknown"
        }
    }
}

function Get-IPLocation {
    param($ip)

    if (-not $script:IPCache) {
        $script:IPCache = @{}
    }

    # Skip local / empty
    if (-not $ip -or $ip -eq '-' -or $ip -eq '::1' -or $ip -match "^(127\.|192\.168\.|10\.)") {
        return [PSCustomObject]@{
            Country = "Local"
            City    = "Local"
        }
    }

    # Cache check
    if ($script:IPCache.ContainsKey($ip)) {
        return $script:IPCache[$ip]
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

    $script:IPCache[$ip] = $location

    return $location
}

function Get-RDPData {
        param(
        [ValidateRange(1,1500)]
        $Hours = 10
        )

# Time in hours
#$hours = 10
$IPCache = @{}

# Convert to milliseconds
$ms = (New-TimeSpan -Hours $hours).TotalMilliseconds

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

    $loc = Get-IPLocation $obj.IpAddress

    # Final object
    [PSCustomObject]@{
        UserName    = $obj.TargetUserName
        IpAddress   = $obj.IpAddress
        Date        = [datetime]$Event.System.TimeCreated.SystemTime
        Reason      = Resolve-Status $obj.SubStatus
        SubStatus   = $obj.SubStatus
        Country     = $loc.Country
        City        = $loc.City
        ProcessName = $obj.LogonProcessName
        Protocol    = $obj.AuthenticationPackageName
        #Status      = $obj.Status
    }
}

return $result

}

function Get-RDPFailedEvents {
    param(
        [int]$Hours = 10,
        [int]$MaxEvents = 4000
    )

    $ms = (New-TimeSpan -Hours $hours).TotalMilliseconds

    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        "Security",
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        #"*[System[(EventID=4625)]] and *[EventData[Data[@Name='LogonType']='3']]"
        "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3']]"
    )

    $query.ReverseDirection = $true

    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

    #$limit = (Get-Date).AddHours(-$Hours)

    $count = 0

    $result =  while ($event = $reader.ReadEvent()) {

    #if ($event.TimeCreated -lt $limit) { break }

    $count++

    if ($count -ge $MaxEvents) { break }

    $props = $event.Properties

    $ip = $props[19].Value
    if (-not $ip -or $ip -eq "-") { continue }
    
    $loc = Get-IPLocation $ip.Trim()

    $status = Resolve-Status $props[9].Value

    [PSCustomObject]@{
        UserName    = $props[5].Value
        #Domainame      = $props[6].Value
        IpAddress   = $ip
        Date        = [datetime]$event.TimeCreated
        Reason      = $status.Message
        SubStatus   = $status.Code
        Country     = $loc.Country
        City        = $loc.City
        ProcessName = $props[11].Value
        Protocol    = $props[12].Value
        #Status     = $obj.Status
    }   
}

    return $result
}

function Get-RDPSuccessEvents {
    param(
        [int]$Hours = 24,
        [int]$MaxEvents = 4000
    )

    $ms = (New-TimeSpan -Hours $Hours).TotalMilliseconds

    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
        "Security",
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='3']] or *[EventData[Data[@Name='LogonType']='10']]"
    )

    $query.ReverseDirection = $true

    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

    $count = 0

    $result = while ($event = $reader.ReadEvent()) {

        $count++
        if ($MaxEvents -gt 0 -and $count -ge $MaxEvents) { break }

        $props = $event.Properties
        if ($props.Count -lt 19) { continue }

        $ip = $props[18].Value
        if (-not $ip -or $ip -eq "-") { continue }

        $loc = Get-IPLocation $ip.Trim()
        

        [PSCustomObject]@{
            UserName    = $props[5].Value
            IpAddress   = $ip
            Date        = [datetime]$event.TimeCreated
            Country     = $loc.Country
            City        = $loc.City
            Reason      = $props[11].Value # Computer name call
            Type        = $props[8].Value
            Protocol    = $props[14].Value # Protocol
            ProcessName = ($props[17].Value -split "\\")[-1]
            Domain      = $props[6].Value
        }
    }

    return $result
}

function Update-Stats {

    param(
        [Parameter(Mandatory)]
        $Data
    )

    # TOTAL
    $lblTotal.Text = $Data.Count

    # UNIQUE IP
    $uniqueIPs = $Data.IpAddress | Where-Object { $_ } | Sort-Object -Unique
    $lblUniqueIP.Text = "Attacker IPs: $($uniqueIPs.Count)"

    # RESET UI
    $spTopIP.Children.Clear()
    $spTopUser.Children.Clear()
    $spTopCountry.Children.Clear()
    $spTopReason.Children.Clear()

    # TOP IP
    $Data |
        Group-Object IpAddress |
        Sort-Object Count -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "White"
            #$txt.HorizontalAlignment = "Center"
            $spTopIP.Children.Add($txt)
        }

    # TOP USER
    $Data |
        Group-Object Username |
        Sort-Object Count -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "White"
            #$txt.HorizontalAlignment = "Center"
            $spTopUser.Children.Add($txt)
        }

    # TOP COUNTRY
    $Data |
        Group-Object Country |
        Sort-Object Count -Descending |
        Select-Object -First 5 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "White"
            $txt.HorizontalAlignment = "Center"
            $spTopCountry.Children.Add($txt)
        }

    # TOP REASON
    $Data |
        Group-Object Reason |
        Sort-Object Count -Descending |
        Select-Object -First 3 |
        ForEach-Object {
            $txt = New-Object System.Windows.Controls.TextBlock
            $txt.Text = "$($_.Name) ($($_.Count))"
            $txt.Foreground = "white"
            $txt.HorizontalAlignment = "Center"
            $spTopReason.Children.Add($txt)
        }

    # FIREWALL CHECK
    $fwRules = Get-NetFirewallRule -DisplayName "*Block-BruteForce-RDP*" -ErrorAction SilentlyContinue | Get-NetFirewallAddressFilter

    if ($fwRules) {

    $blockedIPs = $fwRules.RemoteAddress | Where-Object { $_ -and $_ -ne "Any" } | Sort-Object -Unique

    $blockedDetectedIPs = $uniqueIPs | Where-Object { $_ -in $blockedIPs }

    $lblBlockedIP.Text = "Blocked: $($blockedDetectedIPs.Count)"
    } else { $lblBlockedIP.Text = "Blocked: 0)" }
}

function Resize-Gridview {

    foreach ($col in $dgResults.Columns) {
    if ($col.SortMemberPath -eq "Date") {
        $col.Width = 150
    } 
    if ($col.SortMemberPath -eq "Type") {
        $col.Width = 60
    } 
    }
}

$txtSearch.Add_TextChanged({

    if (-not $script:fullData) { return }

    $search = $txtSearch.Text.ToLower()

    if (-not $search) {
        $dgResults.ItemsSource = @($script:fullData)
        Resize-Gridview
        return
    }

    $pattern = [regex]::Escape($search)

    $filtered = $script:fullData | Where-Object {
    "$($_.UserName) $($_.IpAddress) $($_.Country) $($_.City) $($_.Reason) $($_.ProcessName) $($_.Protocol)" -match $pattern
    }
    
    $dgResults.ItemsSource = @($filtered)

    Resize-Gridview         
})

# ===== EVENTS =====
$btnScan.Add_Click({
    
    $startTime = Get-Date
    $dgResults.ItemsSource = $null
    $lblSummary.Text = "Scan in progress..."

    [System.Windows.Forms.Application]::DoEvents()

    $selected = $cbHours.SelectedItem.Content.ToString()
    $value = [int]($selected -replace "[^0-9]")

    if ($selected -like "*day*") {
        $hours = $value * 24
    } 
    else {
        $hours = $value
    }

    $selectedEvent = $cbMaxEvents.SelectedItem.Content

    if ($selectedEvent -eq "Unlimited") {
    $MaxEvents = 100000
    }
    else {
    $MaxEvents = [int]$selectedEvent
    }

    $mode = $cbMode.SelectedItem.Content

    switch ($mode) {

    "Bruteforce (4625)" {
        $data = Get-RDPFailedEvents -Hours $Hours -MaxEvents $MaxEvents
    }

    "Successful Logon (4624)" {
        $data = Get-RDPSuccessEvents -Hours $Hours -MaxEvents $MaxEvents
    }
    }

    if ($data) {
    $script:fullData = $data
    $dgResults.ItemsSource = @($script:fullData)
    
    Resize-Gridview       

    Update-Stats -Data $data

    } 
    else { 
    $script:fullData = $null }

    $elapsed = (Get-Date) - $startTime
    $elapsedText = "{0:mm\:ss}" -f $elapsed
    $lblSummary.Text = "Scan done - $($data.Count) events ($hours h) - Time: $elapsedText s"

})

$btnExportcsv.Add_Click({

if ($script:fullData) {
Add-Type -AssemblyName System.Windows.Forms

$dialog = New-Object System.Windows.Forms.SaveFileDialog
$dialog.Filter = "CSV files (*.csv)|*.csv"
$dialog.FileName = "Brutforcelogs_$(Get-Date -Format 'MMdd_HHmmss').csv"

if ($dialog.ShowDialog() -eq "OK") {
    $script:fullData | Export-Csv $dialog.FileName -NoTypeInformation -Encoding UTF8
    $lblSummary.Text = "Export done: $($dialog.FileName)"
}
}

})

$btnExport.Add_Click({

    #[System.Windows.MessageBox]::Show("Export HTML à venir")
   
    # 1. Récup IP uniques (limité pour test)
    $uniqueIPs = $script:fullData.IpAddress |
    Where-Object { $_ } |
    Sort-Object -Unique |
    Select-Object -First 10

    # 2. Résolution GeoIP
    $geoPoints = foreach ($ip in $uniqueIPs) {

    try {
        $res = Invoke-RestMethod "http://ip-api.com/json/$ip" -ErrorAction Stop

        if ($res.status -eq "success") {
            [PSCustomObject]@{
                IP   = $ip
                Lat  = $res.lat
                Lon  = $res.lon
                City = $res.city
                Country = $res.country
            }
        }
    }
    catch {
        Write-Host "Erreur IP: $ip"
    }
}

    # 3. Génération JS des points
    $markers = ""

    foreach ($g in $geoPoints) {

    $markers += @"
L.circle([$($g.Lat), $($g.Lon)], {color:'red', radius:50000}).addTo(map)
.bindPopup("$($g.City), $($g.Country)<br>$($g.IP)");
"@
}
    
    $tableRows = ""

    foreach ($row in $script:fulldata) {
    $tableRows += "<tr>
        <td>$($row.Date)</td>
        <td>$($row.UserName)</td>
        <td>$($row.IpAddress)</td>
        <td>$($row.Country)</td>
        <td>$($row.City)</td>
        <td>$($row.Reason)</td>
        <td>$($row.Protocol)</td>
    </tr>"
    }

    # 4. HTML final

# ===== DATA GRAPH =====
# ===== DATA (par jour) =====
$daily = $script:fulldata |
    Group-Object { (Get-Date $_.Date).ToString("dd/MM") } |
    Sort-Object Name


$total = $script:fulldata.Count

$uniqueIP = ($script:fulldata.IpAddress | Select-Object -Unique).Count

$topIP = ($script:fulldata |
    Group-Object IpAddress |
    Sort-Object Count -Descending |
    Select-Object -First 3 |
    ForEach-Object { "$($_.Name) ($($_.Count))" }) -join "<br>"

$topUser = ($script:fulldata |
    Group-Object UserName |
    Sort-Object Count -Descending |
    Select-Object -First 3 |
    ForEach-Object { "$($_.Name) ($($_.Count))" }) -join "<br>"

$topCountry = ($script:fulldata |
    Group-Object Country |
    Sort-Object Count -Descending |
    Select-Object -First 3 |
    ForEach-Object { "$($_.Name) ($($_.Count))" }) -join "<br>"

$topReason = ($script:fulldata |
    Group-Object Reason |
    Sort-Object Count -Descending |
    Select-Object -First 3 |
    ForEach-Object { "$($_.Name) ($($_.Count))" }) -join "<br>"

    $server = $env:COMPUTERNAME
    $date = Get-Date -Format "dd/MM/yyyy HH:mm"

    $titleDash = "Brut Force : Dashboard"
    $mode = $cbMode.SelectedItem.Content

    if ($Mode -like "*4624*") {
    $titleDash = "Successfull Network Login : Dashboard" } 


$dailyRows = ""
foreach ($d in $daily) {
    $dailyRows += "<tr>
        <td>$($d.Name)</td>
        <td>$($d.Count)</td>
    </tr>"
}

# ===== HTML =====
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title>Brut-Force-Detected Dashboard</title>

<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<style>
body {
    font-family: Segoe UI;
    margin: 40px 20px 20px 20px;
    background: #1E1E1E;
    color: white;
}

/* HEADER */
.header {
    display:flex;
    justify-content:space-between;
    border-bottom:1px solid #444;
    padding-bottom:8px;
    margin-bottom:30px;
}

/* CARDS */
.cards {
    display:flex;
    gap:15px;
    margin-top:20px;  
    margin-bottom:20px;
}

.card {
    flex:1;
    background:#2b2b2b;
    padding:25px;
    border-radius:10px;
    text-align:center;
}

.cards .card:first-child {
    flex:0.6;
    font-weight:700;
}

.card b {
    font-size:14px;
    line-height:1.4;
}

/* SECTION */
.section {
    display:flex;
    gap:20px;
    height:450px;
}

/* TABLE LEFT */
.table-box {
    width:60%;
    height:100%;
    overflow:auto;
}

.table-header {
    position: sticky;
    top: 0;
    background: #1E1E1E;
    z-index: 20;
    padding-bottom: 10px;

    display: flex;
    justify-content: space-between;
    align-items: center;
}

.table-header input:focus {
    outline: none;
    box-shadow: none;
}

/* RIGHT PANEL */
.right-box {
    width:40%;
    display:flex;
    flex-direction:column;
    gap:10px;
}

/* DAILY TABLE */
.daily-box {
    background:#2b2b2b;
    padding:10px;
    border-radius:10px;
    max-height:120px;   
    overflow:auto;      
}

/* MAP */
.map-box {
    flex:1;
}

#map {
    height:100%;
    width:100%;
    border-radius:10px;
    border:2px solid #333;
}

/* TABLE STYLE */
table {
    width:100%;
    border-collapse:collapse;
    font-size:12px;
    background:#2b2b2b;
}

th, td {
    padding:6px;
    border:1px solid #444;
    text-align:left;
}

th { background:#333; }
tr:hover { background:#2a2a2a; }
</style>

</head>
<body>

<!-- HEADER -->
<div class="header">
    <div>
        <h2 style="margin:0;">$titleDash</h2>
    </div>
    <div style="font-size:12px;color:white;">
      $server : $date
            
    </div>
</div>

<!-- CARDS -->
<div class="cards">
<div class="card">Total Attemps<br><b>$total</b></div>
<div class="card">Top IP<br><b>$topIP</b></div>
<div class="card">Top Username<br><b>$topUser</b></div>
<div class="card">Top Country<br><b>$topCountry</b></div>
<div class="card">Top Reason<br><b>$topReason</b></div>
</div>

<!-- SECTION -->
<div class="section">

    <!-- TABLE LEFT -->
<div class="table-box">

    <div class="table-header">
    <h3 style="margin:0;">Events</h3>   
     <input type="text" id="searchMain" onkeyup="filterTable('searchMain','tableMain')" placeholder="Search..."
           style="padding:6px 10px; border:1px solid #444; border-radius:6px; background:#1E1E1E; color:white;">
</div>

<table id="tableMain">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>User</th>
                    <th>IP</th>
                    <th>Country</th>
                    <th>City</th>
                    <th>Reason</th>
                    <th>Protocol</th>
                </tr>
            </thead>
            <tbody>
                $tableRows
            </tbody>
        </table>
    </div>

    <!-- RIGHT PANEL -->
    <div class="right-box">

        <!-- DAILY STATS -->
        <div class="daily-box">
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Attempts</th>
                    </tr>
                </thead>
                <tbody>
                    $dailyRows
                </tbody>
            </table>
        </div>

        <!-- MAP -->
        <div class="map-box">
            <div id="map"></div>
        </div>

    </div>

</div>

<script>

// MAP
var map = L.map('map', {
    minZoom: 2,
    maxZoom: 6
}).setView([40, 60], 2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    noWrap: true
}).addTo(map);

$markers

function filterTable(inputId, tableId) {
    var input = document.getElementById(inputId);
    var filter = input.value.toUpperCase();
    var table = document.getElementById(tableId);
    var tr = table.getElementsByTagName("tr");

    for (var i = 1; i < tr.length; i++) {
        var row = tr[i];
        var text = row.textContent || row.innerText;
        row.style.display = text.toUpperCase().indexOf(filter) > -1 ? "" : "none";
    }
}

</script>

<hr style="margin-top:30px; border-top:1px solid #444;" />

<div style="font-size:12px; color:#888; text-align:center; padding-top:10px;">
    Developed by <strong>Dakhama Mehdi</strong> – ADSafe.fr <br>
    Powered by community knowledge <a href="https://www.it-connect.fr" target="_blank" style="color:#4FC3F7;">IT-Connect</a><br>
    © 2026
</div>
</body>
</html>
"@

    # 5. Export + ouverture
    $path = "$env:TEMP\attack_map.html"
    $html | Out-File -Encoding utf8 $path
    Start-Process $path
})


# ===== SHOW =====
$Window.ShowDialog() | Out-Null