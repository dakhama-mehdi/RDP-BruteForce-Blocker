
Add-Type -AssemblyName PresentationFramework

# ===== XAML =====
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="RD-AD | Brute Force Detection"
        Height="500" Width="1000"
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

    <Button x:Name="btnExport" Content="Export HTML" Width="120" Margin="0,0,20,0"/>

    <TextBlock Text="Time Range:" VerticalAlignment="Center" Foreground="White" Margin="0,0,10,0"/>

    <ComboBox x:Name="cbHours" Width="120" SelectedIndex="3" Margin="0,0,20,0">
        <ComboBoxItem Content="1 hour"/>
        <ComboBoxItem Content="2 hours"/>
        <ComboBoxItem Content="4 hours"/>
        <ComboBoxItem Content="10 hours"/>
        <ComboBoxItem Content="24 hours"/>
        <ComboBoxItem Content="48 hours"/>
        <ComboBoxItem Content="4 days"/>
        <ComboBoxItem Content="7 days"/>
        <ComboBoxItem Content="15 days"/>
    </ComboBox>

    <!-- 🔍 SEARCH -->
    <TextBox x:Name="txtSearch"
             Width="200"
             Height="25"
             VerticalAlignment="Center"
             ToolTip="Search..."/>

</StackPanel>
<TabControl Grid.Row="1">

    <!-- TAB 1 : EVENTS -->
    <TabItem Header="Events">
        <DataGrid x:Name="dgResults"
                  Margin="5"
                  AutoGenerateColumns="False"
                  IsReadOnly="True">
                  
            <DataGrid.Columns>
                <DataGridTextColumn Header="Username" Binding="{Binding Username}" Width="*"/>
                <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="100"/>
                <DataGridTextColumn Header="Date" Binding="{Binding Date}" Width="*"/>
                <DataGridTextColumn Header="Reason" Binding="{Binding Reason}" Width="120"/>
                <DataGridTextColumn Header="SubStatus" Binding="{Binding SubStatus}" Width="80"/>
                <DataGridTextColumn Header="Country" Binding="{Binding Country}" Width="80"/>
                <DataGridTextColumn Header="City" Binding="{Binding City}" Width="*"/>
                <DataGridTextColumn Header="Process" Binding="{Binding ProcessName}" Width="80"/>
                <DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="80"/>
            </DataGrid.Columns>

        </DataGrid>
    </TabItem>

    <!-- TAB 2 : STATS -->
<TabItem Header="Statistics">
    <Grid Background="#1E1E1E" Margin="10">

        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- CARD 1 -->
        <Border Grid.Row="0" Grid.Column="0" Margin="5" Background="#007ACC" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Total Events" Foreground="White" FontSize="14" HorizontalAlignment="Center"/>
                <TextBlock x:Name="lblTotal" Text="0" Foreground="White" FontSize="24" FontWeight="Bold" HorizontalAlignment="Center"/>
            </StackPanel>
        </Border>

        <!-- CARD 2 -->
        <Border Grid.Row="0" Grid.Column="1" Margin="5" Background="#C0392B" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top IP" Foreground="White" FontSize="14" HorizontalAlignment="Center"/>
                <TextBlock x:Name="lblTopIP"
                           Text="-"
                           Foreground="White"
                           FontSize="13"
                           FontWeight="Bold"
                           TextAlignment="Center"
                           TextWrapping="Wrap"/>
            </StackPanel>
        </Border>

        <!-- CARD 3 -->
        <Border Grid.Row="1" Grid.Column="0" Margin="5" Background="#27AE60" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top Country" Foreground="White" FontSize="14" HorizontalAlignment="Center"/>
                <TextBlock x:Name="lblTopCountry"
                           Text="-"
                           Foreground="White"
                           FontSize="13"
                           FontWeight="Bold"
                           TextAlignment="Center"
                           TextWrapping="Wrap"/>
            </StackPanel>
        </Border>

        <!-- CARD 4 -->
        <Border Grid.Row="1" Grid.Column="1" Margin="5" Background="#8E44AD" CornerRadius="8">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="Top User" Foreground="White" FontSize="14" HorizontalAlignment="Center"/>
                <TextBlock x:Name="lblTopUser"
                           Text="-"
                           Foreground="White"
                           FontSize="13"
                           FontWeight="Bold"
                           TextAlignment="Center"
                           TextWrapping="Wrap"/>
            </StackPanel>
        </Border>

    </Grid>
</TabItem>
</TabControl>

        <TextBlock x:Name="lblSummary"
                   Grid.Row="2"
                   Text="Ready"
                   Foreground="White"/>

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
$cbHours   = $Window.FindName("cbHours")
$dgResults = $Window.FindName("dgResults")
$lblSummary= $Window.FindName("lblSummary")
$txtSearch = $Window.FindName("txtSearch")
$lblTotal      = $Window.FindName("lblTotal")
$lblTopIP      = $Window.FindName("lblTopIP")
$lblTopCountry = $Window.FindName("lblTopCountry")
$lblTopUser    = $Window.FindName("lblTopUser")

# ===== TEST DATA =====
function Get-DummyData {
    @(
        [pscustomobject]@{IPAddress="192.168.1.10"; Attempts=25; Country="FR"; TopReason="Wrong password"; RiskScore=80; Status="Blocked"}
        [pscustomobject]@{IPAddress="10.0.0.5"; Attempts=5; Country="US"; TopReason="User not found"; RiskScore=40; Status="Suspicious"}
        [pscustomobject]@{IPAddress="172.16.0.2"; Attempts=2; Country="FR"; TopReason="Bad password"; RiskScore=10; Status="Allowed"}
    )
}

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

function Get-RDPData {
        param(
        [ValidateRange(1,360)]
        [int]$Hours = 10
        )

# Time in hours
#$hours = 10
$IPCache = @{}

# Convert to milliseconds
$ms = [int](New-TimeSpan -Hours $hours).TotalMilliseconds

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
        Country  = $loc.Country
        City      = $loc.City
        ProcessName = $obj.LogonProcessName
        Protocol    = $obj.AuthenticationPackageName
        #Status      = $obj.Status
    }
}

return $result

}

$txtSearch.Add_TextChanged({

    if (-not $script:fullData) { return }

    $search = $txtSearch.Text.ToLower()

    if (-not $search) {
        $dgResults.ItemsSource = $script:fullData
        return
    }

    $filtered = $script:fullData | Where-Object {

        ($_.UserName -and $_.UserName.ToLower().Contains($search)) -or
        ($_.IpAddress -and $_.IpAddress.ToLower().Contains($search)) -or
        ($_.Country -and $_.Country.ToLower().Contains($search)) -or
        ($_.City -and $_.City.ToLower().Contains($search)) -or
        ($_.Reason -and $_.Reason.ToLower().Contains($search)) -or
        ($_.ProcessName -and $_.ProcessName.ToLower().Contains($search)) -or
        ($_.Protocol -and $_.Protocol.ToLower().Contains($search))
    }

    $dgResults.ItemsSource = $filtered
})

# ===== EVENTS =====
$btnScan.Add_Click({

    $dgResults.ItemsSource = $null
    $lblSummary.Text = "Scan in progress..."

    [System.Windows.Forms.Application]::DoEvents()

    $selected = $cbHours.SelectedItem.Content.ToString()
    $value = [int]($selected -replace "[^0-9]")

    if ($selected -like "*day*") {
        $hours = $value * 24
    } else {
        $hours = $value
    }

    $data = Get-RDPData -Hours $hours

    # ===== RESULT =====
    $script:fullData = $data
    $dgResults.ItemsSource = $script:fullData

    $lblSummary.Text = "Scan done - $($data.Count) events ($hours h)"

   $lblTotal.Text      = "Total events: 1245"
   $lblTopCountry.Text = "Top Country: Norway"
   $lblTopUser.Text    = "Top User: admin (32)"

   $topIPs = $data |
    Group-Object IpAddress |
    Sort-Object Count -Descending |
    Select-Object -First 3

    $text = ""

    foreach ($ip in $topIPs) {
    $text += "$($ip.Name) ($($ip.Count))`n"
    }

    $lblTopIP.Text = $text.Trim()

    $topUser = $data |
    Group-Object Username |
    Sort-Object Count -Descending |
    Select-Object -First 3

    $text = ""

    foreach ($user in $topUser) {
    $text += "$($user.Name) ($($user.Count))`n"
    }

    $lblTopUser.Text = $text.Trim()

    $topCountry = $data |
    Group-Object Country |
    Sort-Object Count -Descending |
    Select-Object -First 3

    $text = ""

    foreach ($country in $topCountry) {
    $text += "$($country.Name) ($($country.Count))`n"
    }

    $lblTopCountry.Text = $text.Trim()

})

$btnExport.Add_Click({
    [System.Windows.MessageBox]::Show("Export HTML à venir")
})

# ===== SHOW =====
$Window.ShowDialog() | Out-Null