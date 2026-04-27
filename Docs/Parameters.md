
# ⚙️ Parameters

This file explains the configuration options used by the BruteForce-Blocker script.

---

## 🧩 General Settings

### Mode
Enable or disable blocking.

```powershell
$Mode = "false"
```

- "true" → IPs will be blocked  
- "false" → detection only (no blocking)  

👉 Recommended to start in "false" to test your configuration.

---

### HistoryAttempt
Defines how long previous attempts are kept in memory.

```powershell
$HistoryAttempt = 24
```

- Value is in hours  
- Used to detect slow brute-force attacks over time  

👉 Example: 24 = track attempts over the last 24 hours

---

### Path
Defines where logs and history files are stored.

```powershell
$Path = "C:\temp\BruteForceBlocker\"
```

👉 Make sure the folder exists or can be created.

---

## 🚨 Detection Settings

### Minutes
Time window used to detect brute-force activity.

```powershell
$Minutes = 1
```

👉 Example: 1 = analyze failed logons within 1 minute

---

### Threshold
Number of failed attempts before blocking an IP.

```powershell
$threshold = 10
```

👉 Example: 10 failed logons = IP is blocked

---

## 🎯 Failure Reason Filtering

### filterReason
Allows filtering based on specific failure reasons.

```powershell
$filterReason = @("User does not exist")
```

- Only events matching this reason will be counted  
- Leave empty to disable:

```powershell
$filterReason = @()
```

👉 Use exact values from Windows Event Logs

---

### reasonThreshold
Defines how many identical failures trigger a block.

```powershell
$reasonThreshold = 4
```

👉 Example:
- 4 "User does not exist" → block triggered  

👉 Only applies if filterReason is defined

---

## 🌍 Country Filtering

### trustedCountries
List of countries with higher tolerance.

```powershell
$trustedCountries = @("France", "United States")
```

👉 Use exact country names returned by your geolocation API

---

### trustedThreshold
Higher threshold for trusted countries.

```powershell
$trustedThreshold = 15
```

👉 Example:
- 15 attempts allowed for trusted countries

---

### thresetrange
Lower threshold for non-trusted countries.

```powershell
$thresetrange = 5
```

👉 Example:
- Foreign IPs blocked after 5 attempts  

👉 This makes detection more aggressive for unknown sources

---

## 🛡️ Trusted IPs

List of IP addresses that will never be blocked.

```powershell
$trustedIPs = @(
    "127.0.0.1",
    "::1"
)
```

👉 Useful for:
- local machine  
- monitoring systems  
- internal tools  

---

## 🧠 Best Practices

- Start in detection mode ($Mode = "false")  
- Adjust thresholds based on your environment  
- Combine filters (reason + country) for better accuracy  
- Regularly review logs  

---

## ⚡ Summary

This script provides adaptive protection by combining:

- Time-based detection  
- Failure reason analysis  
- Geolocation filtering  
- Custom thresholds  

👉 Lightweight, flexible, and fully customizable
