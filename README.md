# BruteForce-Blocker

This project provides PowerShell scripts to detect and automatically block RDP brute force attacks on Windows servers.

The detection is based on failed logon events (Event ID 4625), using criteria such as:
- number of failed attempts within a time window
- failure reasons (e.g. unknown user, bad password)

## Scripts

- Find-BruteForce.ps1  
  Detects and lists suspicious brute force activity from Windows Security logs.

- Block-BruteForce.ps1  
  Automatically blocks sources based on detected brute force patterns. *(coming soon)*


