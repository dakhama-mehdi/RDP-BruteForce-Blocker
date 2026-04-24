# Block Brute Force Attack Attempts with Powershell

Block brute force attacks on Windows servers using native PowerShell and Windows Firewall.
No agent. No SIEM. No external dependency.

## Features

- Detect brute force attacks using Event ID 4625
- Automatically block malicious IP addresses
- Smart filtering based on failure reasons
- Country-based blocking (geolocation)
- Adaptive thresholds (fast vs slow attacks)
- Works without Active Directory
- Fully local execution (no cloud dependency)

## Designed for real-world environments

- Standalone Windows servers
- Exposed RDP / IIS / RDS
- No Active Directory
- No centralized security tools

## Results

Reduced brute force attacks by up to 97% on exposed Windows servers.

## Related Project

👉 BruteForce-Detector  
Detect and analyze brute force attacks before blocking them.

