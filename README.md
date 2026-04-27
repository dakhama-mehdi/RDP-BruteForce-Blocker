# Block Brute Force Attack Attempts with Powershell

Detect and block brute-force attacks using native Windows logs.  
This PowerShell script automatically blocks IP addresses based on multiple criteria such as geolocation and authentication failure reasons.

Adaptive thresholds provide fine-grained control:
- 10 attempts for standard users  
- 20 for trusted countries  
- 5 for specific failure types (e.g., user does not exist)
- History 24 hours to detect Slows attacks

Lightweight, flexible, and designed to stand out from traditional solutions.

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

## Documentation
https://www.it-connect.tech/how-to-detect-and-block-brute-force-attacks-on-windows-server-with-powershell/

## Related Project

BruteForce-Detector  
Detect and analyze brute force attacks before blocking them.

