## ⚡ Quick Mode Installation

The **Quick Mode** allows a fast and automated deployment of the solution.

### What it does

Running `BF_install.ps1` will automatically:

- Create the directory:
  `C:\temp\BruteForceBlocker\`

- Deploy the script:
  `BruteForce-Blocker.ps1`

- Create a scheduled task:
  **BruteForceBlocker**
  - Runs as **SYSTEM**
  - Triggered on failed logon events (Event ID 4625)

- Create a Windows Firewall rule:
  **Block-BruteForce-logonIT**
  - Used to block malicious IP addresses

---

### ⚠️ Requirements

- Must be run with **Administrator privileges**
- Windows Firewall must be enabled

---

### 🚀 Installation

```powershell
.\BF_install.ps1
