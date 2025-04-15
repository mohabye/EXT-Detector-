# EXT-Detector-
🔍 EXTDetector - Browser Extension Security Analyzer 🛡️
PowerShell
Slack
VirusTotal

A PowerShell tool that scans installed browser extensions, checks them against VirusTotal, and reports findings to Slack with detailed security analysis.

✨ Features
🔎 Detects all installed Chrome/Edge extensions across user profiles

🔢 Calculates SHA256 hashes of extension files

🦠 Checks extensions against VirusTotal's malware database

📤 Sends detailed security reports to Slack

⚡ Lightweight and fast (no installation required)

🎨 Colorful console output with progress indicators

📦 Installation

# Clone the repository
git clone https://github.com/yourusername/EXTDetector.git
cd EXTDetector

# Edit configuration (required before first run)
notepad EXTDetector.ps1
⚙️ Configuration
Edit these variables in the script:

$slackWebhookUrl = "YOUR_SLACK_WEBHOOK_URL"  # Required for Slack notifications
$vtApiKey = "YOUR_VIRUSTOTAL_API_KEY"       # Required for malware checks
🚀 Usage

# Run with default settings
.\EXTDetector.ps1

# Sample output preview:
_______________  ______________ ________          __                 __                
\_   _____/\   \/  /\__    ___/ \______ \   _____/  |_  ____   _____/  |_  ___________ 
 |    __)_  \     /   |    |     |    |  \_/ __ \   __\/ __ \_/ ___\   __\/  _ \_  __ \
 |        \ /     \   |    |     |    `   \  ___/|  | \  ___/\  \___|  | (  <_> )  | \/
/_______  //___/\  \  |____|    /_______  /\___  >__|  \___  >\___  >__|  \____/|__|   
        \/       \_/                    \/     \/          \/     \/                   
🔐 Starting Extension Security Scan 🔍
🕵️‍♀️ Hunting for browser extensions...
🎯 Found 12 extensions to analyze
🔍 Processing extension: fmphggefmkpfoffkdebjnfkehdhmpocn
🔢 Calculating hash for manifest.json...
🦠 Checking VirusTotal for threats...
✅ Clean - 0/72 malicious results
📤 Slack notification sent successfully!
✅ Checked extension: القرآن الكريم - Azkar
🎉 All checks completed! 🎉
📩 Sample Slack Alert

❓ User: tiger  
❓ Profile: Default  
❓ Extension ID: fmphggefmkpfoffkdebjnfkehdhmpocn  
❓ Extension Name: القرآن الكريم - Azkar  
❓ Store: Chrome  
❓ Hash: 43E1D26422BD3BFDD2D614407F6DB808F45327C4A03E6BA3CB935FE9B72349BF  
❓ Path: C:\Users\tiger\AppData\Local\Google\Chrome\User Data\Default\Extensions\fmphggefmkpfoffkdebjnfkehdhmpocn\1.3_0  
❓ VirusTotal Ratio: ✅ 0/72  
❓ Process Name: chrome  
❓ Process Path: C:\Program Files\Google\Chrome\Application\chrome.exe

![image](https://github.com/user-attachments/assets/e063745d-3ff4-4b2a-bf09-4f97aa4ece11)


📝 Requirements
Windows PowerShell 5.1+ (or PowerShell Core)

Slack incoming webhook URL

VirusTotal API key (free tier available)

Google Chrome or Microsoft Edge installed

🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.
