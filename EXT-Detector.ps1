# 🔍 EXTDetector - Browser Extension Security Analyzer 🛡️
# Scans installed Chrome/Edge extensions, checks them against VirusTotal, and reports to Slack

$slackWebhookUrl = "YOUR_SLACK_WEBHOOK_URL"
$vtApiKey = "YOUR_VIRUSTOTAL_API_KEY"

function Show-EXTDetectorBanner {
    Write-Host @"

_______________  ______________ ________          __                 __                
\_   _____/\   \/  /\__    ___/ \______ \   _____/  |_  ____   _____/  |_  ___________ 
 |    __)_  \     /   |    |     |    |  \_/ __ \   __\/ __ \_/ ___\   __\/  _ \_  __ \
 |        \ /     \   |    |     |    `   \  ___/|  | \  ___/\  \___|  | (  <_> )  | \/
/_______  //___/\  \  |____|    /_______  /\___  >__|  \___  >\___  >__|  \____/|__|   
        \/       \_/                    \/     \/          \/     \/                   
"@ -ForegroundColor Cyan
    Write-Host "🔐 Starting Extension Security Scan 🔍`n" -ForegroundColor Yellow
}

function Get-InstalledExtensions {
    Write-Host "🕵️‍♀️ Hunting for browser extensions..." -ForegroundColor Magenta
    $extensions = @()
    $userProfiles = Get-ChildItem 'C:\Users' -Directory | Where-Object { Test-Path "$($_.FullName)\AppData\Local" }

    foreach ($profile in $userProfiles) {
        $chromePath = "$($profile.FullName)\AppData\Local\Google\Chrome\User Data"
        $edgePath = "$($profile.FullName)\AppData\Local\Microsoft\Edge\User Data"

        foreach ($browser in @("Chrome", "Edge")) {
            $browserPath = if ($browser -eq "Chrome") { $chromePath } else { $edgePath }
            if (Test-Path $browserPath) {
                $profiles = Get-ChildItem $browserPath -Directory | Where-Object { $_.Name -match 'Default|Profile' }
                foreach ($prof in $profiles) {
                    $extPath = "$($prof.FullName)\Extensions"
                    if (Test-Path $extPath) {
                        $extDirs = Get-ChildItem $extPath -Directory
                        foreach ($ext in $extDirs) {
                            $versions = Get-ChildItem $ext.FullName -Directory | Sort-Object Name -Descending
                            if ($versions.Count -gt 0) {
                                $extensions += [PSCustomObject]@{
                                    ID = $ext.Name
                                    Store = $browser
                                    Path = $versions[0].FullName
                                    Profile = $prof.Name
                                    User = $profile.Name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Write-Host "🎯 Found $($extensions.Count) extensions to analyze" -ForegroundColor Green
    return $extensions
}

function Get-ExtensionDetails {
    param ($extId, $store)
    $url = if ($store -eq "Chrome") {
        "https://chrome.google.com/webstore/detail/$extId"
    } else {
        "https://microsoftedge.microsoft.com/addons/detail/$extId"
    }

    try {
        $web = Invoke-WebRequest -Uri $url -UseBasicParsing
        if ($store -eq "Chrome") {
            if ($web.Content -match "<title>(.*?)</title>") {
                return ($matches[1] -replace ' - Chrome Web Store$', '').Trim()
            }
        } else {
            if ($web.Content -match '<h1[^>]*>(.*?)</h1>') {
                return $matches[1].Trim()
            }
        }
    } catch {
        return " Unknown"
    }
}

function Get-FileHashFromPath {
    param ($path)
    if (Test-Path $path) {
        $files = Get-ChildItem $path -Recurse -File
        foreach ($file in $files) {
            Write-Host "🔢 Calculating hash for $($file.Name)..." -ForegroundColor Blue
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
            return $hash.Hash
        }
    }
    return $null
}

function Check-VirusTotal {
    param ($hash)
    Write-Host "🦠 Checking VirusTotal for threats..." -ForegroundColor Yellow
    $url = "https://www.virustotal.com/api/v3/files/$hash"
    $headers = @{ "x-apikey" = $vtApiKey }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        $positives = $response.data.attributes.last_analysis_stats.malicious
        $total = $response.data.attributes.last_analysis_stats.total
        
        if ($positives -gt 0) {
            Write-Host "🚨 Detected $positives/$total malicious results!" -ForegroundColor Red
            return "⚠️ $positives/$total"
        } else {
            Write-Host "✅ Clean - 0/$total malicious results" -ForegroundColor Green
            return "✅ 0/$total"
        }
    } catch {
        Write-Host "❌ VirusTotal check failed" -ForegroundColor Red
        return " N/A"
    }
}

function Get-ProcessInfo {
    $processes = Get-Process | Where-Object { $_.Name -like "*chrome*" -or $_.Name -like "*msedge*" }
    foreach ($proc in $processes) {
        return [PSCustomObject]@{
            ProcessName = $proc.Name
            ProcessPath = $proc.Path
        }
    }
    return $null
}

function Send-SlackMessage {
    param ($message)
    $payload = @{
        "text" = $message
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Uri $slackWebhookUrl -Method Post -Body $payload -ContentType "application/json"
        Write-Host "📤 Slack notification sent successfully!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to send to Slack: $_" -ForegroundColor Red
    }
}

Show-EXTDetectorBanner
$allExtensions = Get-InstalledExtensions

foreach ($ext in $allExtensions) {
    Write-Host "`n🔍 Processing extension: $($ext.ID)" -ForegroundColor Cyan
    $extName = Get-ExtensionDetails -extId $ext.ID -store $ext.Store
    $hash = Get-FileHashFromPath -path $ext.Path
    $vtRatio = if ($hash) { Check-VirusTotal -hash $hash } else { " N/A" }
    $procInfo = Get-ProcessInfo

    $slackMessage = @"
  User: $($ext.User)
 Profile: $($ext.Profile)
 Extension ID: $($ext.ID)
 Extension Name: $extName
 Store: $($ext.Store)
 Hash: $hash
 Path: $($ext.Path)
 VirusTotal Ratio: $vtRatio
 Process Name: $($procInfo.ProcessName)
 Process Path: $($procInfo.ProcessPath)
"@

    Send-SlackMessage -message $slackMessage
    Write-Host "✅ Checked extension: $extName" -ForegroundColor Green
}

Write-Host "`n🎉 All checks completed! 🎉`n" -ForegroundColor Green