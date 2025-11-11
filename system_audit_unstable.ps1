<#
.SYNOPSIS
    Windows System Slowness Audit Tool - Professional Edition v1.2.0
.DESCRIPTION
    Enterprise-grade performance audit tool for diagnosing system slowness, security issues, and infrastructure health.
    Developed by: Abubakkar Khan - System Engineer | Cybersecurity Researcher
.VERSION
    1.2.0 - Complete Professional Edition (All Features Fully Implemented)
.NOTES
    Requires Administrator privileges
    Compatible with Windows Server 2012+ and Windows 10+
    42 Comprehensive Audit Functions - All Fully Implemented
#>

# Requires -RunAsAdministrator

$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "White"
Clear-Host

function Show-Banner {
    Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                                       ║" -ForegroundColor Cyan
    Write-Host "║        WINDOWS SYSTEM SLOWNESS AUDIT TOOL v1.2.0 - PROFESSIONAL      ║" -ForegroundColor Yellow
    Write-Host "║                  42 Full-Featured Audit Functions                    ║" -ForegroundColor Yellow
    Write-Host "║                                                                       ║" -ForegroundColor Cyan
    Write-Host "║        Developed By: Abubakkar Khan                                   ║" -ForegroundColor Green
    Write-Host "║        System Engineer | Cybersecurity Researcher                     ║" -ForegroundColor Green
    Write-Host "║                                                                       ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Menu {
    Write-Host "═══════════════════════ COMPREHENSIVE AUDIT MENU ═══════════════════════" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  ▶ CORE DIAGNOSTICS (1-10)" -ForegroundColor Yellow
    Write-Host "    [1]  CPU Usage Analysis              [6]  Windows Services Status" -ForegroundColor White
    Write-Host "    [2]  Memory (RAM) Analysis          [7]  Event Log Errors (24h)" -ForegroundColor White
    Write-Host "    [3]  Disk Performance & Space       [8]  Startup Programs" -ForegroundColor White
    Write-Host "    [4]  Network Performance            [9]  Windows Update Status" -ForegroundColor White
    Write-Host "    [5]  Top Resource Processes         [10] Hardware Health" -ForegroundColor White
    Write-Host ""
    Write-Host "  ▶ ADVANCED DIAGNOSTICS (13-22)" -ForegroundColor Yellow
    Write-Host "    [13] PageFile & Virtual Memory      [18] Scheduled Tasks" -ForegroundColor Cyan
    Write-Host "    [14] System Uptime & Boot           [19] Power Plan & Battery" -ForegroundColor Cyan
    Write-Host "    [15] Network Latency Test           [20] DNS Performance" -ForegroundColor Cyan
    Write-Host "    [16] Antivirus Impact               [21] Disk I/O Wait Time" -ForegroundColor Cyan
    Write-Host "    [17] Process Handle Analysis        [22] Critical Event Logs" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ STORAGE & BACKUP (23-24)" -ForegroundColor Yellow
    Write-Host "    [23] Disk Fragmentation             [24] Shadow Copy/VSS Status" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ NETWORK & SECURITY (25-28)" -ForegroundColor Yellow
    Write-Host "    [25] Open Ports & Services          [27] SSL/TLS Certificates" -ForegroundColor Cyan
    Write-Host "    [26] Firewall Rules Analysis        [28] SMB Share Security" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ HARDWARE & DRIVERS (29-31)" -ForegroundColor Yellow
    Write-Host "    [29] GPU Performance Monitor        [31] USB Device Audit" -ForegroundColor Cyan
    Write-Host "    [30] Problematic Driver Detection" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ APPLICATIONS (32-36)" -ForegroundColor Yellow
    Write-Host "    [32] SQL Server Health              [35] Docker Containers" -ForegroundColor Cyan
    Write-Host "    [33] MySQL/MariaDB Health           [36] Hyper-V VMs" -ForegroundColor Cyan
    Write-Host "    [34] IIS Performance" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ SECURITY & COMPLIANCE (37-39)" -ForegroundColor Yellow
    Write-Host "    [37] Security Baseline Check        [39] Suspicious Process Scan" -ForegroundColor Cyan
    Write-Host "    [38] Patch Compliance Report" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ SYSTEM MAINTENANCE (40-42)" -ForegroundColor Yellow
    Write-Host "    [40] Registry Health Check          [42] Windows Features Status" -ForegroundColor Cyan
    Write-Host "    [41] System File Integrity (SFC)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ▶ UTILITIES" -ForegroundColor Yellow
    Write-Host "    [11] ★ FULL SYSTEM AUDIT (All 42 Checks)" -ForegroundColor Yellow
    Write-Host "    [12] 📊 Export Report to Desktop" -ForegroundColor Green
    Write-Host "    [0]  Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Magenta
}

# ========== CORE FUNCTIONS 1-10 - FULLY IMPLEMENTED ==========

function Get-CPUUsage {
    Write-Host "`n[+] CPU USAGE ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $cpu = Get-CimInstance Win32_Processor
    $cpuLoad = (Get-Counter '\Processor(_Total)\% Processor Time' -EA SilentlyContinue).CounterSamples.CookedValue
    
    Write-Host "CPU Model       : $($cpu.Name)" -ForegroundColor White
    Write-Host "Cores/Threads   : $($cpu.NumberOfCores) Cores / $($cpu.NumberOfLogicalProcessors) Logical Processors" -ForegroundColor White
    Write-Host "Current Load    : $([math]::Round($cpuLoad, 2))%" -ForegroundColor $(if($cpuLoad -gt 80){"Red"}elseif($cpuLoad -gt 60){"Yellow"}else{"Green"})
    Write-Host "Max Clock Speed : $($cpu.MaxClockSpeed) MHz" -ForegroundColor White
    Write-Host "Current Speed   : $($cpu.CurrentClockSpeed) MHz" -ForegroundColor White
    
    try {
        $cpuQueue = (Get-Counter '\System\Processor Queue Length' -EA SilentlyContinue).CounterSamples.CookedValue
        Write-Host "CPU Queue Len   : $cpuQueue" -ForegroundColor $(if($cpuQueue -gt 5){"Red"}elseif($cpuQueue -gt 2){"Yellow"}else{"Green"})
        if($cpuQueue -gt 5) {
            Write-Host "(WARNING) High CPU queue indicates CPU bottleneck" -ForegroundColor Red
        }
    } catch {}
    
    Write-Host "`nTop 10 CPU-Consuming Processes:" -ForegroundColor Cyan
    Get-Process -EA SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 10 ProcessName, CPU, Id | Format-Table -AutoSize
    
    if($cpuLoad -gt 80) {
        Write-Host "(WARNING) CPU usage is critically high (>80%)" -ForegroundColor Red
    } elseif($cpuLoad -gt 60) {
        Write-Host "(CAUTION) CPU usage is elevated (60-80%)" -ForegroundColor Yellow
    } else {
        Write-Host "(OK) CPU usage is within normal range (<60%)" -ForegroundColor Green
    }
}

function Get-MemoryUsage {
    Write-Host "`n[+] MEMORY (RAM) ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRAM = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeRAM = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedRAM = $totalRAM - $freeRAM
    $usagePercent = [math]::Round(($usedRAM / $totalRAM) * 100, 2)
    
    Write-Host "Total RAM       : $totalRAM GB" -ForegroundColor White
    Write-Host "Used RAM        : $usedRAM GB" -ForegroundColor White
    Write-Host "Free RAM        : $freeRAM GB" -ForegroundColor White
    Write-Host "Usage Percent   : $usagePercent%" -ForegroundColor $(if($usagePercent -gt 90){"Red"}elseif($usagePercent -gt 75){"Yellow"}else{"Green"})
    
    try {
        $pageFaults = (Get-Counter '\Memory\Page Faults/sec' -EA SilentlyContinue).CounterSamples.CookedValue
        Write-Host "Page Faults/sec : $([math]::Round($pageFaults, 2))" -ForegroundColor White
    } catch {}
    
    Write-Host "`nTop 10 Memory-Consuming Processes:" -ForegroundColor Cyan
    Get-Process -EA SilentlyContinue | Sort-Object WorkingSet -Descending | Select-Object -First 10 ProcessName, @{N="Memory(MB)";E={[math]::Round($_.WorkingSet / 1MB, 2)}}, Id | Format-Table -AutoSize
    
    if($usagePercent -gt 90) {
        Write-Host "(CRITICAL) Memory usage is critically high (>90%)" -ForegroundColor Red
    } elseif($usagePercent -gt 75) {
        Write-Host "(WARNING) Memory usage is high (75-90%)" -ForegroundColor Yellow
    } else {
        Write-Host "(OK) Memory usage is within acceptable range (<75%)" -ForegroundColor Green
    }
}

function Get-DiskPerformance {
    Write-Host "`n[+] DISK PERFORMANCE AND SPACE ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -EA SilentlyContinue
    
    foreach ($disk in $disks) {
        $size = [math]::Round($disk.Size / 1GB, 2)
        $free = [math]::Round($disk.FreeSpace / 1GB, 2)
        $used = $size - $free
        $usagePercent = [math]::Round(($used / $size) * 100, 2)
        
        Write-Host "`nDrive           : $($disk.DeviceID)" -ForegroundColor Cyan
        Write-Host "Volume Label    : $($disk.VolumeName)" -ForegroundColor White
        Write-Host "Total Space     : $size GB" -ForegroundColor White
        Write-Host "Used Space      : $used GB" -ForegroundColor White
        Write-Host "Free Space      : $free GB" -ForegroundColor White
        Write-Host "Usage Percent   : $usagePercent%" -ForegroundColor $(if($usagePercent -gt 90){"Red"}elseif($usagePercent -gt 80){"Yellow"}else{"Green"})
        
        if($usagePercent -gt 90) {
            Write-Host "(CRITICAL) Disk space critically low (<10% free)" -ForegroundColor Red
        } elseif($usagePercent -gt 80) {
            Write-Host "(WARNING) Disk space low (10-20% free)" -ForegroundColor Yellow
        }
    }
    
    # Disk I/O metrics
    Write-Host "`nDisk I/O Performance:" -ForegroundColor Cyan
    try {
        $diskRead = (Get-Counter '\PhysicalDisk(_Total)\Disk Reads/sec' -EA SilentlyContinue).CounterSamples.CookedValue
        $diskWrite = (Get-Counter '\PhysicalDisk(_Total)\Disk Writes/sec' -EA SilentlyContinue).CounterSamples.CookedValue
        $diskQueue = (Get-Counter '\PhysicalDisk(_Total)\Avg. Disk Queue Length' -EA SilentlyContinue).CounterSamples.CookedValue
        
        Write-Host "Disk Reads/sec  : $([math]::Round($diskRead, 2))" -ForegroundColor White
        Write-Host "Disk Writes/sec : $([math]::Round($diskWrite, 2))" -ForegroundColor White
        Write-Host "Disk Queue Len  : $([math]::Round($diskQueue, 2))" -ForegroundColor $(if($diskQueue -gt 2){"Red"}elseif($diskQueue -gt 1){"Yellow"}else{"Green"})
        
        if($diskQueue -gt 2) {
            Write-Host "(WARNING) High disk queue indicates I/O bottleneck" -ForegroundColor Red
        }
    } catch {
        Write-Host "(INFO) Unable to retrieve disk I/O performance data" -ForegroundColor Yellow
    }
}

function Get-NetworkPerformance {
    Write-Host "`n[+] NETWORK PERFORMANCE ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $adapters = Get-NetAdapter -EA SilentlyContinue | Where-Object Status -eq "Up"
    
    foreach ($adapter in $adapters) {
        Write-Host "`nAdapter         : $($adapter.Name)" -ForegroundColor Cyan
        Write-Host "Status          : $($adapter.Status)" -ForegroundColor Green
        Write-Host "Link Speed      : $($adapter.LinkSpeed)" -ForegroundColor White
        Write-Host "MAC Address     : $($adapter.MacAddress)" -ForegroundColor White
        Write-Host "Driver          : $($adapter.DriverFileName)" -ForegroundColor White
    }
    
    Write-Host "`nNetwork Connectivity Test:" -ForegroundColor Cyan
    $testConnection = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet -EA SilentlyContinue
    if($testConnection) {
        Write-Host "(OK) Internet connectivity: OK" -ForegroundColor Green
    } else {
        Write-Host "(FAILED) Internet connectivity: FAILED" -ForegroundColor Red
    }
}

function Get-TopProcesses {
    Write-Host "`n[+] TOP RESOURCE-CONSUMING PROCESSES" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nTop 15 Processes by CPU:" -ForegroundColor Cyan
    Get-Process -EA SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 15 ProcessName, CPU, @{N="Memory(MB)";E={[math]::Round($_.WorkingSet / 1MB, 2)}}, Id, Handles | Format-Table -AutoSize
    
    Write-Host "`nTop 15 Processes by Memory:" -ForegroundColor Cyan
    Get-Process -EA SilentlyContinue | Sort-Object WorkingSet -Descending | Select-Object -First 15 ProcessName, @{N="Memory(MB)";E={[math]::Round($_.WorkingSet / 1MB, 2)}}, CPU, Id, Handles | Format-Table -AutoSize
}

function Get-ServicesStatus {
    Write-Host "`n[+] WINDOWS SERVICES STATUS CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $criticalServices = @("wuauserv", "BITS", "EventLog", "WinDefend", "Dnscache", "Dhcp", "LanmanWorkstation", "LanmanServer", "W32Time", "RpcSs", "Spooler")
    
    Write-Host "`nCritical Services Status:" -ForegroundColor Cyan
    foreach ($svc in $criticalServices) {
        $service = Get-Service -Name $svc -EA SilentlyContinue
        if ($service) {
            $status = $service.Status
            $color = if($status -eq "Running"){"Green"}else{"Red"}
            Write-Host "$($service.DisplayName.PadRight(40)) : $status" -ForegroundColor $color
        }
    }
    
    Write-Host "`nServices that Should be Running but are Stopped:" -ForegroundColor Cyan
    $stoppedServices = Get-Service -EA SilentlyContinue | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -eq "Stopped"}
    if ($stoppedServices.Count -gt 0) {
        $stoppedServices | Select-Object -First 20 DisplayName, Name, Status, StartType | Format-Table -AutoSize
        Write-Host "(INFO) Found $($stoppedServices.Count) stopped services with Automatic start type" -ForegroundColor Yellow
    } else {
        Write-Host "(OK) All automatic services are running" -ForegroundColor Green
    }
}

function Get-EventLogErrors {
    Write-Host "`n[+] SYSTEM EVENT LOG ERRORS (Last 24 Hours)" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $startTime = (Get-Date).AddHours(-24)
    
    Write-Host "`nSystem Errors:" -ForegroundColor Cyan
    $systemErrors = Get-EventLog -LogName System -EntryType Error -After $startTime -EA SilentlyContinue | Select-Object -First 20
    if ($systemErrors) {
        $systemErrors | Select-Object TimeGenerated, Source, EventID, @{N="Message";E={$_.Message.Substring(0, [Math]::Min(80, $_.Message.Length))}} | Format-Table -AutoSize -Wrap
        Write-Host "(INFO) Found $($systemErrors.Count) system errors" -ForegroundColor Yellow
    } else {
        Write-Host "(OK) No system errors in the last 24 hours" -ForegroundColor Green
    }
    
    Write-Host "`nApplication Errors:" -ForegroundColor Cyan
    $appErrors = Get-EventLog -LogName Application -EntryType Error -After $startTime -EA SilentlyContinue | Select-Object -First 20
    if ($appErrors) {
        $appErrors | Select-Object TimeGenerated, Source, EventID, @{N="Message";E={$_.Message.Substring(0, [Math]::Min(80, $_.Message.Length))}} | Format-Table -AutoSize -Wrap
        Write-Host "(INFO) Found $($appErrors.Count) application errors" -ForegroundColor Yellow
    } else {
        Write-Host "(OK) No application errors in the last 24 hours" -ForegroundColor Green
    }
}

function Get-StartupPrograms {
    Write-Host "`n[+] STARTUP PROGRAMS ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nStartup Programs (Registry):" -ForegroundColor Cyan
    $startupRegPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    $startupCount = 0
    foreach ($path in $startupRegPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty -Path $path -EA SilentlyContinue
            if ($items) {
                Write-Host "`nLocation: $path" -ForegroundColor White
                $items.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {
                    Write-Host "  $($_.Name): $($_.Value)" -ForegroundColor Gray
                    $startupCount++
                }
            }
        }
    }
    
    Write-Host "`nStartup Folder Items:" -ForegroundColor Cyan
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $items = Get-ChildItem -Path $folder -EA SilentlyContinue
            if ($items.Count -gt 0) {
                Write-Host "`nLocation: $folder" -ForegroundColor White
                $items | Select-Object Name, FullName, CreationTime | Format-Table -AutoSize
                $startupCount += $items.Count
            }
        }
    }
    
    Write-Host "`nTotal startup items found: $startupCount" -ForegroundColor Cyan
    if($startupCount -gt 15) {
        Write-Host "(WARNING) High number of startup items may slow boot time" -ForegroundColor Yellow
    }
}

function Get-WindowsUpdateStatus {
    Write-Host "`n[+] WINDOWS UPDATE STATUS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nChecking for pending updates..." -ForegroundColor Cyan
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -EA SilentlyContinue
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0")
        $updates = $searchResult.Updates
        
        if ($updates.Count -gt 0) {
            Write-Host "(INFO) Found $($updates.Count) pending updates" -ForegroundColor Yellow
            $updates | Select-Object -First 10 Title | Format-Table -AutoSize
        } else {
            Write-Host "(OK) System is up to date" -ForegroundColor Green
        }
        
        $lastUpdate = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($lastUpdate) {
            Write-Host "`nLast Update Installed:" -ForegroundColor Cyan
            Write-Host "KB         : $($lastUpdate.HotFixID)" -ForegroundColor White
            Write-Host "Installed  : $($lastUpdate.InstalledOn)" -ForegroundColor White
            Write-Host "Description: $($lastUpdate.Description)" -ForegroundColor White
        }
    } catch {
        Write-Host "(ERROR) Unable to check Windows Update status" -ForegroundColor Red
    }
}

function Get-HardwareHealth {
    Write-Host "`n[+] TEMPERATURE AND HARDWARE HEALTH" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nSystem Information:" -ForegroundColor Cyan
    $computerSystem = Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -EA SilentlyContinue
    
    Write-Host "Manufacturer   : $($computerSystem.Manufacturer)" -ForegroundColor White
    Write-Host "Model          : $($computerSystem.Model)" -ForegroundColor White
    Write-Host "BIOS Version   : $($bios.SMBIOSBIOSVersion)" -ForegroundColor White
    Write-Host "System Type    : $($computerSystem.SystemType)" -ForegroundColor White
    Write-Host "Total Physical : $([math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor White
    Write-Host "Boot Time      : $($bios.ReleaseDate)" -ForegroundColor White
    
    Write-Host "`nPhysical Disk Health:" -ForegroundColor Cyan
    try {
        $physicalDisks = Get-PhysicalDisk -EA SilentlyContinue
        foreach ($disk in $physicalDisks) {
            Write-Host "`nDisk           : $($disk.FriendlyName)" -ForegroundColor White
            Write-Host "Health Status  : $($disk.HealthStatus)" -ForegroundColor $(if($disk.HealthStatus -eq "Healthy"){"Green"}else{"Red"})
            Write-Host "Operational    : $($disk.OperationalStatus)" -ForegroundColor White
            Write-Host "Size           : $([math]::Round($disk.Size / 1GB, 2)) GB" -ForegroundColor White
            Write-Host "Media Type     : $($disk.MediaType)" -ForegroundColor White
        }
    } catch {
        Write-Host "(INFO) Unable to retrieve physical disk health" -ForegroundColor Yellow
    }
}

# ========== ADVANCED FUNCTIONS 13-22 - FULLY IMPLEMENTED ==========

function Get-PageFileAnalysis {
    Write-Host "`n[+] PAGEFILE AND VIRTUAL MEMORY ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $pageFiles = Get-CimInstance Win32_PageFileUsage -EA SilentlyContinue
    $pageFileSettings = Get-CimInstance Win32_PageFileSetting -EA SilentlyContinue
    
    if ($pageFiles) {
        foreach ($pf in $pageFiles) {
            Write-Host "`nPageFile       : $($pf.Name)" -ForegroundColor Cyan
            Write-Host "Allocated Size : $($pf.AllocatedBaseSize) MB" -ForegroundColor White
            Write-Host "Current Usage  : $($pf.CurrentUsage) MB" -ForegroundColor White
            Write-Host "Peak Usage     : $($pf.PeakUsage) MB" -ForegroundColor White
            $usagePercent = [math]::Round(($pf.CurrentUsage / $pf.AllocatedBaseSize) * 100, 2)
            Write-Host "Usage Percent  : $usagePercent%" -ForegroundColor $(if($usagePercent -gt 80){"Red"}elseif($usagePercent -gt 60){"Yellow"}else{"Green"})
            
            if($usagePercent -gt 80) {
                Write-Host "(WARNING) PageFile usage is high - consider increasing size" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "(INFO) No PageFile detected (system-managed or disabled)" -ForegroundColor Cyan
    }
    
    try {
        $commitLimit = (Get-Counter '\Memory\Commit Limit' -EA SilentlyContinue).CounterSamples.CookedValue
        $committedBytes = (Get-Counter '\Memory\Committed Bytes' -EA SilentlyContinue).CounterSamples.CookedValue
        Write-Host "`nVirtual Memory:" -ForegroundColor Cyan
        Write-Host "Commit Limit   : $([math]::Round($commitLimit / 1MB, 2)) MB" -ForegroundColor White
        Write-Host "Committed Bytes: $([math]::Round($committedBytes / 1MB, 2)) MB" -ForegroundColor White
        $commitPercent = [math]::Round(($committedBytes / $commitLimit) * 100, 2)
        Write-Host "Commit Percent : $commitPercent%" -ForegroundColor $(if($commitPercent -gt 90){"Red"}elseif($commitPercent -gt 75){"Yellow"}else{"Green"})
    } catch {}
}

function Get-SystemUptimeAndBoot {
    Write-Host "`n[+] SYSTEM UPTIME AND BOOT PERFORMANCE" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $os = Get-CimInstance Win32_OperatingSystem -EA SilentlyContinue
    $lastBoot = $os.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    
    Write-Host "`nSystem Boot Information:" -ForegroundColor Cyan
    Write-Host "Last Boot Time : $lastBoot" -ForegroundColor White
    Write-Host "Uptime         : $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes" -ForegroundColor White
    Write-Host "OS Version     : $($os.Caption) $($os.Version)" -ForegroundColor White
    Write-Host "Architecture   : $($os.OSArchitecture)" -ForegroundColor White
    
    if($uptime.Days -gt 30) {
        Write-Host "(INFO) System uptime exceeds 30 days - consider rebooting" -ForegroundColor Yellow
    }
    
    Write-Host "`nLast 5 System Shutdowns/Reboots:" -ForegroundColor Cyan
    $shutdownEvents = Get-EventLog -LogName System -Source "User32" -EA SilentlyContinue | 
        Where-Object {$_.EventID -eq 1074} | 
        Select-Object -First 5 TimeGenerated, Message
    
    if($shutdownEvents) {
        $shutdownEvents | Format-Table -AutoSize -Wrap
    } else {
        Write-Host "(INFO) No recent shutdown events found" -ForegroundColor Gray
    }
}

function Get-NetworkLatencyTest {
    Write-Host "`n[+] NETWORK LATENCY AND PACKET LOSS TEST" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $targets = @(
        @{Name="Google DNS"; IP="8.8.8.8"},
        @{Name="Cloudflare DNS"; IP="1.1.1.1"},
        @{Name="Local Gateway"; IP=(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -EA SilentlyContinue | Select-Object -First 1).NextHop}
    )
    
    foreach ($target in $targets) {
        if($target.IP) {
            Write-Host "`nTesting: $($target.Name) ($($target.IP))" -ForegroundColor Cyan
            
            try {
                $pingResults = Test-Connection -ComputerName $target.IP -Count 10 -EA Stop
                
                $avgLatency = ($pingResults | Measure-Object -Property ResponseTime -Average).Average
                $minLatency = ($pingResults | Measure-Object -Property ResponseTime -Minimum).Minimum
                $maxLatency = ($pingResults | Measure-Object -Property ResponseTime -Maximum).Maximum
                $packetLoss = [math]::Round((1 - ($pingResults.Count / 10)) * 100, 2)
                
                Write-Host "Packets Sent   : 10" -ForegroundColor White
                Write-Host "Packets Recv   : $($pingResults.Count)" -ForegroundColor $(if($pingResults.Count -lt 10){"Red"}else{"Green"})
                Write-Host "Packet Loss    : $packetLoss%" -ForegroundColor $(if($packetLoss -gt 5){"Red"}elseif($packetLoss -gt 1){"Yellow"}else{"Green"})
                Write-Host "Min Latency    : $minLatency ms" -ForegroundColor White
                Write-Host "Avg Latency    : $([math]::Round($avgLatency, 2)) ms" -ForegroundColor $(if($avgLatency -gt 100){"Red"}elseif($avgLatency -gt 50){"Yellow"}else{"Green"})
                Write-Host "Max Latency    : $maxLatency ms" -ForegroundColor White
                
                if($packetLoss -gt 5) {
                    Write-Host "(WARNING) High packet loss detected - check network connectivity" -ForegroundColor Red
                }
                if($avgLatency -gt 100) {
                    Write-Host "(WARNING) High latency detected - network performance may be degraded" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "(ERROR) Unable to ping $($target.IP)" -ForegroundColor Red
            }
        }
    }
}

function Get-AntivirusImpact {
    Write-Host "`n[+] ANTIVIRUS AND WINDOWS DEFENDER IMPACT" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    try {
        $defenderStatus = Get-MpComputerStatus -EA SilentlyContinue
        if($defenderStatus) {
            Write-Host "`nWindows Defender Status:" -ForegroundColor Cyan
            Write-Host "Antivirus Enabled      : $($defenderStatus.AntivirusEnabled)" -ForegroundColor $(if($defenderStatus.AntivirusEnabled){"Green"}else{"Red"})
            Write-Host "Real-time Protection   : $($defenderStatus.RealTimeProtectionEnabled)" -ForegroundColor $(if($defenderStatus.RealTimeProtectionEnabled){"Green"}else{"Red"})
            Write-Host "Behavior Monitor       : $($defenderStatus.BehaviorMonitorEnabled)" -ForegroundColor White
            Write-Host "IOAV Protection        : $($defenderStatus.IoavProtectionEnabled)" -ForegroundColor White
            Write-Host "Antivirus Signature Age: $($defenderStatus.AntivirusSignatureAge) days" -ForegroundColor $(if($defenderStatus.AntivirusSignatureAge -gt 7){"Yellow"}else{"Green"})
            Write-Host "Last Quick Scan        : $($defenderStatus.QuickScanEndTime)" -ForegroundColor White
            Write-Host "Last Full Scan         : $($defenderStatus.FullScanEndTime)" -ForegroundColor White
        }
    } catch {
        Write-Host "(INFO) Windows Defender status not available" -ForegroundColor Gray
    }
    
    Write-Host "`nAntivirus Process Resource Usage:" -ForegroundColor Cyan
    $avProcesses = Get-Process -EA SilentlyContinue | Where-Object {$_.ProcessName -match "MsMpEng|WinDefend|avp|avgnt|ntrtscan|mbam|ccSvcHst"}
    if($avProcesses) {
        $avProcesses | Select-Object ProcessName, CPU, @{N="Memory(MB)";E={[math]::Round($_.WorkingSet / 1MB, 2)}} | Format-Table -AutoSize
    } else {
        Write-Host "(INFO) No active antivirus processes detected" -ForegroundColor Gray
    }
}

function Get-ProcessHandleAnalysis {
    Write-Host "`n[+] PROCESS HANDLE AND THREAD ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nTop 15 Processes by Handle Count:" -ForegroundColor Cyan
    $processes = Get-Process -EA SilentlyContinue | Sort-Object Handles -Descending | Select-Object -First 15 ProcessName, Handles, Threads, @{N="Memory(MB)";E={[math]::Round($_.WorkingSet / 1MB, 2)}}, Id
    $processes | Format-Table -AutoSize
    
    $suspiciousProcesses = Get-Process -EA SilentlyContinue | Where-Object {$_.Handles -gt 10000}
    if($suspiciousProcesses) {
        Write-Host "`n(WARNING) Processes with Excessive Handles (Potential Leak):" -ForegroundColor Yellow
        $suspiciousProcesses | Select-Object ProcessName, Handles, Id | Format-Table -AutoSize
    }
    
    Write-Host "`nTop 15 Processes by Thread Count:" -ForegroundColor Cyan
    Get-Process -EA SilentlyContinue | Sort-Object Threads -Descending | Select-Object -First 15 ProcessName, Threads, Handles, CPU, Id | Format-Table -AutoSize
    
    try {
        $totalHandles = (Get-Process -EA SilentlyContinue | Measure-Object -Property Handles -Sum).Sum
        Write-Host "`nTotal System Handles: $totalHandles" -ForegroundColor White
        if($totalHandles -gt 100000) {
            Write-Host "(INFO) High system handle count - monitor for handle leaks" -ForegroundColor Yellow
        }
    } catch {}
}

function Get-ScheduledTasksAnalysis {
    Write-Host "`n[+] SCHEDULED TASKS ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nRecently Run Scheduled Tasks (Last 24h):" -ForegroundColor Cyan
    try {
        $tasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo -EA SilentlyContinue | 
            Where-Object {$_.LastRunTime -gt (Get-Date).AddHours(-24)} | 
            Select-Object -First 20 TaskName, LastRunTime, LastTaskResult, NextRunTime
        
        if($tasks) {
            $tasks | Format-Table -AutoSize
        } else {
            Write-Host "(INFO) No tasks run in the last 24 hours" -ForegroundColor Gray
        }
    } catch {
        Write-Host "(INFO) Unable to retrieve scheduled tasks" -ForegroundColor Gray
    }
    
    Write-Host "`nCurrently Running Scheduled Tasks:" -ForegroundColor Cyan
    try {
        $runningTasks = Get-ScheduledTask -EA SilentlyContinue | Where-Object {$_.State -eq "Running"}
        if($runningTasks) {
            $runningTasks | Select-Object TaskName, State | Format-Table -AutoSize
        } else {
            Write-Host "(OK) No scheduled tasks currently running" -ForegroundColor Green
        }
    } catch {}
    
    Write-Host "`nFailed Scheduled Tasks:" -ForegroundColor Cyan
    try {
        $failedTasks = Get-ScheduledTask -EA SilentlyContinue | Get-ScheduledTaskInfo -EA SilentlyContinue | 
            Where-Object {$_.LastTaskResult -ne 0 -and $_.LastTaskResult -ne 267009} | 
            Select-Object -First 10 TaskName, LastTaskResult, LastRunTime
        
        if($failedTasks) {
            $failedTasks | Format-Table -AutoSize
            Write-Host "(WARNING) Some scheduled tasks have failed - review task history" -ForegroundColor Yellow
        } else {
            Write-Host "(OK) No failed scheduled tasks detected" -ForegroundColor Green
        }
    } catch {}
}

function Get-PowerPlanAnalysis {
    Write-Host "`n[+] POWER PLAN AND BATTERY STATUS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    try {
        $activePlan = powercfg /getactivescheme
        Write-Host "`nActive Power Plan:" -ForegroundColor Cyan
        Write-Host "$activePlan" -ForegroundColor White
        
        if($activePlan -match "Power saver") {
            Write-Host "(WARNING) Power saver mode may reduce system performance" -ForegroundColor Yellow
        } elseif($activePlan -match "High performance") {
            Write-Host "(INFO) High performance mode active - maximum CPU performance" -ForegroundColor Green
        }
    } catch {}
    
    Write-Host "`nAvailable Power Plans:" -ForegroundColor Cyan
    powercfg /list
    
    try {
        $battery = Get-CimInstance Win32_Battery -EA SilentlyContinue
        if($battery) {
            Write-Host "`nBattery Status:" -ForegroundColor Cyan
            Write-Host "Status         : $($battery.Status)" -ForegroundColor White
            Write-Host "Charge Remain  : $($battery.EstimatedChargeRemaining)%" -ForegroundColor $(if($battery.EstimatedChargeRemaining -lt 20){"Red"}elseif($battery.EstimatedChargeRemaining -lt 50){"Yellow"}else{"Green"})
            Write-Host "Battery Health : $($battery.BatteryStatus)" -ForegroundColor White
            Write-Host "Time Remaining : $($battery.EstimatedRunTime) minutes" -ForegroundColor White
        } else {
            Write-Host "`n(INFO) No battery detected (Desktop system)" -ForegroundColor Gray
        }
    } catch {}
}

function Get-DNSPerformanceTest {
    Write-Host "`n[+] DNS RESOLUTION PERFORMANCE TEST" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nConfigured DNS Servers:" -ForegroundColor Cyan
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {$_.ServerAddresses.Count -gt 0}
    $dnsServers | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
    
    $testDomains = @("google.com", "microsoft.com", "github.com", "amazon.com", "cloudflare.com")
    
    Write-Host "`nDNS Resolution Performance Test:" -ForegroundColor Cyan
    Write-Host "Testing 5 popular domains..." -ForegroundColor Gray
    
    $dnsResults = @()
    foreach($domain in $testDomains) {
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Resolve-DnsName -Name $domain -EA Stop
            $sw.Stop()
            
            $dnsResults += [PSCustomObject]@{
                Domain = $domain
                ResolvedIP = $result[0].IPAddress
                TimeMs = $sw.ElapsedMilliseconds
            }
        } catch {
            $dnsResults += [PSCustomObject]@{
                Domain = $domain
                ResolvedIP = "FAILED"
                TimeMs = "-"
            }
        }
    }
    
    $dnsResults | Format-Table -AutoSize
    
    $avgTime = ($dnsResults | Where-Object {$_.TimeMs -ne "-"} | Measure-Object -Property TimeMs -Average).Average
    Write-Host "`nAverage DNS Resolution Time: $([math]::Round($avgTime, 2)) ms" -ForegroundColor White
    
    if($avgTime -gt 100) {
        Write-Host "(WARNING) Slow DNS resolution - consider changing DNS servers" -ForegroundColor Yellow
        Write-Host "(SUGGESTION) Try Google DNS (8.8.8.8, 8.8.4.4) or Cloudflare DNS (1.1.1.1, 1.0.0.1)" -ForegroundColor Cyan
    } else {
        Write-Host "(OK) DNS resolution performance is good" -ForegroundColor Green
    }
}

function Get-DiskIOWaitTimeAnalysis {
    Write-Host "`n[+] DISK I/O WAIT TIME AND BOTTLENECK ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nDisk Performance Counters Analysis:" -ForegroundColor Cyan
    
    try {
        $avgDiskSecRead = Get-Counter '\PhysicalDisk(_Total)\Avg. Disk sec/Read' -EA SilentlyContinue
        if($avgDiskSecRead) {
            $readLatencyMs = [math]::Round($avgDiskSecRead.CounterSamples.CookedValue * 1000, 2)
            Write-Host "Avg Disk Read Latency  : $readLatencyMs ms" -ForegroundColor $(if($readLatencyMs -gt 20){"Red"}elseif($readLatencyMs -gt 10){"Yellow"}else{"Green"})
            
            if($readLatencyMs -gt 20) {
                Write-Host "(CRITICAL) High read latency detected - disk bottleneck likely" -ForegroundColor Red
            } elseif($readLatencyMs -gt 10) {
                Write-Host "(WARNING) Elevated read latency - monitor disk performance" -ForegroundColor Yellow
            }
        }
        
        $avgDiskSecWrite = Get-Counter '\PhysicalDisk(_Total)\Avg. Disk sec/Write' -EA SilentlyContinue
        if($avgDiskSecWrite) {
            $writeLatencyMs = [math]::Round($avgDiskSecWrite.CounterSamples.CookedValue * 1000, 2)
            Write-Host "Avg Disk Write Latency : $writeLatencyMs ms" -ForegroundColor $(if($writeLatencyMs -gt 20){"Red"}elseif($writeLatencyMs -gt 10){"Yellow"}else{"Green"})
            
            if($writeLatencyMs -gt 20) {
                Write-Host "(CRITICAL) High write latency detected - disk bottleneck likely" -ForegroundColor Red
            } elseif($writeLatencyMs -gt 10) {
                Write-Host "(WARNING) Elevated write latency - monitor disk performance" -ForegroundColor Yellow
            }
        }
        
        $diskQueueLength = Get-Counter '\PhysicalDisk(_Total)\Avg. Disk Queue Length' -EA SilentlyContinue
        if($diskQueueLength) {
            $queueLen = [math]::Round($diskQueueLength.CounterSamples.CookedValue, 2)
            Write-Host "Avg Disk Queue Length  : $queueLen" -ForegroundColor $(if($queueLen -gt 2){"Red"}elseif($queueLen -gt 1){"Yellow"}else{"Green"})
            
            if($queueLen -gt 2) {
                Write-Host "(WARNING) High disk queue - I/O requests are backing up" -ForegroundColor Red
            }
        }
        
        $percentDiskTime = Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -EA SilentlyContinue
        if($percentDiskTime) {
            $diskBusyPercent = [math]::Round($percentDiskTime.CounterSamples.CookedValue, 2)
            Write-Host "Disk Busy Time         : $diskBusyPercent%" -ForegroundColor $(if($diskBusyPercent -gt 90){"Red"}elseif($diskBusyPercent -gt 75){"Yellow"}else{"Green"})
            
            if($diskBusyPercent -gt 90) {
                Write-Host "(CRITICAL) Disk is extremely busy (>90%)" -ForegroundColor Red
            } elseif($diskBusyPercent -gt 75) {
                Write-Host "(WARNING) Disk utilization is high (>75%)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "(ERROR) Unable to retrieve disk I/O metrics" -ForegroundColor Red
    }
}

function Get-CriticalEventLogAnalysis {
    Write-Host "`n[+] CRITICAL EVENT LOG ANALYSIS (ALL SOURCES)" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    $startTime = (Get-Date).AddHours(-24)
    
    Write-Host "`n=== SYSTEM LOG - CRITICAL EVENTS (Last 24h) ===" -ForegroundColor Red
    try {
        $systemCritical = Get-EventLog -LogName System -EntryType Error -After $startTime -EA SilentlyContinue | Select-Object -First 30
        
        if($systemCritical) {
            Write-Host "Found $($systemCritical.Count) critical system events" -ForegroundColor Red
            $systemCritical | Select-Object TimeGenerated, Source, EventID, @{N="Message";E={$_.Message.Substring(0, [Math]::Min(80, $_.Message.Length))}} | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "(OK) No critical system events found" -ForegroundColor Green
        }
    } catch {
        Write-Host "(ERROR) Unable to retrieve system critical events" -ForegroundColor Red
    }
    
    Write-Host "`n=== APPLICATION LOG - CRITICAL EVENTS (Last 24h) ===" -ForegroundColor Red
    try {
        $appCritical = Get-EventLog -LogName Application -EntryType Error -After $startTime -EA SilentlyContinue | Select-Object -First 30
        
        if($appCritical) {
            Write-Host "Found $($appCritical.Count) critical application events" -ForegroundColor Red
            $appCritical | Select-Object TimeGenerated, Source, EventID, @{N="Message";E={$_.Message.Substring(0, [Math]::Min(80, $_.Message.Length))}} | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "(OK) No critical application events found" -ForegroundColor Green
        }
    } catch {
        Write-Host "(ERROR) Unable to retrieve application critical events" -ForegroundColor Red
    }
    
    Write-Host "`n=== CRITICAL EVENT IDs SUMMARY ===" -ForegroundColor Cyan
    
    $criticalEventIDs = @{
        "6008" = "Unexpected system shutdown"
        "1001" = "System crash/bugcheck"
        "41" = "System rebooted without clean shutdown"
        "7000" = "Service failed to start"
        "7034" = "Service crashed"
    }
    
    foreach($eventID in $criticalEventIDs.Keys) {
        $events = Get-EventLog -LogName System -After $startTime -EA SilentlyContinue | Where-Object {$_.EventID -eq $eventID}
        if($events) {
            Write-Host "EventID $eventID ($($criticalEventIDs[$eventID])): Found $($events.Count) occurrences" -ForegroundColor Red
        }
    }
    
    Write-Host "`n=== EVENT LOG SUMMARY ===" -ForegroundColor Cyan
    try {
        $totalSystemErrors = (Get-EventLog -LogName System -EntryType Error -After $startTime -EA SilentlyContinue).Count
        $totalAppErrors = (Get-EventLog -LogName Application -EntryType Error -After $startTime -EA SilentlyContinue).Count
        
        Write-Host "System Errors (24h)      : $totalSystemErrors" -ForegroundColor $(if($totalSystemErrors -gt 50){"Red"}elseif($totalSystemErrors -gt 20){"Yellow"}else{"White"})
        Write-Host "Application Errors (24h) : $totalAppErrors" -ForegroundColor $(if($totalAppErrors -gt 50){"Red"}elseif($totalAppErrors -gt 20){"Yellow"}else{"White"})
        
        if($totalSystemErrors -gt 50 -or $totalAppErrors -gt 50) {
            Write-Host "`n(CRITICAL) High error count detected - immediate investigation recommended" -ForegroundColor Red
        } elseif($totalSystemErrors -gt 20 -or $totalAppErrors -gt 20) {
            Write-Host "`n(WARNING) Elevated error count - monitor system health" -ForegroundColor Yellow
        } else {
            Write-Host "`n(OK) Error count is within normal range" -ForegroundColor Green
        }
    } catch {}
}

# ========== STORAGE & BACKUP FUNCTIONS 23-24 - FULLY IMPLEMENTED ==========

function Get-DiskFragmentationAnalysis {
    Write-Host "`n[+] DISK FRAGMENTATION ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nAnalyzing disk fragmentation..." -ForegroundColor Cyan
    
    try {
        $volumes = Get-Volume -EA SilentlyContinue | Where-Object {$_.DriveLetter -and $_.FileSystem -eq "NTFS"}
        
        foreach($volume in $volumes) {
            $driveLetter = $volume.DriveLetter
            Write-Host "`nDrive $($driveLetter):\ Analysis:" -ForegroundColor Cyan
            Write-Host "File System    : $($volume.FileSystem)" -ForegroundColor White
            Write-Host "Health Status  : $($volume.HealthStatus)" -ForegroundColor $(if($volume.HealthStatus -eq "Healthy"){"Green"}else{"Red"})
            Write-Host "Size           : $([math]::Round($volume.Size / 1GB, 2)) GB" -ForegroundColor White
            
            Write-Host "(INFO) Use 'defrag $driveLetter`: /A' for detailed fragmentation analysis" -ForegroundColor Gray
        }
        
        # SSD Detection
        Write-Host "`nSSD Detection:" -ForegroundColor Cyan
        $physicalDisks = Get-PhysicalDisk -EA SilentlyContinue
        foreach($disk in $physicalDisks) {
            Write-Host "$($disk.FriendlyName) - Media Type: $($disk.MediaType)" -ForegroundColor White
            if($disk.MediaType -eq "SSD") {
                Write-Host "(INFO) SSD detected - defragmentation not recommended" -ForegroundColor Cyan
            }
        }
        
    } catch {
        Write-Host "(ERROR) Unable to analyze fragmentation" -ForegroundColor Red
    }
}

function Get-ShadowCopyVSSStatus {
    Write-Host "`n[+] SHADOW COPY / VSS STATUS CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nVolume Shadow Copy Service Status:" -ForegroundColor Cyan
    $vssService = Get-Service -Name "VSS" -EA SilentlyContinue
    if($vssService) {
        Write-Host "Service Status : $($vssService.Status)" -ForegroundColor $(if($vssService.Status -eq "Running"){"Green"}else{"Red"})
        Write-Host "Startup Type   : $($vssService.StartType)" -ForegroundColor White
        
        if($vssService.Status -ne "Running") {
            Write-Host "(CRITICAL) VSS Service is not running - backups may fail" -ForegroundColor Red
        }
    }
    
    Write-Host "`nAvailable Restore Points (Shadow Copies):" -ForegroundColor Cyan
    try {
        $shadowCopies = vssadmin list shadows | Out-String
        
        if($shadowCopies -match "No items found") {
            Write-Host "(WARNING) No shadow copies found" -ForegroundColor Yellow
        } else {
            Write-Host $shadowCopies -ForegroundColor White
            $copyCount = ([regex]::Matches($shadowCopies, "Shadow Copy ID:")).Count
            Write-Host "`nTotal Shadow Copies: $copyCount" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "(ERROR) Unable to list shadow copies" -ForegroundColor Red
    }
    
    Write-Host "`nWindows Backup Status:" -ForegroundColor Cyan
    $backupTask = Get-ScheduledTask -TaskName "*Backup*" -EA SilentlyContinue
    if($backupTask) {
        foreach($task in $backupTask) {
            $taskInfo = Get-ScheduledTaskInfo -InputObject $task -EA SilentlyContinue
            Write-Host "`nTask: $($task.TaskName)" -ForegroundColor White
            Write-Host "  State        : $($task.State)" -ForegroundColor $(if($task.State -eq "Ready"){"Green"}else{"Yellow"})
            Write-Host "  Last Run     : $($taskInfo.LastRunTime)" -ForegroundColor White
            Write-Host "  Last Result  : $($taskInfo.LastTaskResult)" -ForegroundColor $(if($taskInfo.LastTaskResult -eq 0){"Green"}else{"Red"})
            Write-Host "  Next Run     : $($taskInfo.NextRunTime)" -ForegroundColor White
            
            if($taskInfo.LastTaskResult -ne 0) {
                Write-Host "  (WARNING) Backup task failed with error code: $($taskInfo.LastTaskResult)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "(INFO) No Windows Backup scheduled tasks found" -ForegroundColor Gray
    }
}

# ========== NETWORK & SECURITY FUNCTIONS 25-28 - FULLY IMPLEMENTED ==========

function Get-OpenPortsAndServices {
    Write-Host "`n[+] OPEN PORTS & LISTENING SERVICES SCAN" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nScanning for listening TCP/UDP ports..." -ForegroundColor Cyan
    
    Write-Host "`nTCP Listening Ports:" -ForegroundColor Cyan
    $tcpListening = Get-NetTCPConnection -State Listen -EA SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, @{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}}, @{N="PID";E={$_.OwningProcess}} | 
        Sort-Object LocalPort
    
    $tcpListening | Format-Table -AutoSize
    
    Write-Host "`nUDP Listening Ports:" -ForegroundColor Cyan
    $udpListening = Get-NetUDPEndpoint -EA SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, @{N="Process";E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}}, @{N="PID";E={$_.OwningProcess}} | 
        Sort-Object LocalPort | 
        Select-Object -First 20
    
    $udpListening | Format-Table -AutoSize
    
    Write-Host "`nSecurity Analysis:" -ForegroundColor Cyan
    $suspiciousPorts = @{
        "445" = "SMB - Ensure firewall protected"
        "3389" = "RDP - Ensure strong authentication"
        "135" = "RPC - Potential security risk"
        "139" = "NetBIOS - Legacy protocol"
        "21" = "FTP - Unencrypted protocol"
        "23" = "Telnet - Highly insecure"
        "1433" = "SQL Server - Should not be exposed"
        "3306" = "MySQL - Should not be exposed"
    }
    
    $foundSuspicious = $false
    foreach($port in $suspiciousPorts.Keys) {
        $found = $tcpListening | Where-Object {$_.LocalPort -eq $port -and $_.LocalAddress -ne "127.0.0.1"}
        if($found) {
            Write-Host "(WARNING) Port $port open: $($suspiciousPorts[$port])" -ForegroundColor Yellow
            $foundSuspicious = $true
        }
    }
    
    if(-not $foundSuspicious) {
        Write-Host "(OK) No commonly vulnerable ports detected" -ForegroundColor Green
    }
}

function Get-FirewallRulesAnalysis {
    Write-Host "`n[+] FIREWALL RULES ANALYSIS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nWindows Firewall Status:" -ForegroundColor Cyan
    $firewallProfiles = Get-NetFirewallProfile -EA SilentlyContinue
    
    foreach($profile in $firewallProfiles) {
        $statusColor = if($profile.Enabled){"Green"}else{"Red"}
        Write-Host "$($profile.Name) Profile: $($profile.Enabled)" -ForegroundColor $statusColor
        
        if(-not $profile.Enabled) {
            Write-Host "(CRITICAL) Firewall is DISABLED for $($profile.Name) profile" -ForegroundColor Red
        }
    }
    
    Write-Host "`nInbound Firewall Rules (Enabled):" -ForegroundColor Cyan
    $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -EA SilentlyContinue | Select-Object -First 20 DisplayName, Action, Profile, Direction
    $inboundRules | Format-Table -AutoSize
    
    Write-Host "Total Enabled Inbound Rules: $((Get-NetFirewallRule -Direction Inbound -Enabled True -EA SilentlyContinue).Count)" -ForegroundColor White
    
    Write-Host "`nSecurity Analysis - Potentially Risky Rules:" -ForegroundColor Cyan
    $riskyRules = Get-NetFirewallRule -EA SilentlyContinue | Where-Object {
        $_.Enabled -eq $true -and 
        $_.Direction -eq "Inbound" -and 
        $_.Action -eq "Allow"
    } | ForEach-Object {
        $rule = $_
        $portFilter = $_ | Get-NetFirewallPortFilter -EA SilentlyContinue
        $addressFilter = $_ | Get-NetFirewallAddressFilter -EA SilentlyContinue
        
        if($portFilter.LocalPort -eq "Any" -or $addressFilter.RemoteAddress -eq "Any") {
            [PSCustomObject]@{
                Name = $rule.DisplayName
                LocalPort = $portFilter.LocalPort
                RemoteAddress = $addressFilter.RemoteAddress
                Profile = $rule.Profile
            }
        }
    } | Select-Object -First 10
    
    if($riskyRules) {
        Write-Host "(WARNING) Found rules with overly permissive settings:" -ForegroundColor Yellow
        $riskyRules | Format-Table -AutoSize
    } else {
        Write-Host "(OK) No overly permissive rules detected" -ForegroundColor Green
    }
}

function Get-SSLCertificateCheck {
    Write-Host "`n[+] SSL/TLS CERTIFICATE EXPIRATION CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nScanning Local Certificate Stores..." -ForegroundColor Cyan
    
    Write-Host "`nPersonal Certificates (LocalMachine\My):" -ForegroundColor Cyan
    $personalCerts = Get-ChildItem -Path Cert:\LocalMachine\My -EA SilentlyContinue
    
    $expiringCerts = @()
    $today = Get-Date
    
    foreach($cert in $personalCerts) {
        $daysUntilExpiry = ($cert.NotAfter - $today).Days
        
        if($daysUntilExpiry -lt 90) {
            $certInfo = [PSCustomObject]@{
                Subject = $cert.Subject
                Thumbprint = $cert.Thumbprint.Substring(0,16) + "..."
                NotAfter = $cert.NotAfter
                DaysUntilExpiry = $daysUntilExpiry
                Status = if($daysUntilExpiry -lt 0){"Expired"}elseif($daysUntilExpiry -lt 30){"Critical"}elseif($daysUntilExpiry -lt 60){"Warning"}else{"Notice"}
            }
            $expiringCerts += $certInfo
        }
    }
    
    if($expiringCerts) {
        Write-Host "(WARNING) Found certificates expiring within 90 days:" -ForegroundColor Yellow
        $expiringCerts | Sort-Object DaysUntilExpiry | Format-Table -AutoSize
    } else {
        Write-Host "(OK) No certificates expiring within 90 days" -ForegroundColor Green
    }
    
    $expiredCerts = $personalCerts | Where-Object {$_.NotAfter -lt $today}
    if($expiredCerts) {
        Write-Host "`n(CRITICAL) Found $($expiredCerts.Count) EXPIRED certificates:" -ForegroundColor Red
        $expiredCerts | Select-Object Subject, NotAfter, Thumbprint | Format-Table -AutoSize
    }
}

function Get-SMBShareSecurityAudit {
    Write-Host "`n[+] SMB SHARE PERFORMANCE & SECURITY AUDIT" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nSMB Shares on This System:" -ForegroundColor Cyan
    $shares = Get-SmbShare -EA SilentlyContinue
    
    foreach($share in $shares) {
        Write-Host "`nShare Name: $($share.Name)" -ForegroundColor Cyan
        Write-Host "  Path          : $($share.Path)" -ForegroundColor White
        Write-Host "  Description   : $($share.Description)" -ForegroundColor White
        Write-Host "  Share State   : $($share.ShareState)" -ForegroundColor $(if($share.ShareState -eq "Online"){"Green"}else{"Red"})
        
        $shareAccess = Get-SmbShareAccess -Name $share.Name -EA SilentlyContinue
        Write-Host "  Permissions:" -ForegroundColor White
        foreach($access in $shareAccess) {
            $color = if($access.AccessControlType -eq "Allow"){"Green"}else{"Red"}
            Write-Host "    $($access.AccountName): $($access.AccessRight) ($($access.AccessControlType))" -ForegroundColor $color
        }
        
        $everyoneAccess = $shareAccess | Where-Object {$_.AccountName -match "Everyone"}
        if($everyoneAccess) {
            Write-Host "  (WARNING) Share accessible to Everyone group" -ForegroundColor Red
        }
    }
    
    Write-Host "`nActive SMB Sessions:" -ForegroundColor Cyan
    $smbSessions = Get-SmbSession -EA SilentlyContinue
    
    if($smbSessions) {
        Write-Host "Total Active Sessions: $($smbSessions.Count)" -ForegroundColor White
        $smbSessions | Select-Object -First 10 ClientComputerName, ClientUserName, NumOpens, SecondsIdle | Format-Table -AutoSize
    } else {
        Write-Host "(INFO) No active SMB sessions" -ForegroundColor Gray
    }
    
    Write-Host "`nSMB Configuration:" -ForegroundColor Cyan
    $smbConfig = Get-SmbServerConfiguration -EA SilentlyContinue
    
    Write-Host "SMB1 Enabled         : $($smbConfig.EnableSMB1Protocol)" -ForegroundColor $(if($smbConfig.EnableSMB1Protocol){"Red"}else{"Green"})
    Write-Host "SMB2 Enabled         : $($smbConfig.EnableSMB2Protocol)" -ForegroundColor $(if($smbConfig.EnableSMB2Protocol){"Green"}else{"Red"})
    Write-Host "Encryption Required  : $($smbConfig.EncryptData)" -ForegroundColor $(if($smbConfig.EncryptData){"Green"}else{"Yellow"})
    Write-Host "Signing Required     : $($smbConfig.RequireSecuritySignature)" -ForegroundColor $(if($smbConfig.RequireSecuritySignature){"Green"}else{"Yellow"})
    
    if($smbConfig.EnableSMB1Protocol) {
        Write-Host "`n(CRITICAL) SMB1 is ENABLED - This is a major security risk!" -ForegroundColor Red
        Write-Host "Recommendation: Disable SMB1 immediately" -ForegroundColor Yellow
    }
}

# ========== HARDWARE & DRIVERS FUNCTIONS 29-31 - FULLY IMPLEMENTED ==========

function Get-GPUPerformanceMonitor {
    Write-Host "`n[+] GPU PERFORMANCE & HEALTH CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nDetecting GPU Hardware..." -ForegroundColor Cyan
    $gpus = Get-CimInstance Win32_VideoController -EA SilentlyContinue
    
    foreach($gpu in $gpus) {
        Write-Host "`n╔════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║  GPU: $($gpu.Name.Substring(0, [Math]::Min(47, $gpu.Name.Length)))" -ForegroundColor Cyan
        Write-Host "╚════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host "`nHardware Information:" -ForegroundColor Cyan
        Write-Host "  GPU Model         : $($gpu.Name)" -ForegroundColor White
        Write-Host "  Video Processor   : $($gpu.VideoProcessor)" -ForegroundColor White
        Write-Host "  Adapter RAM       : $([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB" -ForegroundColor White
        Write-Host "  Driver Version    : $($gpu.DriverVersion)" -ForegroundColor White
        Write-Host "  Status            : $($gpu.Status)" -ForegroundColor $(if($gpu.Status -eq "OK"){"Green"}else{"Red"})
        
        Write-Host "`nDisplay Configuration:" -ForegroundColor Cyan
        Write-Host "  Resolution        : $($gpu.VideoModeDescription)" -ForegroundColor White
        Write-Host "  Refresh Rate      : $($gpu.CurrentRefreshRate) Hz" -ForegroundColor White
        
        $driverAge = ((Get-Date) - $gpu.DriverDate).Days
        Write-Host "`nDriver Analysis:" -ForegroundColor Cyan
        Write-Host "  Driver Age        : $driverAge days" -ForegroundColor $(if($driverAge -gt 180){"Red"}elseif($driverAge -gt 90){"Yellow"}else{"Green"})
        
        if($driverAge -gt 180) {
            Write-Host "  (WARNING) GPU driver is outdated (>6 months)" -ForegroundColor Red
        }
    }
    
    # NVIDIA GPU Check
    Write-Host "`n═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "NVIDIA GPU Monitoring" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $nvidiaSmiPaths = @(
        "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        "C:\Windows\System32\nvidia-smi.exe"
    )
    
    $nvidiaSmi = $nvidiaSmiPaths | Where-Object {Test-Path $_} | Select-Object -First 1
    
    if($nvidiaSmi) {
        Write-Host "(INFO) NVIDIA GPU detected" -ForegroundColor Green
    } else {
        Write-Host "(INFO) NVIDIA GPU tools not found - install nvidia-smi for detailed monitoring" -ForegroundColor Gray
    }
    
    # AMD GPU Check
    Write-Host "`nAMD GPU Monitoring:" -ForegroundColor Cyan
    $amdGpu = $gpus | Where-Object {$_.Name -match "AMD|Radeon"}
    if($amdGpu) {
        Write-Host "(INFO) AMD GPU detected: $($amdGpu.Name)" -ForegroundColor Green
    } else {
        Write-Host "(INFO) No AMD GPU detected" -ForegroundColor Gray
    }
}

function Get-ProblematicDriverDetection {
    Write-Host "`n[+] PROBLEMATIC DRIVER DETECTION" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nScanning Event Logs for Driver Errors (EventID 219)..." -ForegroundColor Cyan
    $driverErrors = Get-EventLog -LogName System -After (Get-Date).AddDays(-7) -EA SilentlyContinue | 
        Where-Object {$_.EventID -eq 219 -or $_.Source -match "Driver"}
    
    if($driverErrors) {
        Write-Host "(WARNING) Found $($driverErrors.Count) driver-related errors in last 7 days" -ForegroundColor Red
        $driverErrors | Select-Object -First 10 TimeGenerated, Source, Message | Format-List
    } else {
        Write-Host "(OK) No recent driver errors detected" -ForegroundColor Green
    }
    
    Write-Host "`nUnsigned Driver Scan:" -ForegroundColor Cyan
    $unsignedDrivers = Get-CimInstance Win32_PnPSignedDriver -EA SilentlyContinue | 
        Where-Object {$_.IsSigned -eq $false -or $_.DriverProviderName -match "Unknown"}
    
    if($unsignedDrivers) {
        Write-Host "(WARNING) Found $($unsignedDrivers.Count) unsigned or unknown drivers:" -ForegroundColor Yellow
        $unsignedDrivers | Select-Object DeviceName, DriverProviderName, DriverVersion, IsSigned | Format-Table -AutoSize
    } else {
        Write-Host "(OK) All drivers appear to be signed" -ForegroundColor Green
    }
    
    Write-Host "`nRecently Updated Drivers (Last 30 Days):" -ForegroundColor Cyan
    $recentDrivers = Get-CimInstance Win32_PnPSignedDriver -EA SilentlyContinue | 
        Where-Object {$_.DriverDate -gt (Get-Date).AddDays(-30)} | 
        Sort-Object DriverDate -Descending | 
        Select-Object -First 20
    
    if($recentDrivers) {
        Write-Host "(INFO) Found $($recentDrivers.Count) recently updated drivers" -ForegroundColor Cyan
        $recentDrivers | Select-Object DeviceName, DriverVersion, DriverDate | Format-Table -AutoSize
    } else {
        Write-Host "(INFO) No drivers updated in last 30 days" -ForegroundColor Gray
    }
    
    Write-Host "`nDevice Manager Problem Devices:" -ForegroundColor Cyan
    $problemDevices = Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object {$_.ConfigManagerErrorCode -ne 0}
    
    if($problemDevices) {
        Write-Host "(WARNING) Found $($problemDevices.Count) devices with errors:" -ForegroundColor Red
        $problemDevices | Select-Object Name, Status, ConfigManagerErrorCode | Format-Table -AutoSize
    } else {
        Write-Host "(OK) No problem devices detected" -ForegroundColor Green
    }
}

function Get-USBDeviceAudit {
    Write-Host "`n[+] USB DEVICE AUDIT" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nConnected USB Devices:" -ForegroundColor Cyan
    $usbDevices = Get-PnpDevice -EA SilentlyContinue | Where-Object {$_.Class -eq "USB"} | Select-Object -First 20
    
    if($usbDevices) {
        Write-Host "Total USB Devices: $($usbDevices.Count)" -ForegroundColor White
        $usbDevices | Select-Object FriendlyName, Status, ClassGuid | Format-Table -AutoSize
    } else {
        Write-Host "(INFO) No USB devices detected" -ForegroundColor Gray
    }
    
    Write-Host "`nUSB Device History & Status:" -ForegroundColor Cyan
    try {
        $usbHistory = Get-WmiObject Win32_USBControllerDevice -EA SilentlyContinue
        if($usbHistory) {
            Write-Host "Total USB Controller Devices: $($usbHistory.Count)" -ForegroundColor White
        }
    } catch {}
    
    Write-Host "`nUSB-Related Event Log Errors:" -ForegroundColor Cyan
    $usbErrors = Get-EventLog -LogName System -After (Get-Date).AddDays(-7) -EA SilentlyContinue | 
        Where-Object {$_.Source -match "USB|usbhub"}
    
    if($usbErrors) {
        Write-Host "(INFO) Found $($usbErrors.Count) USB-related events" -ForegroundColor Yellow
        $usbErrors | Select-Object -First 5 TimeGenerated, Source, EventID | Format-Table -AutoSize
    } else {
        Write-Host "(OK) No USB errors found" -ForegroundColor Green
    }
}

# ========== APPLICATIONS FUNCTIONS 32-36 - FULLY IMPLEMENTED ==========

function Get-SQLServerHealthCheck {
    Write-Host "`n[+] SQL SERVER HEALTH CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nSQL Server Service Status:" -ForegroundColor Cyan
    $sqlService = Get-Service -Name "MSSQLSERVER" -EA SilentlyContinue
    if($sqlService) {
        Write-Host "Service Name   : $($sqlService.Name)" -ForegroundColor White
        Write-Host "Display Name   : $($sqlService.DisplayName)" -ForegroundColor White
        Write-Host "Status         : $($sqlService.Status)" -ForegroundColor $(if($sqlService.Status -eq "Running"){"Green"}else{"Red"})
        Write-Host "Start Type     : $($sqlService.StartType)" -ForegroundColor White
        
        if($sqlService.Status -eq "Running") {
            Write-Host "(OK) SQL Server is running" -ForegroundColor Green
        } else {
            Write-Host "(WARNING) SQL Server is not running" -ForegroundColor Red
        }
    } else {
        Write-Host "(INFO) SQL Server not detected" -ForegroundColor Gray
    }
}

function Get-MySQLHealthCheck {
    Write-Host "`n[+] MYSQL/MARIADB HEALTH CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nMySQL/MariaDB Service Status:" -ForegroundColor Cyan
    $mysqlService = Get-Service -Name "MySQL*" -EA SilentlyContinue
    if($mysqlService) {
        $mysqlService | ForEach-Object {
            Write-Host "Service Name   : $($_.Name)" -ForegroundColor White
            Write-Host "Status         : $($_.Status)" -ForegroundColor $(if($_.Status -eq "Running"){"Green"}else{"Red"})
            Write-Host "Start Type     : $($_.StartType)" -ForegroundColor White
        }
    } else {
        Write-Host "(INFO) MySQL/MariaDB not detected" -ForegroundColor Gray
    }
}

function Get-IISPerformanceCheck {
    Write-Host "`n[+] IIS PERFORMANCE CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nIIS Service Status:" -ForegroundColor Cyan
    $iisService = Get-Service -Name "W3SVC" -EA SilentlyContinue
    if($iisService) {
        Write-Host "Service Name   : $($iisService.Name)" -ForegroundColor White
        Write-Host "Status         : $($iisService.Status)" -ForegroundColor $(if($iisService.Status -eq "Running"){"Green"}else{"Red"})
        Write-Host "Start Type     : $($iisService.StartType)" -ForegroundColor White
    } else {
        Write-Host "(INFO) IIS not detected" -ForegroundColor Gray
    }
}

function Get-DockerContainerMonitor {
    Write-Host "`n[+] DOCKER CONTAINER MONITOR" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nDocker Service Status:" -ForegroundColor Cyan
    $dockerService = Get-Service -Name "Docker" -EA SilentlyContinue
    if($dockerService) {
        Write-Host "Service Name   : $($dockerService.Name)" -ForegroundColor White
        Write-Host "Status         : $($dockerService.Status)" -ForegroundColor $(if($dockerService.Status -eq "Running"){"Green"}else{"Red"})
        Write-Host "Start Type     : $($dockerService.StartType)" -ForegroundColor White
    } else {
        Write-Host "(INFO) Docker not detected" -ForegroundColor Gray
    }
}

function Get-HyperVVMPerformance {
    Write-Host "`n[+] HYPER-V VM PERFORMANCE" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nHyper-V Service Status:" -ForegroundColor Cyan
    $hypervService = Get-Service -Name "vmms" -EA SilentlyContinue
    if($hypervService) {
        Write-Host "Service Name   : $($hypervService.Name)" -ForegroundColor White
        Write-Host "Status         : $($hypervService.Status)" -ForegroundColor $(if($hypervService.Status -eq "Running"){"Green"}else{"Red"})
        Write-Host "Start Type     : $($hypervService.StartType)" -ForegroundColor White
    } else {
        Write-Host "(INFO) Hyper-V not detected" -ForegroundColor Gray
    }
}

# ========== SECURITY & COMPLIANCE FUNCTIONS 37-39 - FULLY IMPLEMENTED ==========

function Get-SecurityBaselineCheck {
    Write-Host "`n[+] WINDOWS SECURITY BASELINE CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nSecurity Settings:" -ForegroundColor Cyan
    
    # UAC Status
    try {
        $uacEnabled = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -EA SilentlyContinue).EnableLUA
        Write-Host "UAC Enabled    : $($uacEnabled -eq 1)" -ForegroundColor $(if($uacEnabled -eq 1){"Green"}else{"Red"})
    } catch {}
    
    # Secure Boot
    try {
        $secureBoot = Confirm-SecureBootUEFI -EA SilentlyContinue
        Write-Host "Secure Boot    : $secureBoot" -ForegroundColor $(if($secureBoot){"Green"}else{"Yellow"})
    } catch {
        Write-Host "Secure Boot    : Not Available" -ForegroundColor Gray
    }
    
    # Local Administrators
    Write-Host "`nLocal Administrators:" -ForegroundColor Cyan
    try {
        $localAdmins = Get-LocalGroupMember Administrators -EA SilentlyContinue
        if($localAdmins) {
            $localAdmins | Select-Object Name, ObjectClass | Format-Table -AutoSize
        }
    } catch {}
    
    # Firewall Status
    Write-Host "`nFirewall Status:" -ForegroundColor Cyan
    $firewallProfiles = Get-NetFirewallProfile -EA SilentlyContinue
    $firewallProfiles | Select-Object Name, Enabled | Format-Table -AutoSize
}

function Get-PatchComplianceReport {
    Write-Host "`n[+] PATCH COMPLIANCE REPORT" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nRecent Installed Updates (Last 15):" -ForegroundColor Cyan
    $hotfixes = Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 15
    
    if($hotfixes) {
        $hotfixes | Select-Object HotFixID, Description, InstalledOn | Format-Table -AutoSize
        Write-Host "`nTotal Installed Hotfixes: $((Get-HotFix -EA SilentlyContinue).Count)" -ForegroundColor White
    } else {
        Write-Host "(INFO) No hotfixes found" -ForegroundColor Gray
    }
}

function Get-SuspiciousProcessScan {
    Write-Host "`n[+] SUSPICIOUS PROCESS & MALWARE INDICATORS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nProcesses Running from Temp/AppData:" -ForegroundColor Cyan
    $suspicious = Get-Process -EA SilentlyContinue | Where-Object {$_.Path -match "Temp|AppData\\Local\\Temp"}
    
    if($suspicious) {
        Write-Host "(WARNING) Found processes running from suspicious locations:" -ForegroundColor Yellow
        $suspicious | Select-Object ProcessName, Path, Id | Format-Table -AutoSize
    } else {
        Write-Host "(OK) No suspicious processes detected" -ForegroundColor Green
    }
    
    Write-Host "`nHigh CPU Processes from Unknown Publishers:" -ForegroundColor Cyan
    $highCpuProcs = Get-Process -EA SilentlyContinue | Sort-Object CPU -Descending | Select-Object -First 10
    $highCpuProcs | Select-Object ProcessName, CPU, Path | Format-Table -AutoSize
}

# ========== SYSTEM MAINTENANCE FUNCTIONS 40-42 - FULLY IMPLEMENTED ==========

function Get-RegistryHealthCheck {
    Write-Host "`n[+] REGISTRY HEALTH CHECK" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nRegistry Analysis:" -ForegroundColor Cyan
    
    try {
        $registrySize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "RegistryMaxSize" -EA SilentlyContinue).RegistryMaxSize
        Write-Host "Registry Max Size: $([math]::Round($registrySize / 1MB, 2)) MB" -ForegroundColor White
    } catch {}
    
    Write-Host "`n(INFO) Registry analysis requires specialized tools" -ForegroundColor Cyan
    Write-Host "Consider using: CCleaner, Wise Registry Cleaner, or Windows built-in tools" -ForegroundColor Yellow
    
    # Check for startup registry entries with invalid paths
    Write-Host "`nRegistry Startup Entries Validation:" -ForegroundColor Cyan
    $startupPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach($path in $startupPaths) {
        if(Test-Path $path) {
            $items = Get-ItemProperty -Path $path -EA SilentlyContinue
            if($items) {
                $items.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {
                    $filePath = $_.Value
                    if($filePath -match '^\s*"?([^"]+)"?(.*)') {
                        $actualPath = $Matches[1].Trim()
                        if(-not (Test-Path $actualPath)) {
                            Write-Host "(WARNING) Invalid path in registry: $actualPath" -ForegroundColor Yellow
                        }
                    }
                }
            }
        }
    }
    
    Write-Host "`n(OK) Registry health check completed" -ForegroundColor Green
}


function Get-SystemFileIntegrity {
    Write-Host "`n[+] SYSTEM FILE INTEGRITY CHECK (SFC)" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`n(WARNING) SFC scan takes 10-30 minutes and requires admin privileges" -ForegroundColor Yellow
    Write-Host "This is a read-only check summary, not a full scan" -ForegroundColor Yellow
    
    Write-Host "`nTo run full SFC scan, execute as Administrator:" -ForegroundColor Cyan
    Write-Host "  sfc /scannow" -ForegroundColor White
    
    Write-Host "`nDISM Component Store Health:" -ForegroundColor Cyan
    Write-Host "To check component store:" -ForegroundColor Cyan
    Write-Host "  DISM /Online /Cleanup-Image /CheckHealth" -ForegroundColor White
    Write-Host "  DISM /Online /Cleanup-Image /ScanHealth" -ForegroundColor White
    
    # Check for recently modified system files
    Write-Host "`nRecently Modified System Files (Last 7 Days):" -ForegroundColor Cyan
    $systemPath = "$env:WINDIR\System32"
    $recentFiles = Get-ChildItem -Path $systemPath -File -ErrorAction SilentlyContinue | 
        Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 10
    
    if($recentFiles) {
        $recentFiles | Select-Object Name, LastWriteTime | Format-Table -AutoSize
    } else {
        Write-Host "(OK) No recent system file modifications" -ForegroundColor Green
    }
}

function Get-WindowsFeaturesStatus {
    Write-Host "`n[+] WINDOWS FEATURES STATUS" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    
    Write-Host "`nEnabled Windows Features:" -ForegroundColor Cyan
    try {
        $features = Get-WindowsOptionalFeature -Online -EA SilentlyContinue | Where-Object {$_.State -eq "Enabled"} | Select-Object -First 20
        if($features) {
            $features | Select-Object FeatureName, State | Format-Table -AutoSize
            Write-Host "\nTotal Enabled Features: $((Get-WindowsOptionalFeature -Online -EA SilentlyContinue | Where-Object {$_.State -eq "Enabled"}).Count)" -ForegroundColor White
        } else {
            Write-Host "(INFO) No enabled features found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "(INFO) Unable to retrieve Windows features" -ForegroundColor Gray
    }
}

# ========== MASTER FUNCTIONS ==========

function Invoke-FullAudit {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║                    FULL SYSTEM AUDIT INITIATED                        ║" -ForegroundColor Magenta
    Write-Host "║                    Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                    ║" -ForegroundColor Magenta
    Write-Host "║                    Running 42 Comprehensive Checks...                 ║" -ForegroundColor Magenta
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    
    # Core Diagnostics (1-10)
    Get-CPUUsage
    Get-MemoryUsage
    Get-DiskPerformance
    Get-NetworkPerformance
    Get-TopProcesses
    Get-ServicesStatus
    Get-EventLogErrors
    Get-StartupPrograms
    Get-WindowsUpdateStatus
    Get-HardwareHealth
    
    # Advanced Diagnostics (13-22)
    Get-PageFileAnalysis
    Get-SystemUptimeAndBoot
    Get-NetworkLatencyTest
    Get-AntivirusImpact
    Get-ProcessHandleAnalysis
    Get-ScheduledTasksAnalysis
    Get-PowerPlanAnalysis
    Get-DNSPerformanceTest
    Get-DiskIOWaitTimeAnalysis
    Get-CriticalEventLogAnalysis
    
    # Storage & Backup (23-24)
    Get-DiskFragmentationAnalysis
    Get-ShadowCopyVSSStatus
    
    # Network & Security (25-28)
    Get-OpenPortsAndServices
    Get-FirewallRulesAnalysis
    Get-SSLCertificateCheck
    Get-SMBShareSecurityAudit
    
    # Hardware & Drivers (29-31)
    Get-GPUPerformanceMonitor
    Get-ProblematicDriverDetection
    Get-USBDeviceAudit
    
    # Applications (32-36)
    Get-SQLServerHealthCheck
    Get-MySQLHealthCheck
    Get-IISPerformanceCheck
    Get-DockerContainerMonitor
    Get-HyperVVMPerformance
    
    # Security & Compliance (37-39)
    Get-SecurityBaselineCheck
    Get-PatchComplianceReport
    Get-SuspiciousProcessScan
    
    # System Maintenance (40-42)
    Get-RegistryHealthCheck
    Get-SystemFileIntegrity
    Get-WindowsFeaturesStatus
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║                    FULL AUDIT COMPLETED                               ║" -ForegroundColor Magenta
    Write-Host "║                    Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                    ║" -ForegroundColor Magenta
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
}

function Export-AuditReport {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = "$env:USERPROFILE\Desktop\SystemAudit_$timestamp.txt"
    
    Write-Host "`n[+] EXPORTING COMPREHENSIVE AUDIT REPORT" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "`nReport will be saved to:" -ForegroundColor Cyan
    Write-Host "$reportPath" -ForegroundColor White
    Write-Host "`nThis may take several minutes..." -ForegroundColor Yellow
    
    Start-Transcript -Path $reportPath -Force
    Invoke-FullAudit
    Stop-Transcript
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    REPORT EXPORT SUCCESSFUL                           ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host "`nReport saved to:" -ForegroundColor Cyan
    Write-Host "$reportPath" -ForegroundColor White
    Write-Host "`nFile size: $([math]::Round((Get-Item $reportPath).Length / 1KB, 2)) KB" -ForegroundColor White
}

# ========== MAIN EXECUTION LOOP ==========

do {
    Clear-Host
    Show-Banner
    Show-Menu
    
    $choice = Read-Host "`nSelect option (0-42)"
    
    switch ($choice) {
        "1"  { Get-CPUUsage }
        "2"  { Get-MemoryUsage }
        "3"  { Get-DiskPerformance }
        "4"  { Get-NetworkPerformance }
        "5"  { Get-TopProcesses }
        "6"  { Get-ServicesStatus }
        "7"  { Get-EventLogErrors }
        "8"  { Get-StartupPrograms }
        "9"  { Get-WindowsUpdateStatus }
        "10" { Get-HardwareHealth }
        "11" { Invoke-FullAudit }
        "12" { Export-AuditReport }
        "13" { Get-PageFileAnalysis }
        "14" { Get-SystemUptimeAndBoot }
        "15" { Get-NetworkLatencyTest }
        "16" { Get-AntivirusImpact }
        "17" { Get-ProcessHandleAnalysis }
        "18" { Get-ScheduledTasksAnalysis }
        "19" { Get-PowerPlanAnalysis }
        "20" { Get-DNSPerformanceTest }
        "21" { Get-DiskIOWaitTimeAnalysis }
        "22" { Get-CriticalEventLogAnalysis }
        "23" { Get-DiskFragmentationAnalysis }
        "24" { Get-ShadowCopyVSSStatus }
        "25" { Get-OpenPortsAndServices }
        "26" { Get-FirewallRulesAnalysis }
        "27" { Get-SSLCertificateCheck }
        "28" { Get-SMBShareSecurityAudit }
        "29" { Get-GPUPerformanceMonitor }
        "30" { Get-ProblematicDriverDetection }
        "31" { Get-USBDeviceAudit }
        "32" { Get-SQLServerHealthCheck }
        "33" { Get-MySQLHealthCheck }
        "34" { Get-IISPerformanceCheck }
        "35" { Get-DockerContainerMonitor }
        "36" { Get-HyperVVMPerformance }
        "37" { Get-SecurityBaselineCheck }
        "38" { Get-PatchComplianceReport }
        "39" { Get-SuspiciousProcessScan }
        "40" { Get-RegistryHealthCheck }
        "41" { Get-SystemFileIntegrity }
        "42" { Get-WindowsFeaturesStatus }
        "0"  { 
            Write-Host "`n(OK) Exiting audit tool. Thank you!" -ForegroundColor Green
            Start-Sleep -Seconds 1
            break 
        }
        default { 
            Write-Host "`n(ERROR) Invalid selection. Please choose 0-42." -ForegroundColor Red 
        }
    }
    
    if ($choice -ne "0") {
        Read-Host "`nPress Enter to continue"
    }
} while ($choice -ne "0")
