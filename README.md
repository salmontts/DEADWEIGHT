# DEADWEIGHT - Windows Cleaner

Basic Usage (For Everyone)

    🚀 Download the latest deadweight.exe

    🖱️ Run (double-click)

    🔘 Click CLEAN

    ☕ Wait for completion (typically 1-3 minutes)

## The program automatically performs:

    ✔️ Temporary files cleanup (%TEMP%, Prefetch)

    ✔️ Removal of unnecessary startup entries

    ✔️ Logging all operations to deadweight.log

## 🔧 Advanced Section
💻 Command Line Mode (CMD/PowerShell)
cmd

    # Full system cleanup (requires admin)
    deadweight.exe --purge
    
    # Folder scan (default: 30+ days unused)
    deadweight.exe --scan "C:\Program Files" [DAYS]
    
    # Real-time process monitoring
    deadweight.exe --live 60
    
    # Detailed process analysis
    deadweight.exe --lupa chrome.exe
    
    # Generate full report
    deadweight.exe --report > report.txt

🛠️ Advanced Features
cmd

    # Aggressive cleaning (warning!):
    deadweight.exe --purge --force
    
    # Remove specific applications:
    deadweight.exe --uninstall "Adobe Flash"
    
    # Registry cleaning:
    deadweight.exe --regclean
    
    # Remove unused drivers:
    deadweight.exe --drvclean

🔍 Technical Implementation Details

The program uses:

    Low-level Windows API (Win32/Native API)

    Recursive NTFS filesystem scanning

    Direct registry access

    Prefetch and event logs analysis

    WMI for process management

📝 Example Use Cases
powershell

    # Scheduled cleaning (Task Scheduler)
    SCHTASKS /Create /SC WEEKLY /TN "Deadweight Clean" /TR "deadweight.exe --purge" /ST 23:00
    
    # PowerShell script integration:
    Invoke-DeadweightClean -Mode Deep -LogPath "C:\logs\clean.log"
    
    # Custom cleaning filters:
    deadweight.exe --custom-filter "*.tmp,*.log,~*.*"

⚠️ Security and Logs

The program generates detailed logs:

    deadweight.log - basic operations

    deadweight_purge.log - full cleaning record

    deadweight_errors.log - errors and warnings

Always check logs before deleting important data!

📌 Version: 1.3 (2025-07-29)
📜 License: MIT (full modification rights)
