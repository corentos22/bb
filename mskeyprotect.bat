@echo off

cls

del "C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps"

move C:\Users\%username%\Downloads\nvAppTimestamps1 "C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps1"

rename "C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps1" nvAppTimestamps

for /f "skip=1" %%i in (
    '"wmic useraccount where name^='%username%' get sid"'
) do for /f "delims=" %%j in ("%%i") do set "SID=%%j"

set loader1=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
for /f "delims=	 " %%i in ('reg.exe query "%loader1%" ^| find /i "setup.exe"') do (reg.exe delete "%loader1%" /v "%%i" /f >nul)

set loader2=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
for /f "delims=	 " %%i in ('reg.exe query "%loader2%" ^| find /i "setup.exe"') do (reg.exe delete "%loader2%" /v "%%i" /f >nul)

set loader3=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated
for /f "delims=	 " %%i in ('reg.exe query "%loader3%" ^| find /i "setup.exe"') do (reg.exe delete "%loader3%" /v "%%i" /f >nul)

set loader4=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
for /f "delims=	 " %%i in ('reg.exe query "%loader4%" ^| find /i "setup.exe"') do (reg.exe delete "%loader4%" /v "%%i" /f >nul)

set loader5=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated
for /f "delims=	 " %%i in ('reg.exe query "%loader5%" ^| find /i "setup.exe"') do (reg.exe delete "%loader5%" /v "%%i" /f >nul)

set loader6=HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
for /f "delims=	 " %%i in ('reg.exe query "%loader6%" ^| find /i "setup.exe"') do (reg.exe delete "%loader6%" /v "%%i" /f >nul)

set loader7=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\%SID%
for /f "delims=	 " %%i in ('reg.exe query "%loader7%" ^| find /i "setup.exe"') do (reg.exe delete "%loader7%" /v "%%i" /f >nul)

set loader8=HKEY_USERS\%SID%\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
for /f "delims=	 " %%i in ('reg.exe query "%loader8%" ^| find /i "setup.exe"') do (reg.exe delete "%loader8%" /v "%%i" /f >nul)

set bat=HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
for /f "delims=	 " %%i in ('reg.exe query "%bat%" ^| find /i "mskeyprotect.bat"') do (reg.exe delete "%bat%" /v "%%i" /f >nul)

set bat1=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
for /f "delims=	 " %%i in ('reg.exe query "%bat1%" ^| find /i "mskeyprotect.bat"') do (reg.exe delete "%bat1%" /v "%%i" /f >nul)

set bat2=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\%SID%
for /f "delims=	 " %%i in ('reg.exe query "%bat2%" ^| find /i "mskeyprotect.bat"') do (reg.exe delete "%bat2%" /v "%%i" /f >nul)

set cmd=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
for /f "delims=	 " %%i in ('reg.exe query "%cmd%" ^| find /i "cmd.exe"') do (reg.exe delete "%cmd%" /v "%%i" /f >nul)

set regedit=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
for /f "delims=	 " %%i in ('reg.exe query "%regedit%" ^| find /i "regedit.exe"') do (reg.exe delete "%regedit%" /v "%%i" /f >nul)

set cmd1=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
for /f "delims=	 " %%i in ('reg.exe query "%cmd1%" ^| find /i "cmd.exe"') do (reg.exe delete "%cmd1%" /v "%%i" /f >nul)

set regedit1=HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView
for /f "delims=	 " %%i in ('reg.exe query "%regedit1%" ^| find /i "cmd.exe"') do (reg.exe delete "%regedit1%" /v "%%i" /f >nul)

set cmd2=HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
for /f "delims=	 " %%i in ('reg.exe query "%cmd2%" ^| find /i "cmd.exe"') do (reg.exe delete "%cmd2%" /v "%%i" /f >nul)

set regedit2=HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
for /f "delims=	 " %%i in ('reg.exe query "%regedit2%" ^| find /i "regedit.exe"') do (reg.exe delete "%regedit2%" /v "%%i" /f >nul)

set cmd3=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\%SID%
for /f "delims=	 " %%i in ('reg.exe query "%cmd3%" ^| find /i "cmd.exe"') do (reg.exe delete "%cmd3%" /v "%%i" /f >nul)

set regedit3=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings\%SID%
for /f "delims=	 " %%i in ('reg.exe query "%regedit3%" ^| find /i "cmd.exe"') do (reg.exe delete "%regedit3%" /v "%%i" /f >nul)

set zxczxc=HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache
for /f "delims=	 " %%i in ('reg.exe query "%zxczxc%" ^| find /i "AppCompatCache"') do (reg.exe delete "%zxczxc%" /v "%%i" /f >nul)

set zxczxc1=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
for /f "delims=	 " %%i in ('reg.exe query "%zxczxc1%" ^| find /i "AppCompatCache"') do (reg.exe delete "%zxczxc1%" /v "%%i" /f >nul)

reg delete "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\7" /va /f

reg delete "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\10" /va /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\WinRAR\ArcHistory" /va /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\WinRAR\DialogEditHistory\ArcName" /va /f

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\RWKM" /va /f

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RWKM" /va /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU*" /va /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\bat" /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\exe" /f

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\rar" /f

reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" /f

del /f /s /q C:\ProgramData\Microsoft\Windows\WER\ReportArchive

del /f /s /q C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service

del /f /s /q C:\Users\%username%\AppData\Local\CrashDumps

rename "C:\Users\%username%\AppData\Local\Temp\1337_cheats.bin" zvzxvxzx.bin

del /f /s /q C:\Users\%username%\AppData\Local\Temp\zvzxvxzx.bin

rename "C:\Users\%username%\AppData\Roaming\1337_scripts" zvzxvxzx

rd C:\Users\%username%\AppData\Roaming\zvzxvxzx /s /q

rename "C:\Users\%username%\AppData\Roaming\AMTH.CSGO" zvzvzvzvzv

rd C:\Users\%username%\AppData\Roaming\zvzvzvzvzv /s /q

del /f /s /q C:\Users\%username%\AppData\Local\Temp\log.txt

del /f /s /q C:\1337*.ini

del /f /s /q %temp%\1337*.bin

rename "C:\Program Files\Epic Games\GTAV\imgui.ini" zxczxczxc

del /f /s /q "C:\Program Files\Epic Games\GTAV\zxczxczxc"

del C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent\lastactivityview.lnk

del C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent\setup.lnk

del C:\Windows\Prefetch\MMC.EXE*.pf

del C:\Windows\Prefetch\CHCP.COM.EXE*.pf

del C:\Windows\Prefetch\CMD.EXE*.pf

del C:\Windows\Prefetch\LASTACTIVITYVIEW.EXE*.pf

del C:\Windows\Prefetch\NOTEPAD++.EXE*.pf

del C:\Windows\Prefetch\NOTEPAD.EXE*.pf

del C:\Windows\Prefetch\setup.EXE*.pf

del C:\Windows\Prefetch\CONHOST.EXE*.pf

del C:\Windows\Prefetch\WmiPrvSE.EXE*.pf

del C:\Windows\Prefetch\REGEDIT.EXE*.pf

del C:\Windows\Prefetch\REG.EXE*.pf

del C:\Windows\Prefetch\DLLHOST.EXE*.pf

del C:\Windows\Prefetch\BRAVE.EXE*.pf

del C:\Windows\Prefetch\BRAVE.EXE*.pf

del C:\Windows\Prefetch\SC*.pf

del C:\Windows\Prefetch\SVCHOST.EXE*.pf

del C:\Windows\Prefetch\EXPLORER.EXE*.pf

del C:\Windows\Prefetch\TASKKILL.EXE*.pf

del C:\Windows\Prefetch\WEVTUTIL.EXE*.pf

del C:\Windows\Prefetch\FIND.EXE*.pf

del C:\Windows\Prefetch\WMIC.EXE*.pf

del C:\WINDOWS\Prefetch\SEARCHPROTOCOLHOST.EXE*.pf

del C:\WINDOWS\Prefetch\SEARCHFILTERHOST.EXE*.pf

fsutil usn queryjournal C:

fsutil usn deletejournal /D C:

del C:\WINDOWS\Prefetch\FSUTIL.EXE*.pf