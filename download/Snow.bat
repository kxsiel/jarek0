@echo off
title Snow
color 8
mode 98,20
set version=v2.4

REM Checking for Admin Perms - Requesting them if not
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' ( goto UACPrompt ) else ( goto Start )
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:Start
cls
echo        SSSSSSSSSSSSSSS
echo      SS:::::::::::::::S
echo     S:::::SSSSSS::::::S
echo    S:::::S     SSSSSSS
echo     S:::::S          nnnn  nnnnnnnn       ooooooooooo wwwwwww           wwwww           wwwwwww
echo     S:::::S          n:::nn::::::::nn   oo:::::::::::oow:::::w         w:::::w         w:::::w
echo      S::::SSSS       n::::::::::::::nn o:::::::::::::::ow:::::w       w:::::::w       w:::::w
echo       SS::::::SSSSS  nn:::::::::::::::no:::::ooooo:::::o w:::::w     w:::::::::w     w:::::w
echo         SSS::::::::SS  n:::::nnnn:::::no::::o     o::::o  w:::::w   w:::::w:::::w   w:::::w
echo            SSSSSS::::S n::::n    n::::no::::o     o::::o   w:::::w w:::::w w:::::w w:::::w
echo                 S:::::Sn::::n    n::::no::::o     o::::o    w:::::w:::::w   w:::::w:::::w
echo                 S:::::Sn::::n    n::::no::::o     o::::o     w:::::::::w     w:::::::::w
echo     SSSSSSS     S:::::Sn::::n    n::::no:::::ooooo:::::o      w:::::::w       w:::::::w
echo     S::::::SSSSSS:::::Sn::::n    n::::no:::::::::::::::o       w:::::w         w:::::w
echo     S:::::::::::::::SS n::::n    n::::n oo:::::::::::oo         w:::w           w:::w
echo      SSSSSSSSSSSSSSS   nnnnnn    nnnnnn   ooooooooooo            www             www      %version%
echo.
echo                                     [Enter] Optimize
set /p=

cls
echo        SSSSSSSSSSSSSSS
echo      SS:::::::::::::::S
echo     S:::::SSSSSS::::::S
echo    S:::::S     SSSSSSS
echo     S:::::S          nnnn  nnnnnnnn       ooooooooooo wwwwwww           wwwww           wwwwwww
echo     S:::::S          n:::nn::::::::nn   oo:::::::::::oow:::::w         w:::::w         w:::::w
echo      S::::SSSS       n::::::::::::::nn o:::::::::::::::ow:::::w       w:::::::w       w:::::w
echo       SS::::::SSSSS  nn:::::::::::::::no:::::ooooo:::::o w:::::w     w:::::::::w     w:::::w
echo         SSS::::::::SS  n:::::nnnn:::::no::::o     o::::o  w:::::w   w:::::w:::::w   w:::::w
echo            SSSSSS::::S n::::n    n::::no::::o     o::::o   w:::::w w:::::w w:::::w w:::::w
echo                 S:::::Sn::::n    n::::no::::o     o::::o    w:::::w:::::w   w:::::w:::::w
echo                 S:::::Sn::::n    n::::no::::o     o::::o     w:::::::::w     w:::::::::w
echo     SSSSSSS     S:::::Sn::::n    n::::no:::::ooooo:::::o      w:::::::w       w:::::::w
echo     S::::::SSSSSS:::::Sn::::n    n::::no:::::::::::::::o       w:::::w         w:::::w
echo     S:::::::::::::::SS n::::n    n::::n oo:::::::::::oo         w:::w           w:::w
echo      SSSSSSSSSSSSSSS   nnnnnn    nnnnnn   ooooooooooo            www             www      %version%
echo.
echo                                Optimizing your PC [...]

:Create Restore Point
echo                                Creating Restore Point [...]
wmic /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Before Snow", 100, 12 >nul 2>&1

:Remove Windows UWP Apps
echo                                Removing UWP Apps [...]
Powershell -Command "Get-AppxPackage Microsoft.Microsoft3DViewer | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *alarms* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *calculator* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *camera* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *Microsoft.GetHelp* -AllUsers | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *zunemusic* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *communications* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *maps* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *solitairecollection* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage Microsoft.MixedReality.Portal | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage Microsoft.MSPaint | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage people | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *soundrecorder* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppXPackage *Microsoft.WindowsMaps* | Remove-AppXPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage *bingweather* | Remove-AppxPackage" >nul 2>&1
PowerShell -Command "Get-AppxPackage *yourphone* | Remove-AppxPackage" >nul 2>&1
Powershell -Command "Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage" >nul 2>&1

:Disable Hibernation
echo                                Disabling Hibernation [...]
powercfg -h off >nul 2>&1

:Disable Automatic Maintenance
echo                                Disabling Automatic Maintenance [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v MaintenanceDisabled /t Reg_DWORD /d 1 /f >nul 2>&1

:Power Plan
echo                                Importing ggOS Power Plan [...]
powershell Invoke-WebRequest "https://cdn.discordapp.com/attachments/813079232467959819/864959995636613121/ggOS-0.8.13.pow" -OutFile "%temp%\ggOS-0.8.13.pow" >nul 2>&1
powercfg -delete 88888888-8888-8888-8888-888888888888 >nul 2>&1
powercfg -import "%temp%\ggOS-0.8.13.pow" 88888888-8888-8888-8888-888888888888 >nul 2>&1
powercfg /setactive 88888888-8888-8888-8888-888888888888 >nul 2>&1

:Disable Power Throttling
echo                                Disabling Power Throttling [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t Reg_DWORD /d 1 /f >nul 2>&1

:Win32PrioritySeparation
echo                                Changing Win32PrioritySeparation [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t Reg_DWORD /d 38 /f >nul 2>&1

:BCDEdit
echo                                Applying BCDEdit [...]
bcdedit /set linearaddress57 OptOut >nul 2>&1
bcdedit /set increaseuserva 268435328 >nul 2>&1
bcdedit /set firstmegabytepolicy UseAll >nul 2>&1
bcdedit /set avoidlowmemory 0x8000000 >nul 2>&1
bcdedit /set nolowmem Yes >nul 2>&1
bcdedit /set allowedinmemorysettings 0x0 >nul 2>&1
bcdedit /set isolatedcontext No >nul 2>&1
bcdedit /set vsmlaunchtype Off >nul 2>&1
bcdedit /set vm No >nul 2>&1
bcdedit /set x2apicpolicy Enable >nul 2>&1
bcdedit /set configaccesspolicy Default >nul 2>&1
bcdedit /set MSI Default >nul 2>&1
bcdedit /set usephysicaldestination No >nul 2>&1
bcdedit /set usefirmwarepcisettings No >nul 2>&1
bcdedit /deletevalue useplatformclock >nul 2>&1
bcdedit /deletevalue disabledynamictick >nul 2>&1
bcdedit /set useplatformtick Yes >nul 2>&1
bcdedit /set tscsyncpolicy Enhanced >nul 2>&1
bcdedit /set disableelamdrivers Yes >nul 2>&1
bcdedit /timeout 0 >nul 2>&1
bcdedit /set uselegacyapicmode yes >nul 2>&1
bcdedit /set bootux disabled >nul 2>&1
bcdedit /set bootmenupolicy standard >nul 2>&1
bcdedit /set hypervisorlaunchtype off >nul 2>&1
bcdedit /set tpmbootentropy ForceDisable >nul 2>&1
bcdedit /set quietboot yes >nul 2>&1
bcdedit /set linearaddress57 OptOut >nul 2>&1
bcdedit /set increaseuserva 268435328 >nul 2>&1
bcdedit /debug Off
bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS  >nul 2>&1
bcdedit /set nointergritychecks On  >nul 2>&1
bcdedit /set bootlog No  >nul 2>&1

:Pagefile
echo                                Pagefile [...]
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False >nul 2>&1
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=32768,MaximumSize=32768 >nul 2>&1

:Powershell Tweaks
echo                                Melody's Powershell Tweaks [...]
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >nul 2>&1
powershell "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" >nul 2>&1
powershell "Disable-MMAgent -MemoryCompression" >nul 2>&1
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue" >nul 2>&1

:Registry Tweaks
echo                                Melody's Registry Tweaks [...]
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /v DisableExternalDMAUnderLock /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired  /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KernelSEHOPEnabled /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v EnableCfg /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 4 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 3 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DpiMapIommuContiguous /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PreferSystemMemoryContiguous /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001" /v PreferSystemMemoryContiguous /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d Experimental /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request"  /t REG_SZ /d Allowed /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 16 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 16 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatencyCheckEnabled /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride/t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleMonitorOff /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleNoContext /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleShortTime /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleVeryLongTime /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle0 /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle0MonitorOff /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle1 /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle1MonitorOff /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceMemory /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceNoContext /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceNoContextMonitorOff /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceOther /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceTimerPeriod /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultMemoryRefreshLatencyToleranceActivelyUsed /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultMemoryRefreshLatencyToleranceMonitorOff /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultMemoryRefreshLatencyToleranceNoContext /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MaxIAverageGraphicsLatencyInOneBucket /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MiracastPerfTrackGraphicsLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v TransitionLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v VerboseStatus /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableRoutinelyTakingAction /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v ServiceKeepAlive /t REG_DWORD /d 0 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f >nul 2>&1

:Check for GPU
echo                                Checking GPU Brand [...]
for /f "tokens=* skip=1" %%n in ('wmic path win32_VideoController get name ^| findstr "."') do set GPU_NAME=%%n >nul 2>&1
set GPU_NAME=%GPU_NAME: =%
if not "%GPU_NAME:GeForce=%" == "%GPU_NAME%" goto :NVIDIA
if not "%GPU_NAME:NVIDIA=%" == "%GPU_NAME%" goto :NVIDIA
if not "%GPU_NAME:AMD=%" == "%GPU_NAME%" goto :AMD
goto Disable Spectre and Meltdown

:NVIDIA
echo                                Enabling Gamemode [...]
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t Reg_DWORD /d 1 /f >nul 2>&1
echo                                Applying NVIDIA Registry Tweaks [..]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v D3PCLatency /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v F1TransitionLatency /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LOWLATENCY /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v Node3DLowLatency /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PciLatencyTimerControl /t Reg_DWORD /d 32 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMDeepL1EntryLatencyUsec /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcMaxFtuS /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcMinFtuS /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcPerioduS /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrEiIdleThresholdUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrGrIdleThresholdUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrGrRgIdleThresholdUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrMsIdleThresholdUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectFlipDPCDelayUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectFlipTimingMarginUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectJITFlipMsHybridFlipDelayUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v vrrCursorMarginUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v vrrDeflickerMarginUs /t Reg_DWORD /d 1 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v vrrDeflickerMaxUs /t Reg_DWORD /d 1 /f >nul 2>&1
echo                                Unhiding Silk Smoothness [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID61684 /t Reg_DWORD /d 1 /f >nul 2>&1

:AMD
echo                                Disabling Gamemode [...]
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AllowAutoGameMode /t Reg_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled /t Reg_DWORD /d 0 /f >nul 2>&1
echo                                Applying AMD Registry Tweaks [...]
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRSnoopL1Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRSnoopL0Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRMaxNoSnoopLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v KMD_RpmComputeLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalUrgentLatencyNs /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v memClockSwitchLatency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_RTPMComputeF1Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_DGBMMMaxTransitionLatencyUvd /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_DGBPMMaxTransitionLatencyGfx /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalNBLatencyForUnderFlow /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalDramClockChangeLatencyNs /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRSnoopL1Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRSnoopL0Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRNoSnoopL0Latency /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRMaxSnoopLatencyValue /t REG_DWORD /d 1 /f >nul 2>&1
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRMaxNoSnoopLatencyValue /t REG_DWORD /d 1 /f >nul 2>&1

:Disable Spectre And Meltdown
echo                                Disabling Spectre and Meltdown [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t Reg_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t Reg_DWORD /d 3 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t Reg_DWORD /d 3 /f >nul 2>&1

:System Responsiveness
echo                                System Responsiveness Registry Tweaks [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t Reg_DWORD /d 10 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t Reg_DWORD /d 14 /f >nul 2>&1

:Enable HAGS
echo                                Enabling Hardware Accelerated Scheduling [...]
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /t Reg_DWORD /d 2 /f >nul 2>&1

:SetSvcHostSplitThreshold
echo                                Setting SvcHostSplitThreshold [...]
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%i >nul 2>&1
set /a ram=%mem% + 1024000 >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t Reg_DWORD /d "%ram%" /f >nul 2>&1

:Fix CPU Stock Speed
echo                                Fixing CPU Stock Speed [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm" /v Start /t Reg_DWORD /d 4 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdppm" /v Start /t Reg_DWORD /d 4 /f >nul 2>&1

:Network Tweaks
echo                                Network Tweaks [...]
netsh winsock reset catalog  >nul 2>&1
netsh int ip reset C:\resetlog.txt >nul 2>&1
netsh int ip reset C:\tcplog.txt  >nul 2>&1
netsh int tcp set supplemental Internet congestionprovider=ctcp  >nul 2>&1
netsh int tcp set heuristics disabled  >nul 2>&1
netsh int tcp set global initialRto=2000  >nul 2>&1
netsh int tcp set global autotuninglevel=normal  >nul 2>&1
netsh int tcp set global rsc=disabled  >nul 2>&1
netsh int tcp set global chimney=disabled  >nul 2>&1
netsh int tcp set global dca=enabled  >nul 2>&1
netsh int tcp set global netdma=disabled >nul 2>&1
netsh int tcp set global ecncapability=enabled  >nul 2>&1
netsh int tcp set global timestamps=disabled  >nul 2>&1
netsh int tcp set global nonsackrttresiliency=disabled  >nul 2>&1
netsh int tcp set global rss=enabled  >nul 2>&1
netsh int tcp set global MaxSynRetransmissions=2 >nul 2>&1
netsh int tcp set global autotuning=experimental >nul 2>&1
netsh int tcp set supp internet congestionprovider=newreno >nul 2>&1
netsh int udp set global uro=enabled >nul 2>&1
netsh int teredo set state natawareclient >nul 2>&1
netsh int 6to4 set state state=enabled >nul 2>&1
netsh winsock set autotuning on >nul 2>&1
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /d 1 /t Reg_DWORD /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /d 1 /t Reg_DWORD /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /d 0 /t Reg_DWORD /f >nul 2>&1
)
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "00000010" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "00000000" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "00000006" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "00000005" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "00000004" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "00000007" /f  >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "00000016" /f  >nul 2>&1
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "00000016" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "00000000" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "4294967295" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "00000001" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "00065534" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000030" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f  >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "00000001" /f  >nul 2>&1

:services
echo                                Disabling Services [...]
sc config WSearch start=disabled >nul 2>&1
sc config SysMain start=disabled >nul 2>&1

:NTFS Overhead
echo                                Reducing NTFS Overhead [...]
fsutil behavior set disablecompression 1 >nul 2>&1
fsutil behavior set disableencryption 1 >nul 2>&1
fsutil behavior set disablelastaccess 1 >nul 2>&1
fsutil behavior set encryptpagingfile 0 >nul 2>&1

:Check for WinRAR
if exist "C:\Program Files\WinRAR\winrar.exe" (
  if not exist "C:\Program Files\WinRAR\rarreg.key" (
    echo                                Removing Purchase WinRAR Popup [...]
    powershell Invoke-WebRequest "https://cdn.discordapp.com/attachments/906709401174421565/906741807268913224/rarreg.key" -OutFile "%temp%\rarreg.key" >nul 2>&1
    move "%temp%\rarreg.key" "C:\Program Files\WinRAR" >nul 2>&1
  ) else (
    goto Check for VALORANT
  )
  )
)

:Check for VALORANT
if exist "C:\Program Files\Riot Vanguard\vgc.exe" (
	echo                                Fixing VALORANT Vanguard [...]
	powershell "Set-ProcessMitigation -Name vgc.exe -Enable CFG" >nul 2>&1
	powershell "Set-ProcessMitigation -Name vgc.exe -Enable DEP" >nul 2>&1
	powershell "Set-ProcessMitigation -Name vgc.exe -Enable AuditDynamicCode" >nul 2>&1
	bcdedit /set {current} nx OptIn >nul 2>&1
) else (
	goto Disable Prefetch
)

:Disable Prefetch
echo                                Disabling Prefetch and Superfetch [...]
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t Reg_DWORD /d 0 /f >nul 2>&1
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t Reg_DWORD /d 0 /f >nul 2>&1

:Delete Temporary Files
echo                                Deleting Temporary Files [...]
del /f /q "%localappdata%\temp\*.*" >nul 2>&1
del /f /q "C:\Windows\temp\*.*" >nul 2>&1
del /f /q "C:\Windows\Prefetch\*.*" >nul 2>&1

:Finished
start "" https://discord.gg/MQtpHrx6Gm
cls
echo        SSSSSSSSSSSSSSS
echo      SS:::::::::::::::S
echo     S:::::SSSSSS::::::S
echo    S:::::S     SSSSSSS
echo     S:::::S          nnnn  nnnnnnnn       ooooooooooo wwwwwww           wwwww           wwwwwww
echo     S:::::S          n:::nn::::::::nn   oo:::::::::::oow:::::w         w:::::w         w:::::w
echo      S::::SSSS       n::::::::::::::nn o:::::::::::::::ow:::::w       w:::::::w       w:::::w
echo       SS::::::SSSSS  nn:::::::::::::::no:::::ooooo:::::o w:::::w     w:::::::::w     w:::::w
echo         SSS::::::::SS  n:::::nnnn:::::no::::o     o::::o  w:::::w   w:::::w:::::w   w:::::w
echo            SSSSSS::::S n::::n    n::::no::::o     o::::o   w:::::w w:::::w w:::::w w:::::w
echo                 S:::::Sn::::n    n::::no::::o     o::::o    w:::::w:::::w   w:::::w:::::w
echo                 S:::::Sn::::n    n::::no::::o     o::::o     w:::::::::w     w:::::::::w
echo     SSSSSSS     S:::::Sn::::n    n::::no:::::ooooo:::::o      w:::::::w       w:::::::w
echo     S::::::SSSSSS:::::Sn::::n    n::::no:::::::::::::::o       w:::::w         w:::::w
echo     S:::::::::::::::SS n::::n    n::::n oo:::::::::::oo         w:::w           w:::w
echo      SSSSSSSSSSSSSSS   nnnnnn    nnnnnn   ooooooooooo            www             www      %version%
echo.
echo                                    The optimizer has finished
echo                                 Press Enter to Restart your Computer
set /p=
shutdown -t 0 -r -f
