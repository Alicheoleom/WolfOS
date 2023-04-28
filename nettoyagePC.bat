
@Echo 

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0" 


@echo off

:: Fichiers Temp et Prefetch supprimés
del /s /f /q %userprofile%\Recent\*.*
del /s /f /q C:\Windows\Prefetch\*.*
del /s /f /q C:\Windows\Temp\*.*
del /s /f /q %USERPROFILE%\appdata\local\temp\*.*
:: Corbeille vidée
rd /s /q %SYSTEMDRIVE%\$Recycle.bin
:: Logs Windows supprimées
cd/
del *.log /a /s /q /f
:: Cache DNS vidée
ipconfig /flushdns
:: Nettoyage de disque
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Content Indexer Cleaner" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Microsoft_Event_Reporting_2.0_Temp_Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Remote Desktop Cache Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\ServicePack Cleanup" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" /v StateFlags0777  /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Sync Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\WebClient and WebPublisher Cache" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /v StateFlags0777 /d 2 /t REG_DWORD /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Archive Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Queue Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f    
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Archive Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Queue Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files" /v StateFlags0777 /t REG_DWORD /d 00000002 /f
cleanmgr /sagerun:777
:: DeviceCleanup
powershell Invoke-WebRequest "https://cdn.discordapp.com/attachments/858096985524142130/993219850216423526/DeviceCleanupCmd.exe" -OutFile "%temp%\DeviceCleanupCmd.exe
cd %temp%
DeviceCleanupCmd * -s
timeout 3 
cls
:: AdwCleaner
powershell Invoke-WebRequest "https://cdn.discordapp.com/attachments/858096985524142130/1001484690227744800/adwcleaner.exe" -OutFile "%temp%\adwcleaner.exe
cd %temp% 
adwcleaner /eula /clean /noreboot
timeout 3 
del /s /f /q %USERPROFILE%\appdata\local\temp\*.*
cls
:: Verification Windows 10
sfc /scannow
cls


:: Fichier Log nettoyage 

del *.log /a /s /q /f

:: Nettoyage de tout les fichier inutile de windows 

ipconfig/release                  
ipconfig/renew                   
ipconfig/flushdns                 
ipconfig /registerdns           
arp -d                                  
Nbtstat -R                         
Nbtstat -RR
del /f /q /s %systemdrive%\*.old
del /f /s /q %systemdrive%\*._mp
del /f /q /s %systemdrive%\*.bak
del /f /q /s %systemdrive%\*.log
del /f /q /s %systemdrive%\*.tmp
del /f /q /s %systemdrive%\*.chk
del /f /s /q %systemdrive%\*.gid
del /f /q /s %systemdrive%\RECYCLER\*.*
del /f /q /s %WinDir%\Temp\*.*
del /f /q /s %WinDir%\Prefetch\*.*
del /f /q /s %WinDir%\Driver Cache\i386\*.*
del /f /q /s %WinDir%\system32\dllcache\*.*
del /f /q /s %WinDir%$hf_mig$\*.*
del /f /q /s %WinDir%\Driver Cache\*.*ll
del /f /q /s %WinDir%\addins\*.*
del /f /q /s %WinDir%\LastGood\*.*
del /f /q /s %WinDir%\Offline Web Pages\*.*
del /f /q /s %WinDir%$NtServicePackUninstall$\*.*
del /f /q /s %WinDir%\Provisioning\*.*
del /f /q /s %WinDir%\ServicePackFiles\*.*
del /f /q /s %WinDir%\Web klasörü\*.*
del /f /q /s %WinDir%\Connection Wizard\*.*
del /f /q /s %WinDir%\EHome\*.*
del /f /q /s %WinDir%\Assembly\*.*
del /f /q /s %WinDir%\SoftwareDistribution\Download\*.*
del /f /q /s %WinDir%\mui\*.*
del /f /q /s %WinDir%\Config\*.*
del /f /q /s %WinDir%\msapps\*.*
del /f /s /q %winDir%\*.bak
del /f /q /s %userprofile%\AppData/Local/Temp\*.*
del /f /s /q %windir%\prefetch\*.*


