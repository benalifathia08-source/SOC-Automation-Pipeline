@echo off
rem soc-disable-account.cmd: the file Wazuh runs (as SYSTEM) for the "soc-disable-account" command.
rem The request arrives on stdin and is passed on to the PowerShell script next to this file.
rem No -ExecutionPolicy flag: the domain GPO already allows local scripts (RemoteSigned).
powershell.exe -NoProfile -NonInteractive -File "%~dp0soc-disable-account.ps1"
