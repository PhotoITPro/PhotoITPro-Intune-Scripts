@echo off
rem Launches Rob's Toolkit (RobsToolkit.ps1) from the same folder as this batch file.
rem   No arguments  -> opens the GUI
rem   Any arguments -> passed straight through (command-line mode), e.g.
rem                    Run-RobsToolkit.bat -Preset Stability -Quick -Label AfterReboot
rem                    Run-RobsToolkit.bat -ListChecks
rem                    Run-RobsToolkit.bat -Version

set "SCRIPT=%~dp0RobsToolkit.ps1"
if not exist "%SCRIPT%" (
    echo Cannot find "%SCRIPT%"
    pause
    exit /b 1
)

rem -STA is required for the WPF GUI. Execution policy is bypassed for this process only.
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%SCRIPT%" %*
set "RC=%ERRORLEVEL%"

rem Keep the window open if something went wrong.
if not "%RC%"=="0" pause
exit /b %RC%
