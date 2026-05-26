@echo off
echo.
echo  NetScanner -- Full Release ^| Windows Installer
echo.
python --version >nul 2>&1 || (echo [!] Python not found. Get it from python.org & pause & exit /b)
set DEST=C:\netscanner
if not exist "%DEST%" mkdir "%DEST%"
xcopy /E /Y /Q "%~dp0." "%DEST%\" >nul
(echo @echo off & echo python "%DEST%\main.py" %%*) > "%DEST%\netscanner.bat"
copy /Y "%DEST%\netscanner.bat" "C:\Windows\System32\netscanner.bat" >nul 2>&1
echo  Done! Open a new CMD and type: netscanner
pause
