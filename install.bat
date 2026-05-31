@echo off
setlocal EnableDelayedExpansion
:: NetScanner v1.3 — Windows Installer
:: Yönetici olarak çalıştır (sağ tıkla → Yönetici olarak çalıştır)

echo.
echo   ╔══════════════════════════════════════╗
echo   ║   NetScanner v1.3 — Windows Setup   ║
echo   ╚══════════════════════════════════════╝
echo.

:: Yönetici yetkisi kontrolü
net session >nul 2>&1
if errorlevel 1 (
    echo [!] Yonetici yetkisi gerekli.
    echo [!] Bu dosyaya sag tikla → "Yonetici olarak calistir"
    pause
    exit /b 1
)

:: Python kontrolü
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python bulunamadi.
    echo [!] https://python.org adresinden Python 3.8+ yukleyin.
    echo [!] Kurulum sirasinda "Add Python to PATH" secenegini isaretleyin.
    pause
    exit /b 1
)

:: Kurulum dizini
set "DEST=%ProgramFiles%\NetScanner"
echo [*] Dosyalar kopyalaniyor: %DEST%
if not exist "%DEST%" mkdir "%DEST%"
xcopy /E /I /Y "%~dp0." "%DEST%\" >nul

:: netscanner.bat wrapper — System32'ye yaz (her zaman PATH'te)
set "WRAPPER=%SystemRoot%\System32\netscanner.bat"
echo [*] Komut olusturuluyor: netscanner

(
echo @echo off
echo python "%DEST%\main.py" %%*
) > "%WRAPPER%"

:: Çalışıp çalışmadığını test et
netscanner --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo [!] Komut testi basarisiz. Manuel PATH ekleniyor...
    :: Kullanıcı PATH'ine de ekle
    for /f "tokens=2*" %%A in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "UPATH=%%B"
    if not "!UPATH!"=="" (
        echo !UPATH! | findstr /I "%DEST%" >nul || (
            setx PATH "!UPATH!;%DEST%" >nul
        )
    ) else (
        setx PATH "%DEST%" >nul
    )
    echo [*] PATH guncellendi. Yeni terminal acip tekrar deneyin.
) else (
    echo [*] Komut testi basarili.
)

echo.
echo   ====================================================
echo   Kurulum tamamlandi!
echo.
echo   Kullanim ^(yeni CMD / PowerShell ac^):
echo     netscanner                    menu/GUI
echo     netscanner 192.168.1.1        hizli tarama
echo     netscanner 192.168.1.1 -A     agresif tarama
echo     netscanner 192.168.1.1 -p web -oH rapor.html
echo     netscanner --help             yardim
echo   ====================================================
echo.
pause
