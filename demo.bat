@echo off
rem JOCKY demo launcher - runs the demo with NATIVE Git Bash on Windows
rem (not WSL), so the Windows-specific EDR sensor analysis runs live.
rem Falls back to WSL only if Git Bash is not installed.
setlocal
set "ROOT=%~dp0"
set "GITBASH=C:\Program Files\Git\bin\bash.exe"

if exist "%GITBASH%" goto have_gitbash

rem Git Bash not found - try WSL as a last resort.
wsl bash.exe -c "cd '%ROOT:\=/%' && bash demo.sh fast"
goto done

:have_gitbash
pushd "%ROOT%"
"%GITBASH%" demo.sh fast
set "RC=%ERRORLEVEL%"
popd

:done
if not "%RC%"=="0" if errorlevel 1 (
  echo.
  echo Demo did not finish 10/10 - see the stage output above.
  pause
)
endlocal
exit /b %RC%