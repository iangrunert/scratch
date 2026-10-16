@echo off
REM MSVC build. Run from a Developer Command Prompt (x64 Native Tools).
REM _CRT_SECURE_NO_WARNINGS only silences the CRT deprecation noise; the code
REM bounds every copy it makes.

setlocal
set CFLAGS=/nologo /W4 /O2 /D_CRT_SECURE_NO_WARNINGS

cl %CFLAGS% schantest.c /link secur32.lib crypt32.lib ws2_32.lib advapi32.lib
if errorlevel 1 goto :fail

cl %CFLAGS% runrestricted.c childio.c /link advapi32.lib
if errorlevel 1 goto :fail

cl %CFLAGS% runappcontainer.c childio.c /link userenv.lib advapi32.lib ole32.lib
if errorlevel 1 goto :fail

echo.
echo Built schantest.exe, runrestricted.exe and runappcontainer.exe
goto :eof

:fail
echo.
echo Build failed.
exit /b 1
