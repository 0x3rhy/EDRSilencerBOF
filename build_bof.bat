@echo off
set BOFNAME="EDRSilencer"
set PLAT="x86"
set STRIP="i686-w64-mingw32-strip"
IF "%Platform%"=="x64" set PLAT="x64"
IF "%Platform%"=="x64" set STRIP="x86_64-w64-mingw32-strip"

cl.exe /nologo /Os /D BOF /MT /W0 /GS- /c %BOFNAME%.c /Fo%BOFNAME%.%PLAT%.o
%STRIP% --strip-unneeded %BOFNAME%.%PLAT%.o
