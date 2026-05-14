@echo off
echo TinyLoad v4.0
echo ------------
echo Building...
g++ -o TinyLoad.exe TinyLoad.cpp -static -O2 -s
if %errorlevel% equ 0 (
    echo Build successful!!
) else (
    echo Build failed. Make sure you have MinGW g++ installed.
)
pause
