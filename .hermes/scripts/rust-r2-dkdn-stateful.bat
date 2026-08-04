@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-dkdn-stateful"
set "EXE=%INTEROP_DIR%\rust-r2-dkdn-stateful.exe"
set "OBJ=%INTEROP_DIR%\DkdnStatefulInterop.obj"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :missing_toolchain
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL goto :missing_toolchain
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%BUILD_DIR%\CMakeCache.txt" goto :missing_build
cmake --build "%BUILD_DIR%" --target client server -j 2
if not "!ERRORLEVEL!"=="0" goto :failed
if exist "%INTEROP_DIR%" rmdir /s /q "%INTEROP_DIR%"
if exist "%INTEROP_DIR%" goto :failed
mkdir "%INTEROP_DIR%"
if not exist "%INTEROP_DIR%" goto :failed

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\DkdnStatefulInterop.cpp" /Fo"%OBJ%" /Fe"%EXE%" "%BUILD_DIR%\src\lib\client\client.lib" "%BUILD_DIR%\src\lib\server\server.lib" "%BUILD_DIR%\src\lib\net\net.lib" "%BUILD_DIR%\src\lib\platform\platform.lib" "%BUILD_DIR%\src\lib\mt\mt.lib" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libssl.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-dkdn-stateful.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%EXE%" goto :missing_binary

"%EXE%"
if not "!ERRORLEVEL!"=="0" goto :failed
echo RUST_R2_DKDN_STATEFUL_PASS exact_exit_handling=PASS exclusive_outputs=PASS
popd
exit /b 0

:missing_toolchain
echo ERROR: MSVC x64 toolchain not found 1>&2
popd
exit /b 1
:missing_build
echo ERROR: build tree missing: %BUILD_DIR% 1>&2
popd
exit /b 1
:missing_binary
echo ERROR: compiler returned success without output binary 1>&2
popd
exit /b 1
:failed
set "RESULT=!ERRORLEVEL!"
if "!RESULT!"=="0" set "RESULT=1"
popd
exit /b !RESULT!
