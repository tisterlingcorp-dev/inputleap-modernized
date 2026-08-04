@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1
set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-dkup-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-dkup-interop.exe"
set "FIXTURE=%INTEROP_DIR%\dkup-boundary-fixture.bin"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :missing
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL goto :missing
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%BUILD_DIR%\CMakeCache.txt" goto :missing_build
if exist "%INTEROP_DIR%" rmdir /s /q "%INTEROP_DIR%"
if exist "%INTEROP_DIR%" goto :failed
mkdir "%INTEROP_DIR%"
if not exist "%INTEROP_DIR%" goto :failed
cmake --build "%BUILD_DIR%" --target protocol-fixture-emitter -j 2
if not "!ERRORLEVEL!"=="0" goto :failed
cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\DkupInterop.cpp" /Fo"%INTEROP_DIR%\DkupInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-dkup-interop.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" fixture-frame 4660 32769 65535 "%FIXTURE%"
if not "!ERRORLEVEL!"=="0" goto :failed
call :case 0 0 0
if not "!ERRORLEVEL!"=="0" goto :failed
call :case 1 2 3
if not "!ERRORLEVEL!"=="0" goto :failed
call :case 4660 32769 65535
if not "!ERRORLEVEL!"=="0" goto :failed
call :case 65535 65535 65535
if not "!ERRORLEVEL!"=="0" goto :failed
python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-dkup-manifest.py"
if not "!ERRORLEVEL!"=="0" goto :failed
echo RUST_R2_DKUP_INTEROP_PASS cpp_protocolutil=PASS cpp_packetstreamfilter=PASS cpp_to_rust_decode=PASS rust_to_cpp_encode=PASS unsigned_u16_boundaries=PASS exclusive_outputs=PASS exact_exit_handling=PASS manifest=PASS
popd
exit /b 0
:case
set "KEY_ID=%~1"
set "MODIFIER_MASK=%~2"
set "BUTTON=%~3"
set "CPP_BYTES=%INTEROP_DIR%\cpp-%KEY_ID%-%MODIFIER_MASK%-%BUTTON%.bin"
set "RUST_BYTES=%INTEROP_DIR%\rust-%KEY_ID%-%MODIFIER_MASK%-%BUTTON%.bin"
"%CPP_EXE%" emit-frame %KEY_ID% %MODIFIER_MASK% %BUTTON% "%CPP_BYTES%"
if not "!ERRORLEVEL!"=="0" exit /b !ERRORLEVEL!
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example dkup_interop -- decode-frame %KEY_ID% %MODIFIER_MASK% %BUTTON% "%CPP_BYTES%"
if not "!ERRORLEVEL!"=="0" exit /b !ERRORLEVEL!
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example dkup_interop -- encode-frame %KEY_ID% %MODIFIER_MASK% %BUTTON% "%RUST_BYTES%"
if not "!ERRORLEVEL!"=="0" exit /b !ERRORLEVEL!
"%CPP_EXE%" decode-frame %KEY_ID% %MODIFIER_MASK% %BUTTON% "%RUST_BYTES%"
if not "!ERRORLEVEL!"=="0" exit /b !ERRORLEVEL!
fc /b "%CPP_BYTES%" "%RUST_BYTES%" >nul
if not "!ERRORLEVEL!"=="0" exit /b 1
exit /b 0
:missing
echo rust-r2-dkup-interop: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2
:missing_build
echo rust-r2-dkup-interop: expected existing build tree at "%BUILD_DIR%" 1>&2
popd
exit /b 2
:failed
set "RESULT=!ERRORLEVEL!"
if "!RESULT!"=="0" set "RESULT=1"
popd
exit /b !RESULT!
