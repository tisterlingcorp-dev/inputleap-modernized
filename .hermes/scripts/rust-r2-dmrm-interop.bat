@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1
set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-dmrm-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-dmrm-interop.exe"
set "FIXTURE=%INTEROP_DIR%\dmrm-boundary-fixture.bin"
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
cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\DmrmInterop.cpp" /Fo"%INTEROP_DIR%\DmrmInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-dmrm-interop.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" fixture-frame -32768 32767 "%FIXTURE%"
if not "!ERRORLEVEL!"=="0" goto :failed
for %%V in (-32768 -1 0 1 32767) do (
    set "X=%%V"
    set "Y=%%V"
    set "CPP_BYTES=%INTEROP_DIR%\cpp-!X!-!Y!.bin"
    set "RUST_BYTES=%INTEROP_DIR%\rust-!X!-!Y!.bin"
    "%CPP_EXE%" emit-frame !X! !Y! "!CPP_BYTES!"
    if not "!ERRORLEVEL!"=="0" goto :failed
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example dmrm_interop -- decode-frame !X! !Y! "!CPP_BYTES!"
    if not "!ERRORLEVEL!"=="0" goto :failed
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example dmrm_interop -- encode-frame !X! !Y! "!RUST_BYTES!"
    if not "!ERRORLEVEL!"=="0" goto :failed
    "%CPP_EXE%" decode-frame !X! !Y! "!RUST_BYTES!"
    if not "!ERRORLEVEL!"=="0" goto :failed
    fc /b "!CPP_BYTES!" "!RUST_BYTES!" >nul
    if not "!ERRORLEVEL!"=="0" goto :failed
)
if not "!ERRORLEVEL!"=="0" goto :failed
python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-dmrm-manifest.py"
if not "!ERRORLEVEL!"=="0" goto :failed
echo RUST_R2_DMRM_INTEROP_PASS cpp_protocolutil=PASS cpp_packetstreamfilter=PASS cpp_to_rust_decode=PASS rust_to_cpp_encode=PASS signed_i16_boundaries=PASS exclusive_outputs=PASS exact_exit_handling=PASS manifest=PASS dmwm=EXCLUDED
popd
exit /b 0
:missing
echo rust-r2-dmrm-interop: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2
:missing_build
echo rust-r2-dmrm-interop: expected existing build tree at "%BUILD_DIR%" 1>&2
popd
exit /b 2
:failed
set "RESULT=!ERRORLEVEL!"
if "!RESULT!"=="0" set "RESULT=1"
popd
exit /b !RESULT!
