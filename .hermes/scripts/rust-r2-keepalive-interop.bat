@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-keepalive-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-keepalive-interop.exe"
set "STATEFUL_EXE=%INTEROP_DIR%\rust-r2-keepalive-stateful.exe"
set "FIXTURE=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures\remote-calv-payload.bin"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" goto :missing_toolchain
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL goto :missing_toolchain
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 goto :failed
if not exist "%BUILD_DIR%\CMakeCache.txt" goto :missing_build
cmake --build "%BUILD_DIR%" --target protocol-fixture-emitter -j 2
if errorlevel 1 goto :failed
if not exist "%INTEROP_DIR%" mkdir "%INTEROP_DIR%"

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\KeepAliveInterop.cpp" /Fo"%INTEROP_DIR%\KeepAliveInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-keepalive-interop.pdb"
if errorlevel 1 goto :failed

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\KeepAliveStatefulInterop.cpp" /Fo"%INTEROP_DIR%\KeepAliveStatefulInterop.obj" /Fe"%STATEFUL_EXE%" "%BUILD_DIR%\src\lib\client\client.lib" "%BUILD_DIR%\src\lib\server\server.lib" "%BUILD_DIR%\src\lib\net\net.lib" "%BUILD_DIR%\src\lib\platform\platform.lib" "%BUILD_DIR%\src\lib\mt\mt.lib" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libssl.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-keepalive-stateful.pdb"
if errorlevel 1 goto :failed

if /I "%~1"=="fixture" goto :fixture
if not "%~1"=="" goto :usage
if not exist "%FIXTURE%" goto :missing_fixture

set "CPP_BYTES=%INTEROP_DIR%\cpp-calv.bin"
set "CPP_FRAME=%INTEROP_DIR%\cpp-calv-frame.bin"
set "TRAILING=%INTEROP_DIR%\calv-trailing.bin"
set "FRAME_TRAILING=%INTEROP_DIR%\calv-frame-trailing.bin"
"%CPP_EXE%" emit "%CPP_BYTES%"
if errorlevel 1 goto :failed
fc /b "%FIXTURE%" "%CPP_BYTES%" >nul
if errorlevel 1 goto :failed

call :rust_decode "%CPP_BYTES%" server-to-client client-handshake
if errorlevel 1 goto :failed
call :rust_decode "%CPP_BYTES%" server-to-client active
if errorlevel 1 goto :failed
call :rust_decode "%CPP_BYTES%" client-to-server active
if errorlevel 1 goto :failed

call :forbidden_decode "%CPP_BYTES%" server-to-client server-awaiting-hello-back
if errorlevel 1 goto :failed
call :forbidden_decode "%CPP_BYTES%" server-to-client server-awaiting-info
if errorlevel 1 goto :failed
call :forbidden_decode "%CPP_BYTES%" client-to-server client-handshake
if errorlevel 1 goto :failed
call :forbidden_decode "%CPP_BYTES%" client-to-server server-awaiting-hello-back
if errorlevel 1 goto :failed
call :forbidden_decode "%CPP_BYTES%" client-to-server server-awaiting-info
if errorlevel 1 goto :failed

call :rust_encode server-to-client active
if errorlevel 1 goto :failed
call :rust_encode client-to-server server-awaiting-info
if errorlevel 1 goto :failed
call :rust_encode client-to-server active
if errorlevel 1 goto :failed

call :forbidden_encode server-to-client client-handshake
if errorlevel 1 goto :failed
call :forbidden_encode server-to-client server-awaiting-hello-back
if errorlevel 1 goto :failed
call :forbidden_encode server-to-client server-awaiting-info
if errorlevel 1 goto :failed
call :forbidden_encode client-to-server client-handshake
if errorlevel 1 goto :failed
call :forbidden_encode client-to-server server-awaiting-hello-back
if errorlevel 1 goto :failed

"%CPP_EXE%" emit-frame "%CPP_FRAME%"
if errorlevel 1 goto :failed
"%CPP_EXE%" decode-frame "%CPP_FRAME%"
if errorlevel 1 goto :failed
cargo run --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- decode-frame "%CPP_FRAME%" server-to-client active
if errorlevel 1 goto :failed

copy /b "%CPP_BYTES%"+"%CPP_BYTES%" "%TRAILING%" >nul
if errorlevel 1 goto :failed
"%CPP_EXE%" decode "%TRAILING%" >nul 2>&1
if not errorlevel 1 goto :false_positive
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- decode "%TRAILING%" server-to-client active >nul 2>&1
if not errorlevel 1 goto :false_positive
copy /b "%CPP_FRAME%"+"%CPP_BYTES%" "%FRAME_TRAILING%" >nul
if errorlevel 1 goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- decode-frame "%FRAME_TRAILING%" server-to-client active >nul 2>&1
if not errorlevel 1 goto :false_positive

del /q "%TRAILING%" "%FRAME_TRAILING%" >nul 2>&1
"%STATEFUL_EXE%"
if errorlevel 1 goto :failed
python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-keepalive-manifest.py"
if errorlevel 1 goto :failed
python "%REPO_ROOT%\.hermes\scripts\generate-rust-r0-source-manifest.py" --check
if errorlevel 1 goto :failed
echo RUST_R2_KEEPALIVE_INTEROP_PASS payload_bytes=PASS packet_stream_frame=PASS cpp_to_rust_decode=PASS rust_to_cpp_encode=PASS encode_only_awaiting_info=PASS forbidden_context_no_file=PASS strict_trailing=PASS cpp_stateful_four_cases=PASS rust_stateful=NONE timer_expiration=NOT_COVERED_VIRTUAL_CLOCK_REQUIRED r0=PASS
popd
exit /b 0

:rust_decode
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- decode %1 %2 %3
exit /b %ERRORLEVEL%

:forbidden_decode
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- decode %1 %2 %3 >nul 2>&1
if not errorlevel 1 exit /b 1
exit /b 0

:rust_encode
set "ENCODED=%INTEROP_DIR%\rust-calv-%~1-%~2.bin"
if exist "!ENCODED!" del /q "!ENCODED!"
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- encode "!ENCODED!" %1 %2
if errorlevel 1 exit /b !ERRORLEVEL!
"%CPP_EXE%" decode "!ENCODED!"
if errorlevel 1 exit /b !ERRORLEVEL!
fc /b "%FIXTURE%" "!ENCODED!" >nul
exit /b !ERRORLEVEL!

:forbidden_encode
set "FORBIDDEN=%INTEROP_DIR%\forbidden-calv-%~1-%~2.bin"
if exist "!FORBIDDEN!" del /q "!FORBIDDEN!"
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example keepalive_interop -- encode "!FORBIDDEN!" %1 %2 >nul 2>&1
if not errorlevel 1 exit /b 1
if exist "!FORBIDDEN!" exit /b 1
exit /b 0

:fixture
if not "%~3"=="" goto :usage
if "%~2"=="" goto :usage
"%CPP_EXE%" fixture "%~f2"
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%

:missing_toolchain
echo rust-r2-keepalive-interop: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2
:missing_build
echo rust-r2-keepalive-interop: expected build tree missing 1>&2
popd
exit /b 2
:missing_fixture
echo rust-r2-keepalive-interop: frozen CALV fixture missing 1>&2
popd
exit /b 2
:false_positive
echo rust-r2-keepalive-interop: negative test produced a false positive 1>&2
popd
exit /b 1
:usage
echo usage: rust-r2-keepalive-interop.bat [fixture ^<new-output-path^>] 1>&2
popd
exit /b 2
:failed
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
