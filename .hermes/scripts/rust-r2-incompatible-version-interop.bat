@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-incompatible-version-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-incompatible-version-interop.exe"
set "STATEFUL_EXE=%INTEROP_DIR%\rust-r2-incompatible-version-stateful.exe"
set "FIXTURE=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures\remote-eicv-1-6-payload.bin"
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

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\IncompatibleVersionInterop.cpp" /Fo"%INTEROP_DIR%\IncompatibleVersionInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-incompatible-version-interop.pdb"
if errorlevel 1 goto :failed

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\IncompatibleVersionStatefulInterop.cpp" /Fo"%INTEROP_DIR%\IncompatibleVersionStatefulInterop.obj" /Fe"%STATEFUL_EXE%" "%BUILD_DIR%\src\lib\client\client.lib" "%BUILD_DIR%\src\lib\server\server.lib" "%BUILD_DIR%\src\lib\net\net.lib" "%BUILD_DIR%\src\lib\platform\platform.lib" "%BUILD_DIR%\src\lib\mt\mt.lib" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libssl.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-incompatible-version-stateful.pdb"
if errorlevel 1 goto :failed

if /I "%~1"=="fixture" goto :fixture
if not "%~1"=="" goto :usage
if not exist "%FIXTURE%" goto :missing_fixture

set "CPP_BYTES=%INTEROP_DIR%\cpp-eicv-1-6.bin"
set "RUST_BYTES=%INTEROP_DIR%\rust-eicv-1-6.bin"
set "CPP_FRAME=%INTEROP_DIR%\cpp-eicv-1-6-frame.bin"
set "SHORT_BYTES=%INTEROP_DIR%\eicv-short.bin"
set "TRAILING_BYTES=%INTEROP_DIR%\eicv-trailing.bin"
set "FRAME_TRAILING=%INTEROP_DIR%\eicv-frame-trailing.bin"

"%CPP_EXE%" emit "%CPP_BYTES%"
if errorlevel 1 goto :failed
fc /b "%FIXTURE%" "%CPP_BYTES%" >nul
if errorlevel 1 goto :failed
cargo run --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- decode "%CPP_BYTES%" server-to-client client-handshake
if errorlevel 1 goto :failed

if exist "%RUST_BYTES%" del /q "%RUST_BYTES%"
cargo run --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- encode "%RUST_BYTES%" server-to-client client-handshake 1 6
if errorlevel 1 goto :failed
"%CPP_EXE%" decode "%RUST_BYTES%"
if errorlevel 1 goto :failed
fc /b "%FIXTURE%" "%RUST_BYTES%" >nul
if errorlevel 1 goto :failed

for %%D in (server-to-client client-to-server) do for %%S in (client-handshake server-awaiting-hello-back server-awaiting-info active) do (
  set "EXPECT=forbid"
  if /I "%%D/%%S"=="server-to-client/client-handshake" set "EXPECT=allow"
  call :verify_decode_context %%D %%S !EXPECT!
  if errorlevel 1 goto :failed
  call :verify_encode_context %%D %%S !EXPECT!
  if errorlevel 1 goto :failed
)

call :verify_unsupported 1 5 below-supported
if errorlevel 1 goto :failed
call :verify_unsupported -32768 32767 signed-extremes-a
if errorlevel 1 goto :failed
call :verify_unsupported 32767 -32768 signed-extremes-b
if errorlevel 1 goto :failed

"%CPP_EXE%" emit-frame "%CPP_FRAME%"
if errorlevel 1 goto :failed
"%CPP_EXE%" decode-frame "%CPP_FRAME%"
if errorlevel 1 goto :failed
cargo run --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- decode-frame "%CPP_FRAME%" server-to-client client-handshake
if errorlevel 1 goto :failed

python -c "from pathlib import Path; p=Path(r'%CPP_BYTES%'); Path(r'%SHORT_BYTES%').write_bytes(p.read_bytes()[:-1])"
if errorlevel 1 goto :failed
copy /b "%CPP_BYTES%"+"%CPP_BYTES%" "%TRAILING_BYTES%" >nul
if errorlevel 1 goto :failed
copy /b "%CPP_FRAME%"+"%CPP_BYTES%" "%FRAME_TRAILING%" >nul
if errorlevel 1 goto :failed
for %%F in ("%SHORT_BYTES%" "%TRAILING_BYTES%") do (
  "%CPP_EXE%" decode "%%~F" >nul 2>&1
  if not errorlevel 1 goto :false_positive
  cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- decode "%%~F" server-to-client client-handshake >nul 2>&1
  if not errorlevel 1 goto :false_positive
)
"%CPP_EXE%" decode-frame "%FRAME_TRAILING%" >nul 2>&1
if not errorlevel 1 goto :false_positive
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- decode-frame "%FRAME_TRAILING%" server-to-client client-handshake >nul 2>&1
if not errorlevel 1 goto :false_positive

"%STATEFUL_EXE%"
if errorlevel 1 goto :failed
python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-incompatible-version-manifest.py"
if errorlevel 1 goto :failed
python "%REPO_ROOT%\.hermes\scripts\generate-rust-r0-source-manifest.py" --check
if errorlevel 1 goto :failed
echo RUST_R2_INCOMPATIBLE_VERSION_INTEROP_PASS cpp_to_rust_payload=PASS rust_to_cpp_payload=PASS packet_stream_frame=PASS decode_contexts=8_OF_8 encode_contexts=8_OF_8 unsupported_no_file=PASS strict_input=PASS strict_trailing=PASS cpp_terminal_effect=CLIENT_CONNECTION_FAILED_PUBLIC_EVENT numeric_fields=NOT_ORACLED_CPP_CONSUMER_BUG rust_stateful=NONE r0=PASS
popd
exit /b 0

:verify_decode_context
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- decode "%CPP_BYTES%" %~1 %~2 >nul 2>&1
if /I "%~3"=="allow" exit /b %ERRORLEVEL%
if not errorlevel 1 exit /b 1
exit /b 0

:verify_encode_context
set "CONTEXT_OUTPUT=%INTEROP_DIR%\context-eicv-%~1-%~2.bin"
if exist "!CONTEXT_OUTPUT!" del /q "!CONTEXT_OUTPUT!"
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- encode "!CONTEXT_OUTPUT!" %~1 %~2 1 6 >nul 2>&1
if /I "%~3"=="allow" (
  if errorlevel 1 exit /b !ERRORLEVEL!
  "%CPP_EXE%" decode "!CONTEXT_OUTPUT!" >nul
  if errorlevel 1 exit /b !ERRORLEVEL!
  fc /b "%FIXTURE%" "!CONTEXT_OUTPUT!" >nul
  exit /b !ERRORLEVEL!
)
if not errorlevel 1 exit /b 1
if exist "!CONTEXT_OUTPUT!" exit /b 1
exit /b 0

:verify_unsupported
set "UNSUPPORTED_OUTPUT=%INTEROP_DIR%\unsupported-eicv-%~3.bin"
if exist "!UNSUPPORTED_OUTPUT!" del /q "!UNSUPPORTED_OUTPUT!"
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example incompatible_version_interop -- encode "!UNSUPPORTED_OUTPUT!" server-to-client client-handshake %~1 %~2 >nul 2>&1
if not errorlevel 1 exit /b 1
if exist "!UNSUPPORTED_OUTPUT!" exit /b 1
exit /b 0

:fixture
if not "%~3"=="" goto :usage
if "%~2"=="" goto :usage
set "FIXTURE_OUTPUT=%~f2"
if exist "%FIXTURE_OUTPUT%" goto :output_exists
"%CPP_EXE%" fixture "%FIXTURE_OUTPUT%"
if errorlevel 1 goto :failed
certutil -hashfile "%FIXTURE_OUTPUT%" SHA256
if errorlevel 1 goto :failed
popd
exit /b 0

:missing_toolchain
echo rust-r2-incompatible-version-interop: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2
:missing_build
echo rust-r2-incompatible-version-interop: expected build tree missing 1>&2
popd
exit /b 2
:missing_fixture
echo rust-r2-incompatible-version-interop: frozen EICV fixture missing 1>&2
popd
exit /b 2
:output_exists
echo rust-r2-incompatible-version-interop: refusing to overwrite existing fixture candidate 1>&2
popd
exit /b 2
:false_positive
echo rust-r2-incompatible-version-interop: negative test produced a false positive 1>&2
popd
exit /b 1
:usage
echo usage: rust-r2-incompatible-version-interop.bat [fixture ^<new-output-path^>] 1>&2
popd
exit /b 2
:failed
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
