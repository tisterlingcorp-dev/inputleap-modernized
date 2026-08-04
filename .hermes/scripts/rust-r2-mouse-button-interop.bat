@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-mouse-button-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-mouse-button-interop.exe"
set "STATEFUL_EXE=%INTEROP_DIR%\rust-r2-mouse-button-stateful.exe"
set "FIXTURE_DOWN=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures\remote-dmdn-button1-payload.bin"
set "FIXTURE_UP=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures\remote-dmup-button1-payload.bin"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :missing_toolchain
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL goto :missing_toolchain
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%BUILD_DIR%\CMakeCache.txt" goto :missing_build
cmake --build "%BUILD_DIR%" --target client server protocol-fixture-emitter -j 2
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%INTEROP_DIR%" mkdir "%INTEROP_DIR%"
del /q "%CPP_EXE%" "%STATEFUL_EXE%" "%INTEROP_DIR%\MouseButtonInterop.obj" "%INTEROP_DIR%\MouseButtonStatefulInterop.obj" >nul 2>&1

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\MouseButtonInterop.cpp" /Fo"%INTEROP_DIR%\MouseButtonInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-mouse-button-interop.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%CPP_EXE%" goto :missing_binary

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\MouseButtonStatefulInterop.cpp" /Fo"%INTEROP_DIR%\MouseButtonStatefulInterop.obj" /Fe"%STATEFUL_EXE%" "%BUILD_DIR%\src\lib\client\client.lib" "%BUILD_DIR%\src\lib\server\server.lib" "%BUILD_DIR%\src\lib\net\net.lib" "%BUILD_DIR%\src\lib\platform\platform.lib" "%BUILD_DIR%\src\lib\mt\mt.lib" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libssl.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-mouse-button-stateful.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%STATEFUL_EXE%" goto :missing_binary

for %%F in ("%CPP_EXE%" "%STATEFUL_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\client\client.lib" "%BUILD_DIR%\src\lib\server\server.lib") do (
  if not exist "%%~F" goto :missing_binary
  certutil -hashfile "%%~F" SHA256
  if not "!ERRORLEVEL!"=="0" goto :failed
)
echo RUST_R2_MOUSE_BUTTON_BINARY_HASH_CAPTURE_PASS

if /I "%~1"=="fixture" goto :fixture
if not "%~1"=="" goto :usage
if not exist "%FIXTURE_DOWN%" goto :missing_fixture
if not exist "%FIXTURE_UP%" goto :missing_fixture

set "CPP_DOWN1=%INTEROP_DIR%\cpp-dmdn-1.bin"
set "CPP_UP1=%INTEROP_DIR%\cpp-dmup-1.bin"
set "CPP_DOWN255=%INTEROP_DIR%\cpp-dmdn-255.bin"
set "CPP_UP255=%INTEROP_DIR%\cpp-dmup-255.bin"
set "FRAME_DOWN1=%INTEROP_DIR%\cpp-dmdn-1-frame.bin"
set "FRAME_UP255=%INTEROP_DIR%\cpp-dmup-255-frame.bin"
set "TRAILING=%INTEROP_DIR%\mouse-button-trailing.bin"
set "FRAME_TRAILING=%INTEROP_DIR%\mouse-button-frame-trailing.bin"
del /q "%CPP_DOWN1%" "%CPP_UP1%" "%CPP_DOWN255%" "%CPP_UP255%" "%FRAME_DOWN1%" "%FRAME_UP255%" "%TRAILING%" "%FRAME_TRAILING%" "%INTEROP_DIR%\rust-*.bin" "%INTEROP_DIR%\invalid-context.bin" "%INTEROP_DIR%\invalid-u8.bin" "%INTEROP_DIR%\existing.bin" >nul 2>&1

"%CPP_EXE%" emit DMDN 1 "%CPP_DOWN1%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" emit DMUP 1 "%CPP_UP1%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" emit DMDN 255 "%CPP_DOWN255%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" emit DMUP 255 "%CPP_UP255%"
if not "!ERRORLEVEL!"=="0" goto :failed
fc /b "%FIXTURE_DOWN%" "%CPP_DOWN1%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
fc /b "%FIXTURE_UP%" "%CPP_UP1%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed

for %%F in ("%CPP_DOWN1%" "%CPP_UP1%" "%CPP_DOWN255%" "%CPP_UP255%") do (
  cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- decode "%%~F" server-to-client active
  if not "!ERRORLEVEL!"=="0" goto :failed
)

for %%V in (1 255) do (
  for %%K in (down up) do (
    set "RUST_OUT=%INTEROP_DIR%\rust-%%K-%%V.bin"
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- encode %%K "!RUST_OUT!" server-to-client active %%V
    if not "!ERRORLEVEL!"=="0" goto :failed
    if "%%K"=="down" (set "CPP_CODE=DMDN") else set "CPP_CODE=DMUP"
    "%CPP_EXE%" decode !CPP_CODE! %%V "!RUST_OUT!"
    if not "!ERRORLEVEL!"=="0" goto :failed
  )
)

"%CPP_EXE%" emit-frame DMDN 1 "%FRAME_DOWN1%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" emit-frame DMUP 255 "%FRAME_UP255%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" decode-frame DMDN 1 "%FRAME_DOWN1%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" decode-frame DMUP 255 "%FRAME_UP255%"
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- decode-frame "%FRAME_DOWN1%" server-to-client active
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- decode-frame "%FRAME_UP255%" server-to-client active
if not "!ERRORLEVEL!"=="0" goto :failed

for %%C in ("client-to-server client-handshake" "client-to-server server-awaiting-hello-back" "client-to-server server-awaiting-info" "client-to-server active" "server-to-client client-handshake" "server-to-client server-awaiting-hello-back" "server-to-client server-awaiting-info") do (
  for /f "tokens=1,2" %%D in ("%%~C") do (
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- decode "%CPP_DOWN1%" %%D %%E >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- encode up "%INTEROP_DIR%\invalid-context.bin" %%D %%E 1 >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
    if exist "%INTEROP_DIR%\invalid-context.bin" goto :false_positive
  )
)

copy /b "%CPP_DOWN1%"+"%CPP_UP1%" "%TRAILING%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- decode "%TRAILING%" server-to-client active >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed
"%CPP_EXE%" decode DMDN 1 "%TRAILING%" >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed
copy /b "%FRAME_DOWN1%"+"%CPP_UP1%" "%FRAME_TRAILING%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- decode-frame "%FRAME_TRAILING%" server-to-client active >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed
"%CPP_EXE%" decode-frame DMDN 1 "%FRAME_TRAILING%" >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed

"%CPP_EXE%" emit DMDN 256 "%INTEROP_DIR%\invalid-u8.bin" >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed
if exist "%INTEROP_DIR%\invalid-u8.bin" goto :false_positive
copy /b "%CPP_DOWN1%" "%INTEROP_DIR%\existing.bin" >nul
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example mouse_button_interop -- encode down "%INTEROP_DIR%\existing.bin" server-to-client active 1 >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed

"%STATEFUL_EXE%"
if not "!ERRORLEVEL!"=="0" goto :failed
python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-mouse-button-manifest.py"
if not "!ERRORLEVEL!"=="0" goto :failed
python "%REPO_ROOT%\.hermes\scripts\generate-rust-r0-source-manifest.py" --check
if not "!ERRORLEVEL!"=="0" goto :failed

echo RUST_R2_MOUSE_BUTTON_INTEROP_PASS payload_down_up=PASS all_u8=PASS packet_stream_frames=PASS cpp_to_rust_decode=PASS rust_to_cpp_encode=PASS context_matrix=1_OF_8 strict_trailing=PASS cpp_stateful=ORDERED_CALLBACKS_THEN_CROP truncated_payloads=EBAD_DISCONNECT_NO_CALLBACK rust_stateful=NONE os_input=NOT_INVOKED r0=PASS
popd
exit /b 0

:fixture
if "%~4"=="" goto :usage
"%CPP_EXE%" fixture "%~2" "%~3" "%~4"
set "RESULT=!ERRORLEVEL!"
popd
exit /b !RESULT!

:false_positive
echo ERROR: expected rejection unexpectedly succeeded 1>&2
popd
exit /b 1
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
:missing_fixture
echo ERROR: required mouse-button fixture missing 1>&2
popd
exit /b 1
:usage
echo usage: rust-r2-mouse-button-interop.bat [fixture ^<DMDN^|DMUP^> ^<0..255^> ^<new-path^>] 1>&2
popd
exit /b 2
:failed
popd
exit /b 1
