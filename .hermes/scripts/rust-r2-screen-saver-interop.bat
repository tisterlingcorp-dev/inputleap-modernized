@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-screensaver-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-screensaver-interop.exe"
set "STATEFUL_EXE=%INTEROP_DIR%\rust-r2-screensaver-stateful.exe"
set "FIXTURE_OFF=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures\remote-csec-off-payload.bin"
set "FIXTURE_ON=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures\remote-csec-on-payload.bin"
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
del /q "%CPP_EXE%" "%STATEFUL_EXE%" "%INTEROP_DIR%\ScreenSaverInterop.obj" "%INTEROP_DIR%\ScreenSaverStatefulInterop.obj" >nul 2>&1

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\ScreenSaverInterop.cpp" /Fo"%INTEROP_DIR%\ScreenSaverInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-screensaver-interop.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%CPP_EXE%" goto :missing_binary

cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\ScreenSaverStatefulInterop.cpp" /Fo"%INTEROP_DIR%\ScreenSaverStatefulInterop.obj" /Fe"%STATEFUL_EXE%" "%BUILD_DIR%\src\lib\client\client.lib" "%BUILD_DIR%\src\lib\server\server.lib" "%BUILD_DIR%\src\lib\net\net.lib" "%BUILD_DIR%\src\lib\platform\platform.lib" "%BUILD_DIR%\src\lib\mt\mt.lib" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libssl.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-screensaver-stateful.pdb"
if not "!ERRORLEVEL!"=="0" goto :failed
if not exist "%STATEFUL_EXE%" goto :missing_binary

if /I "%~1"=="fixture" goto :fixture
if not "%~1"=="" goto :usage
if not exist "%FIXTURE_OFF%" goto :missing_fixture
if not exist "%FIXTURE_ON%" goto :missing_fixture

set "CPP_OFF=%INTEROP_DIR%\cpp-csec-off.bin"
set "CPP_ON=%INTEROP_DIR%\cpp-csec-on.bin"
set "CPP_FRAME_OFF=%INTEROP_DIR%\cpp-csec-off-frame.bin"
set "CPP_FRAME_ON=%INTEROP_DIR%\cpp-csec-on-frame.bin"
set "TRAILING=%INTEROP_DIR%\csec-trailing.bin"
set "FRAME_TRAILING=%INTEROP_DIR%\csec-frame-trailing.bin"
del /q "%CPP_OFF%" "%CPP_ON%" "%CPP_FRAME_OFF%" "%CPP_FRAME_ON%" "%TRAILING%" "%FRAME_TRAILING%" >nul 2>&1

"%CPP_EXE%" emit 0 "%CPP_OFF%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" emit 1 "%CPP_ON%"
if not "!ERRORLEVEL!"=="0" goto :failed
fc /b "%FIXTURE_OFF%" "%CPP_OFF%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
fc /b "%FIXTURE_ON%" "%CPP_ON%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed

cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode "%CPP_OFF%" server-to-client active
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode "%CPP_ON%" server-to-client active
if not "!ERRORLEVEL!"=="0" goto :failed

for %%S in (client-handshake server-awaiting-hello-back server-awaiting-info) do (
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode "%CPP_ON%" server-to-client %%S >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
)
for %%S in (client-handshake server-awaiting-hello-back server-awaiting-info active) do (
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode "%CPP_ON%" client-to-server %%S >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
)

for %%V in (0 1) do (
    set "ENCODED=%INTEROP_DIR%\rust-csec-%%V-server-to-client-active.bin"
    if exist "!ENCODED!" del /q "!ENCODED!"
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- encode "!ENCODED!" server-to-client active %%V
    if not "!ERRORLEVEL!"=="0" goto :failed
    "%CPP_EXE%" decode %%V "!ENCODED!"
    if not "!ERRORLEVEL!"=="0" goto :failed
    if "%%V"=="0" fc /b "%FIXTURE_OFF%" "!ENCODED!" >nul
    if "%%V"=="1" fc /b "%FIXTURE_ON%" "!ENCODED!" >nul
    if not "!ERRORLEVEL!"=="0" goto :failed
)

for %%S in (client-handshake server-awaiting-hello-back server-awaiting-info) do (
    set "FORBIDDEN=%INTEROP_DIR%\forbidden-csec-1-server-to-client-%%S.bin"
    if exist "!FORBIDDEN!" del /q "!FORBIDDEN!"
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- encode "!FORBIDDEN!" server-to-client %%S 1 >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
    if exist "!FORBIDDEN!" goto :false_positive
)
for %%S in (client-handshake server-awaiting-hello-back server-awaiting-info active) do (
    set "FORBIDDEN=%INTEROP_DIR%\forbidden-csec-1-client-to-server-%%S.bin"
    if exist "!FORBIDDEN!" del /q "!FORBIDDEN!"
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- encode "!FORBIDDEN!" client-to-server %%S 1 >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
    if exist "!FORBIDDEN!" goto :false_positive
)
for %%V in (2 255) do (
    set "FORBIDDEN=%INTEROP_DIR%\forbidden-csec-%%V-server-to-client-active.bin"
    if exist "!FORBIDDEN!" del /q "!FORBIDDEN!"
    cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- encode "!FORBIDDEN!" server-to-client active %%V >nul 2>&1
    if "!ERRORLEVEL!"=="0" goto :false_positive
    if not "!ERRORLEVEL!"=="1" goto :failed
    if exist "!FORBIDDEN!" goto :false_positive
)

"%CPP_EXE%" emit-frame 0 "%CPP_FRAME_OFF%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" emit-frame 1 "%CPP_FRAME_ON%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" decode-frame 0 "%CPP_FRAME_OFF%"
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" decode-frame 1 "%CPP_FRAME_ON%"
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode-frame "%CPP_FRAME_OFF%" server-to-client active
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode-frame "%CPP_FRAME_ON%" server-to-client active
if not "!ERRORLEVEL!"=="0" goto :failed

copy /b "%CPP_ON%"+"%CPP_OFF%" "%TRAILING%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
"%CPP_EXE%" decode 1 "%TRAILING%" >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode "%TRAILING%" server-to-client active >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed
copy /b "%CPP_FRAME_ON%"+"%CPP_OFF%" "%FRAME_TRAILING%" >nul
if not "!ERRORLEVEL!"=="0" goto :failed
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example screen_saver_interop -- decode-frame "%FRAME_TRAILING%" server-to-client active >nul 2>&1
if "!ERRORLEVEL!"=="0" goto :false_positive
if not "!ERRORLEVEL!"=="1" goto :failed

"%STATEFUL_EXE%"
if not "!ERRORLEVEL!"=="0" goto :failed
python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-screen-saver-manifest.py"
if not "!ERRORLEVEL!"=="0" goto :failed
python "%REPO_ROOT%\.hermes\scripts\generate-rust-r0-source-manifest.py" --check
if not "!ERRORLEVEL!"=="0" goto :failed
echo RUST_R2_SCREEN_SAVER_INTEROP_PASS payload_off_on=PASS packet_stream_frames=PASS cpp_to_rust_decode=PASS rust_to_cpp_encode=PASS context_matrix=1_OF_8 unsupported_no_file=PASS strict_trailing=PASS cpp_stateful=FALSE_TRUE_TRUE_THEN_CROP rust_stateful=NONE r0=PASS
popd
exit /b 0

:fixture
if not "%~4"=="" goto :usage
if "%~3"=="" goto :usage
if not "%~2"=="0" if not "%~2"=="1" goto :usage
"%CPP_EXE%" fixture %2 "%~f3"
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%

:missing_toolchain
echo rust-r2-screen-saver-interop: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2
:missing_build
echo rust-r2-screen-saver-interop: expected build tree missing 1>&2
popd
exit /b 2
:missing_fixture
echo rust-r2-screen-saver-interop: frozen CSEC fixture missing 1>&2
popd
exit /b 2
:missing_binary
echo rust-r2-screen-saver-interop: compiler did not create the requested executable 1>&2
popd
exit /b 1
:false_positive
echo rust-r2-screen-saver-interop: negative test produced a false positive 1>&2
popd
exit /b 1
:usage
echo usage: rust-r2-screen-saver-interop.bat [fixture ^<0^|1^> ^<new-output-path^>] 1>&2
popd
exit /b 2
:failed
popd
exit /b 1
