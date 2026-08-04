@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1

set "BUILD_DIR=%REPO_ROOT%\out\build\windows-msvc-tests"
set "INTEROP_DIR=%BUILD_DIR%\rust-r2-terminal-control-interop"
set "CPP_EXE=%INTEROP_DIR%\rust-r2-terminal-control-interop.exe"
set "FIXTURE_DIR=%REPO_ROOT%\rust\crates\inputleap-protocol-legacy\tests\fixtures"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

if not exist "%VSWHERE%" goto :missing_toolchain
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL goto :missing_toolchain
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 goto :failed

if not exist "%BUILD_DIR%\CMakeCache.txt" goto :missing_build
cmake --build "%BUILD_DIR%" --target protocol-fixture-emitter -j 2
if errorlevel 1 goto :failed

for %%L in (
  "%BUILD_DIR%\src\lib\inputleap\synlib.lib"
  "%BUILD_DIR%\src\lib\base\base.lib"
  "%BUILD_DIR%\src\lib\io\io.lib"
  "%BUILD_DIR%\src\lib\common\common.lib"
  "%BUILD_DIR%\src\lib\arch\arch.lib"
  "%BUILD_DIR%\src\lib\ipc\ipc.lib"
) do if not exist "%%~L" goto :missing_library

if not exist "%INTEROP_DIR%" mkdir "%INTEROP_DIR%"
cl /nologo /EHsc /std:c++20 /MDd /W4 /permissive- /wd4100 /DSYSAPI_WIN32=1 /DWIN32 /D_WINDOWS /DWINAPI_MSWINDOWS=1 /D_CRT_SECURE_NO_WARNINGS /I"%REPO_ROOT%\src\lib" /I"%BUILD_DIR%\src\lib" "%REPO_ROOT%\src\test\rust-r2\TerminalControlInterop.cpp" /Fo"%INTEROP_DIR%\TerminalControlInterop.obj" /Fe"%CPP_EXE%" "%BUILD_DIR%\src\lib\inputleap\synlib.lib" "%BUILD_DIR%\src\lib\base\base.lib" "%BUILD_DIR%\src\lib\io\io.lib" "%BUILD_DIR%\src\lib\common\common.lib" "%BUILD_DIR%\src\lib\arch\arch.lib" "%BUILD_DIR%\src\lib\ipc\ipc.lib" "%REPO_ROOT%\deps\vcpkg\installed\x64-windows-static\debug\lib\libcrypto.lib" crypt32.lib ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib advapi32.lib /link /machine:x64 /pdb:"%INTEROP_DIR%\rust-r2-terminal-control-interop.pdb"
if errorlevel 1 goto :failed

if /I "%~1"=="fixture" goto :fixture
if not "%~1"=="" goto :usage

call :verify_decode CBYE client-handshake
if errorlevel 1 goto :failed
call :verify_decode CBYE active
if errorlevel 1 goto :failed
call :verify_decode EBSY client-handshake
if errorlevel 1 goto :failed
call :verify_decode EUNK client-handshake
if errorlevel 1 goto :failed
call :verify_decode EBAD client-handshake
if errorlevel 1 goto :failed
call :verify_decode EBAD active
if errorlevel 1 goto :failed
call :verify_ebad_encode
if errorlevel 1 goto :failed
for %%M in (CBYE EBSY EUNK) do (
  call :verify_all_contexts_forbidden %%M
  if errorlevel 1 goto :failed
)
call :verify_forbidden_encode EBAD server-to-client server-awaiting-hello-back
if errorlevel 1 goto :failed
call :verify_forbidden_encode EBAD server-to-client server-awaiting-info
if errorlevel 1 goto :failed
call :verify_forbidden_encode EBAD server-to-client active
if errorlevel 1 goto :failed
call :verify_forbidden_encode EBAD client-to-server client-handshake
if errorlevel 1 goto :failed
call :verify_forbidden_encode EBAD client-to-server server-awaiting-hello-back
if errorlevel 1 goto :failed
call :verify_forbidden_encode EBAD client-to-server server-awaiting-info
if errorlevel 1 goto :failed
call :verify_forbidden_encode EBAD client-to-server active
if errorlevel 1 goto :failed

python "%REPO_ROOT%\.hermes\scripts\verify-rust-r2-terminal-control-manifest.py"
if errorlevel 1 goto :failed
python "%REPO_ROOT%\.hermes\scripts\generate-rust-r0-source-manifest.py" --check
if errorlevel 1 goto :failed
echo RUST_R2_TERMINAL_CONTROL_INTEROP_PASS payload_bytes_only=PASS cpp_to_rust_decode=PASS rust_to_cpp_ebad_encode=PASS bytes_equal=PASS fixture_equal=PASS manifest=PASS decode_only_no_productive_encode=PASS wrong_selector_rejected=PASS invalid_context_rejected=PASS forbidden_encode_no_file=PASS strict_file_trailing_rejected=PASS terminal_policy_metadata=PASS_NOT_STATEFUL_TERMINAL_EXECUTION r0=PASS
popd
exit /b 0

:message_lower
set "LOWER=%~1"
set "LOWER=!LOWER:CBYE=cbye!"
set "LOWER=!LOWER:EBSY=ebsy!"
set "LOWER=!LOWER:EUNK=eunk!"
set "LOWER=!LOWER:EBAD=ebad!"
exit /b 0

:wrong_message
set "WRONG=CBYE"
if /I "%~1"=="CBYE" set "WRONG=EBSY"
exit /b 0

:verify_decode
set "MESSAGE=%~1"
set "STATE=%~2"
call :message_lower !MESSAGE!
set "FIXTURE=%FIXTURE_DIR%\remote-!LOWER!-payload.bin"
if not exist "!FIXTURE!" (
  echo rust-r2-terminal-control-interop: frozen fixture is missing: "!FIXTURE!" 1>&2
  exit /b 2
)
set "CPP_BYTES=%INTEROP_DIR%\cpp-!LOWER!-!STATE!.bin"
set "TRAILING_BYTES=%INTEROP_DIR%\trailing-!LOWER!-!STATE!.bin"
"%CPP_EXE%" emit !MESSAGE! "!CPP_BYTES!"
if errorlevel 1 exit /b !ERRORLEVEL!
cargo run --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example terminal_control_interop -- decode !MESSAGE! "!CPP_BYTES!" server-to-client !STATE!
if errorlevel 1 exit /b !ERRORLEVEL!
fc /b "!FIXTURE!" "!CPP_BYTES!" >nul
if errorlevel 1 (
  echo rust-r2-terminal-control-interop: C++ bytes differ from fixture for !MESSAGE! 1>&2
  exit /b 1
)
call :wrong_message !MESSAGE!
"%CPP_EXE%" decode !WRONG! "!CPP_BYTES!" >nul 2>&1
if not errorlevel 1 (
  echo rust-r2-terminal-control-interop: C++ decoder accepted !MESSAGE! bytes as !WRONG! 1>&2
  exit /b 1
)
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example terminal_control_interop -- decode !WRONG! "!CPP_BYTES!" server-to-client !STATE! >nul 2>&1
if not errorlevel 1 (
  echo rust-r2-terminal-control-interop: Rust decoder accepted !MESSAGE! bytes as !WRONG! 1>&2
  exit /b 1
)
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example terminal_control_interop -- decode !MESSAGE! "!CPP_BYTES!" client-to-server active >nul 2>&1
if not errorlevel 1 (
  echo rust-r2-terminal-control-interop: Rust decoder accepted invalid context for !MESSAGE! 1>&2
  exit /b 1
)
copy /b "!CPP_BYTES!"+"!CPP_BYTES!" "!TRAILING_BYTES!" >nul
if errorlevel 1 exit /b !ERRORLEVEL!
"%CPP_EXE%" decode !MESSAGE! "!TRAILING_BYTES!" >nul 2>&1
if not errorlevel 1 (
  echo rust-r2-terminal-control-interop: C++ strict-file decoder accepted trailing bytes for !MESSAGE! 1>&2
  exit /b 1
)
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example terminal_control_interop -- decode !MESSAGE! "!TRAILING_BYTES!" server-to-client !STATE! >nul 2>&1
if not errorlevel 1 (
  echo rust-r2-terminal-control-interop: Rust strict-file decoder accepted trailing bytes for !MESSAGE! 1>&2
  exit /b 1
)
del /q "!TRAILING_BYTES!" >nul 2>&1
exit /b 0

:verify_ebad_encode
set "RUST_BYTES=%INTEROP_DIR%\rust-ebad-client-handshake.bin"
set "FIXTURE=%FIXTURE_DIR%\remote-ebad-payload.bin"
if exist "%RUST_BYTES%" del /q "%RUST_BYTES%"
if exist "%RUST_BYTES%" exit /b 1
cargo run --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example terminal_control_interop -- encode EBAD "%RUST_BYTES%" server-to-client client-handshake
if errorlevel 1 exit /b %ERRORLEVEL%
"%CPP_EXE%" decode EBAD "%RUST_BYTES%"
if errorlevel 1 exit /b %ERRORLEVEL%
fc /b "%FIXTURE%" "%RUST_BYTES%" >nul
if errorlevel 1 (
  echo rust-r2-terminal-control-interop: Rust EBAD bytes differ from fixture 1>&2
  exit /b 1
)
exit /b 0

:verify_forbidden_encode
set "MESSAGE=%~1"
set "DIRECTION=%~2"
set "STATE=%~3"
call :message_lower !MESSAGE!
set "FORBIDDEN_BYTES=%INTEROP_DIR%\forbidden-!LOWER!-!DIRECTION!-!STATE!.bin"
if exist "!FORBIDDEN_BYTES!" del /q "!FORBIDDEN_BYTES!"
cargo run --quiet --locked --manifest-path "%REPO_ROOT%\rust\Cargo.toml" --package inputleap-protocol-legacy --example terminal_control_interop -- encode !MESSAGE! "!FORBIDDEN_BYTES!" !DIRECTION! !STATE! >nul 2>&1
if not errorlevel 1 (
  echo rust-r2-terminal-control-interop: Rust encoder accepted forbidden context for !MESSAGE!/!DIRECTION!/!STATE! 1>&2
  exit /b 1
)
if exist "!FORBIDDEN_BYTES!" (
  echo rust-r2-terminal-control-interop: rejected encode created output for !MESSAGE!/!DIRECTION!/!STATE! 1>&2
  exit /b 1
)
exit /b 0

:verify_all_contexts_forbidden
for %%D in (server-to-client client-to-server) do for %%S in (client-handshake server-awaiting-hello-back server-awaiting-info active) do (
  call :verify_forbidden_encode %~1 %%D %%S
  if errorlevel 1 exit /b !ERRORLEVEL!
)
exit /b 0

:fixture
if not "%~4"=="" goto :usage
if "%~2"=="" goto :usage
if "%~3"=="" goto :usage
set "FIXTURE_OUTPUT=%~f3"
if exist "%FIXTURE_OUTPUT%" goto :output_exists
"%CPP_EXE%" fixture "%~2" "%FIXTURE_OUTPUT%"
if errorlevel 1 goto :failed
certutil -hashfile "%FIXTURE_OUTPUT%" SHA256
if errorlevel 1 goto :failed
popd
exit /b 0

:missing_toolchain
echo rust-r2-terminal-control-interop: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2

:missing_build
echo rust-r2-terminal-control-interop: expected existing build tree at "%BUILD_DIR%" 1>&2
popd
exit /b 2

:missing_library
echo rust-r2-terminal-control-interop: required existing C++ library is missing: %%~L 1>&2
popd
exit /b 2

:output_exists
echo rust-r2-terminal-control-interop: refusing to overwrite existing fixture candidate: "%FIXTURE_OUTPUT%" 1>&2
popd
exit /b 2

:usage
echo usage: rust-r2-terminal-control-interop.bat [fixture ^<CBYE^|EBSY^|EUNK^|EBAD^> ^<new-output-path^>] 1>&2
popd
exit /b 2

:failed
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
