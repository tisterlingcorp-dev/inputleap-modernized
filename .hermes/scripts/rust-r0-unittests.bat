@echo off
setlocal EnableExtensions
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
pushd "%REPO_ROOT%" || exit /b 1
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :missing_toolchain
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL=%%I"
if not defined VS_INSTALL goto :missing_toolchain
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 goto :failed
set "BONJOUR_SDK_HOME=%REPO_ROOT%\deps\BonjourSDKLike"
cmake --preset windows-msvc-tests
if errorlevel 1 goto :failed
cmake --build out\build\windows-msvc-tests --target unittests protocol-fixture-emitter -j 2
if errorlevel 1 goto :failed
set "PATH=%REPO_ROOT%\out\build\windows-msvc-tests\qtDeploy;%REPO_ROOT%\out\build\windows-msvc-tests\bin;%PATH%"
set "QT_PLUGIN_PATH=%REPO_ROOT%\out\build\windows-msvc-tests\qtDeploy\plugins"
out\build\windows-msvc-tests\bin\unittests.exe --gtest_filter=ProtocolFixtureEmitterTests.*
if errorlevel 1 goto :failed
ctest --test-dir out\build\windows-msvc-tests -R "^protocol-fixture-emitter-cli$" --output-on-failure
if errorlevel 1 goto :failed
out\build\windows-msvc-tests\bin\unittests.exe
if errorlevel 1 goto :failed
popd
exit /b 0

:missing_toolchain
echo rust-r0-unittests: Visual Studio C++ toolchain not found 1>&2
popd
exit /b 2

:failed
set "RESULT=%ERRORLEVEL%"
popd
exit /b %RESULT%
