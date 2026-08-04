
# The following packages need to be installed in order to run this script:
# CMake, Visual Studio Build Tools with the C++ workload, Qt, OpenSSL, and Inno Setup.
# OpenSSL can be provided by a local vcpkg checkout, either in .\deps\vcpkg or via B_VCPKG_ROOT.
# Qt needs to be installed either manually or by running:
# python -m aqt install-qt windows desktop 6.4.2 win64_msvc2019_64 -O C:\Qt
# Note that Powershell may need to be restarted in order to changes to take effect.

$bonjour_path = '.\deps\BonjourSDKLike'

New-Item -Force -ItemType Directory -Path .\deps | Out-Null
Invoke-WebRequest 'https://github.com/nelsonjchen/mDNSResponder/releases/download/v2019.05.08.1/x64_RelWithDebInfo.zip' -OutFile 'deps\BonjourSDKLike.zip' ;
$expected_bonjour_sha256 = 'aad489258d047e396a43efff4270571c82e7da5d33cba1710b784b66fd4011f9';
$actual_bonjour_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath 'deps\BonjourSDKLike.zip').Hash.ToLowerInvariant();
if ($actual_bonjour_sha256 -ne $expected_bonjour_sha256) {
    Remove-Item -Force 'deps\BonjourSDKLike.zip';
    throw 'Bonjour SDK-like archive checksum verification failed';
}
if (Test-Path -LiteralPath $bonjour_path) {
    Remove-Item -LiteralPath $bonjour_path -Recurse
}

# CMake configuration expects this to be absolute path
$bonjour_path = -join((Get-Location).Path, '\', $bonjour_path);

Expand-Archive .\deps\BonjourSDKLike.zip -DestinationPath .\deps\BonjourSDKLike
Remove-Item deps\BonjourSDKLike.zip

$vs_version = '';
$vs_path = '';
$cmake_executable = (Get-Command cmake -ErrorAction SilentlyContinue).Source;
if ($cmake_executable -eq $null) {
    $cmake_executable = 'C:\Program Files\CMake\bin\cmake.exe';
}

if (-not (Test-Path -LiteralPath $cmake_executable)) {
    Write-Output "Could not find CMake";
    break;
}

$iscc_executable = (Get-Command ISCC -ErrorAction SilentlyContinue).Source;
if ($iscc_executable -eq $null) {
    $inno_install = Get-ItemProperty `
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', `
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Inno Setup*' -and $_.InstallLocation } |
        Select-Object -First 1 -ExpandProperty InstallLocation;

    if ($inno_install -ne $null) {
        $iscc_executable = Join-Path $inno_install 'ISCC.exe';
    }
}

$vswhere_path = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe";
if (Test-Path -LiteralPath $vswhere_path) {
    $vs_installation_path = & $vswhere_path -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath;
    if ($LASTEXITCODE -eq 0 -and $vs_installation_path) {
        $vs_dev_cmd = Join-Path $vs_installation_path 'Common7\Tools\VsDevCmd.bat';
        if (Test-Path -LiteralPath $vs_dev_cmd) {
            $vs_path = $vs_dev_cmd;

            if ($vs_installation_path -match '\\2022\\') {
                $vs_version = 'Visual Studio 17 2022';
            } elseif ($vs_installation_path -match '\\2019\\') {
                $vs_version = 'Visual Studio 16 2019';
            }
        }
    }
}

if ($vs_version -eq '') {
    $vs_locations = @(
        @{version='Visual Studio 17 2022';
          path='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat'},
        @{version='Visual Studio 17 2022';
          path='C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat'},
        @{version='Visual Studio 17 2022';
          path='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'},
        @{version='Visual Studio 16 2019';
          path='C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsDevCmd.bat'},
        @{version='Visual Studio 16 2019';
          path='C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat'},
        @{version='Visual Studio 16 2019';
          path='C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat'}
    );

    Foreach ($location in $vs_locations) {
        if (Test-Path -LiteralPath $location.path) {
            $vs_version = $location.version;
            $vs_path = $location.path;
            break;
        }
    }
}

if ($vs_version -eq '') {
    Write-Output "Could not find Visual studio version";
    break;
}

Write-Output "Using Visual Studio version $vs_version at $vs_path";
Write-Output "Using CMake at $cmake_executable";
if ($iscc_executable -ne $null -and (Test-Path -LiteralPath $iscc_executable)) {
    Write-Output "Using Inno Setup compiler at $iscc_executable";
}

$build_type = 'Release';
if ($env:B_BUILD_TYPE -ne $null) {
    $build_type = $env:B_BUILD_TYPE;
}
$qt_root = (Resolve-Path C:\Qt\6*\* 2>$null).Path;
if ($env:B_QT_ROOT -ne $null) {
    $qt_root = $env:B_QT_ROOT;
} elseif ($qt_root -eq $null) {
    Write-Output "Could not find Qt and B_QT_ROOT is not provided";
    break;
}

Write-Output "Using Qt at $qt_root";

$cmake_prefix_path = @($qt_root);
$vcpkg_root = $env:B_VCPKG_ROOT;
if ($vcpkg_root -eq $null -and (Test-Path -LiteralPath '.\deps\vcpkg')) {
    $vcpkg_root = (Resolve-Path '.\deps\vcpkg').Path;
}

$openssl_root = $env:B_OPENSSL_ROOT;
if ($vcpkg_root -ne $null) {
    $vcpkg_openssl_root = Join-Path $vcpkg_root 'installed\x64-windows-static';
    if (Test-Path -LiteralPath $vcpkg_openssl_root) {
        Write-Output "Using OpenSSL from vcpkg at $vcpkg_openssl_root";
        $openssl_root = $vcpkg_openssl_root;
        $cmake_prefix_path += $vcpkg_openssl_root;
    }
}

$cmake_prefix_path = $cmake_prefix_path -join ';';

if (Test-Path -LiteralPath build) {
    Remove-Item -LiteralPath build -Recurse;
}
New-Item -Force -ItemType Directory -Path .\build | Out-Null
pushd build

try {
    $env:BONJOUR_SDK_HOME="$bonjour_path"
    $cmake_config_args = @(
        '..',
        '-G', $vs_version,
        '-A', 'x64',
        "-DCMAKE_BUILD_TYPE=$build_type",
        "-DCMAKE_PREFIX_PATH=$cmake_prefix_path",
        "-DDNSSD_LIB=$bonjour_path\Lib\x64\dnssd.lib",
        '-DCMAKE_INSTALL_PREFIX=input-leap-install'
    );
    if ($openssl_root -ne $null) {
        $cmake_config_args += "-DOPENSSL_ROOT_DIR=$openssl_root";
    }

    & $cmake_executable @cmake_config_args

    & $cmake_executable --build . --parallel --config $build_type --target install
    if ($iscc_executable -eq $null -or -not (Test-Path -LiteralPath $iscc_executable)) {
        throw "Could not find Inno Setup compiler (ISCC.exe)";
    }
    & $iscc_executable /Qp installer-inno\input-leap.iss
} finally {
    popd
}
