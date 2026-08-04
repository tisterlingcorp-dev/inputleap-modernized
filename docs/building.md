# Compilar e testar no Windows

Este guia descreve o fluxo reproduzível para Windows 10/11 com MSVC e Qt 6.

## Pré-requisitos

- Visual Studio 2022 Build Tools com **Desenvolvimento para Desktop com C++**.
- CMake 3.21 ou posterior.
- Ninja disponível no `PATH`.
- Qt 6.4.2 MSVC 2019 64-bit em `D:\Qt\6.4.2\msvc2019_64`.
- Dependências vcpkg do repositório em `deps\vcpkg`.
- SDK Bonjour compatível em `deps\BonjourSDKLike`.

Os presets usam caminhos relativos ao repositório para vcpkg e Bonjour; nenhum nome de usuário é fixado. O caminho padrão do Qt pode ser substituído na configuração:

```bat
cmake --preset windows-msvc-tests -DCMAKE_PREFIX_PATH="E:\Qt\6.4.2\msvc2019_64"
```

## Abrir o ambiente MSVC

Execute os comandos abaixo em um **x64 Native Tools Command Prompt for VS 2022**. Em um `cmd.exe` comum, inicialize primeiro:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

## Build dos executáveis principais

A partir da raiz do repositório:

```bat
cmake --preset windows-msvc-main
cmake --build --preset windows-msvc-main
```

O preset compila, em diretório isolado, os targets:

- `input-leap`
- `input-leapc`
- `input-leaps`
- `input-leapd`

Os artefatos ficam em `out\build\windows-msvc-main\bin`.

## Build e execução dos testes

```bat
cmake --preset windows-msvc-tests
cmake --build --preset windows-msvc-tests
ctest --preset windows-msvc-tests
```

O CTest completo executa testes de integração, núcleo, GUI, modelos e parser IPC. Falhas não são ignoradas; o comando retorna código diferente de zero.

### Testes determinísticos dos modelos da GUI

Este grupo não depende de rede externa:

```bat
ctest --preset windows-msvc-gui-models
```

O label `gui-models` cobre:

- `DeviceRegistry`
- `DeviceConnectionModel`
- `CoreConnectionStateController`
- `DashboardPeerStatePolicy`
- `IpcReader`

Para listar os testes:

```bat
ctest --test-dir out\build\windows-msvc-tests -N
ctest --test-dir out\build\windows-msvc-tests --print-labels
```

## Executar a GUI compilada

Não abra uma build Debug diretamente de um shell MSYS confiando em um `PATH` antigo. Depois de reiniciar o Windows isso pode resultar em `0xC0000135` quando as DLLs do Qt não forem encontradas.

Use um caminho Windows nativo:

```bat
set "PATH=D:\Qt\6.4.2\msvc2019_64\bin;%PATH%"
cd /d C:\caminho\para\inputleap\out\build\windows-msvc-main\bin
input-leap.exe
```

Para outra instalação do Qt, ajuste somente a primeira linha.

## Limpeza reproduzível

Os presets não usam os diretórios históricos `build` e `build-tests`. Para reconfigurar do zero, remova apenas o diretório isolado correspondente e execute novamente o preset:

```bat
rmdir /s /q out\build\windows-msvc-tests
cmake --preset windows-msvc-tests
```

Não remova um diretório que contenha executáveis em uso. O serviço `input-leapd` não precisa ser interrompido porque os presets escrevem em `out\build`.
