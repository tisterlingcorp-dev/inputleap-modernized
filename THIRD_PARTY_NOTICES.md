# Third-Party Notices

This file records the principal third-party components used or redistributed by InputLeap Modernized. It complements, but does not replace, each component's license file. A source checkout does not necessarily contain the source of Cargo/system dependencies; `Cargo.lock`, CMake discovery and package-manager metadata identify the exact build graph.

Before distributing a binary, regenerate the dependency inventory for the exact revision and platform, include all applicable license texts, and review the resulting package contents. This document is technical compliance guidance, not legal advice.

## Project origin

InputLeap Modernized is an unofficial derivative of [input-leap/input-leap](https://github.com/input-leap/input-leap), which in turn carries copyright from Input Leap, Barrier and Synergy contributors. The derivative source remains under GPL-2.0-only with the OpenSSL linking permission reproduced in the repository [`LICENSE`](LICENSE). Existing file-level copyright notices must be preserved.

## Components and build dependencies

| Component | How it is used | License / obligation summary |
| --- | --- | --- |
| Qt 6 | C++ GUI/runtime | LGPL-3.0-only, GPL-3.0-only or commercial terms, depending on the selected Qt distribution. Binary redistributors using LGPL Qt must provide the required notices, license text, relinking/replacement ability and any other LGPL requirements. |
| OpenSSL | TLS/mTLS | Apache-2.0 for current OpenSSL releases. Linking is additionally permitted by the exception in the project `LICENSE`; retain OpenSSL notices when redistributing it. |
| libpng | PNG clipboard/image support | libpng license. Preserve its copyright and license notice when redistributing the library. |
| zlib | Compression dependency | Zlib license. Preserve its notice and do not misrepresent altered versions. |
| Tauri/Wry/Tao | Rust desktop shell | Primarily MIT OR Apache-2.0. Exact versions and transitive dependencies are pinned by the Tauri `Cargo.lock`. |
| Rust/Cargo dependencies | Rust applications and libraries | MIT, Apache-2.0, BSD, ISC, Zlib, Unicode, MPL-2.0 and Apache-2.0 WITH LLVM-exception components are accepted by `rust/deny.toml`. Each dependency remains under its own terms. |
| GoogleTest/GoogleMock | C++ tests via `ext/gtest` | BSD-3-Clause; full notice below. |
| gulrak/filesystem | C++ filesystem compatibility via `ext/gulrak-filesystem` | MIT; full notice below. |
| mDNSResponder DNS-SD runtime | Windows installer redistributes the DNS-SD client DLL and service executable; the header and import stub/library are build-only inputs | Source revision, SHA-256 inventory, upstream license summary, and the complete Apache-2.0 license text are installed under `licenses/mDNSResponder`; the BSD-3-Clause notice for the shared DNS-SD client code is reproduced below. The applicable per-file license notices and redistribution terms must still be reviewed for the exact source files and product model before public release. The proprietary Apple Bonjour installer is not bundled. |
| Inno Setup | Optional legacy Windows package compiler, installed separately | Inno Setup is not vendored in this repository. Builders and binary redistributors must follow the license of the installed Inno Setup version. |
| isxdl 5.1.0 | Download helper DLL used only by the legacy Inno scripts | BSD-3-Clause; full notice below. The tracked DLL has SHA-256 `b0cc4697b2fd1b4163fddca2050fc62a9e7d221864f1bd11e739144c90b685b3`. |

The Cargo license gate is run separately for the main Rust workspace and the standalone Tauri workspace:

```text
cargo deny --manifest-path rust/Cargo.toml check licenses
cargo deny --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml check licenses
```

Allowing a license in `deny.toml` means the dependency is known and accepted by the automated inventory; it is not a legal conclusion about every possible distribution model.

## mDNSResponder DNS-SD source and binary provenance

The Windows build fetches the exact source revision `f783506af3836b39b83fc14115bc2728a49db4b2` from [apple-oss-distributions/mDNSResponder](https://github.com/apple-oss-distributions/mDNSResponder/tree/f783506af3836b39b83fc14115bc2728a49db4b2), then builds the x64 Release DNS-SD client DLL, DLL stub/import library, and Windows service with the runner's Visual Studio toolchain. The installer redistributes the client DLL and service executable, plus the upstream `LICENSE` summary, the complete Apache-2.0 text as `LICENSE-APACHE-2.0.txt`, source/revision metadata and SHA-256 inventory under `licenses/mDNSResponder`. The Apache license text is fetched from the Apache Software Foundation's canonical URL and verified against a pinned SHA-256 before packaging. The header and import library are used for compilation/linking but are not included in the installed product. The CMake install tree and SBOM include the client DLL, service executable and license materials; the installer smoke checks their presence and service lifecycle.

The upstream repository contains components with different licenses. The pinned repository `LICENSE` and file-level notices are the source of truth for each built component; its `LICENSE` is only a summary and says most source is Apache-2.0 while the shared DNS-SD client code uses Three-Clause BSD. Keep the exact upstream `LICENSE`, the complete Apache-2.0 license text, the BSD-3-Clause DNS-SD notice reproduced below, applicable per-file notices, and the generated provenance/hash inventory with the package. Do not use Apple names or marks to endorse the fork. The service's upstream Windows implementation uses the service display name “Bonjour Service”; public distribution remains subject to the required legal/trademark review for this specific source-built product.

The proprietary Apple Bonjour installer/runtime is not bundled. Apple's separate [Bonjour for Windows software distribution agreement](https://developer.apple.com/licensing-trademarks/files/bonjour4win.pdf) describes terms for Apple's proprietary Windows distribution and does not itself grant this project permission. This source-build route is technically distinct, but it is not a legal clearance: binary release remains blocked until the exact source files, license obligations, service naming/trademark issues and redistributable package are reviewed and approved.

## Apple DNS-SD header and Windows DLL stub — BSD 3-Clause License

Copyright (c) 2003-2015 Apple Inc. All rights reserved.

Copyright (c) 2009, Apple Computer, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of Apple Inc. ("Apple"), nor the name of Apple Computer, Inc., nor the names of their contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Names and artwork

The Input Leap name and artwork identify the upstream project. Icon files under `res/` and `rust/apps/input-leap/src-tauri/icons/` originate from or adapt the upstream Input Leap artwork and are carried with the project source license unless an adjacent notice states otherwise. This fork must be presented as unofficial and must not imply endorsement by upstream maintainers or third parties.

## isxdl 5.1.0 — BSD 3-Clause License

Copyright (c) 2002-2009, Bjørnar Henden

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Source: <https://github.com/KrinkelsTeam/isxdl>

## GoogleTest/GoogleMock — BSD 3-Clause License

Copyright 2008, Google Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
- Neither the name of Google Inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Source: <https://github.com/google/googletest>

## gulrak/filesystem — MIT License

Copyright (c) 2018, Steffen Schümann <s.schuemann@pobox.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Source: <https://github.com/gulrak/filesystem>
