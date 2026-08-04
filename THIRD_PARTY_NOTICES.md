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
| mDNSResponder / Bonjour SDK-like files | Windows discovery build inputs (`dns_sd.h`, `dnssd.lib` and `dnssd.pdb`) downloaded from the pinned `nelsonjchen/mDNSResponder` release | The upstream `LICENSE` states that most source is Apache-2.0, shared-library code is BSD-3-Clause and NSS code uses the NICTA license. The binary archive does not include a license file; determine the applicable per-file terms and include the required license texts before binary redistribution. Provenance details follow below. |
| Inno Setup | Optional legacy Windows package compiler, installed separately | Inno Setup is not vendored in this repository. Builders and binary redistributors must follow the license of the installed Inno Setup version. |
| isxdl 5.1.0 | Download helper DLL used only by the legacy Inno scripts | BSD-3-Clause; full notice below. The tracked DLL has SHA-256 `b0cc4697b2fd1b4163fddca2050fc62a9e7d221864f1bd11e739144c90b685b3`. |

The Cargo license gate is run separately for the main Rust workspace and the standalone Tauri workspace:

```text
cargo deny --manifest-path rust/Cargo.toml check licenses
cargo deny --manifest-path rust/apps/input-leap/src-tauri/Cargo.toml check licenses
```

Allowing a license in `deny.toml` means the dependency is known and accepted by the automated inventory; it is not a legal conclusion about every possible distribution model.

## mDNSResponder / Bonjour SDK-like provenance

Windows builds obtain `x64_RelWithDebInfo.zip` from the pinned `nelsonjchen/mDNSResponder` tag `v2019.05.08.1`. The expected archive SHA-256 is `aad489258d047e396a43efff4270571c82e7da5d33cba1710b784b66fd4011f9`; build automation verifies it before extraction. The archive contains `Include/dns_sd.h`, `Lib/x64/dnssd.lib` and `Lib/x64/dnssd.pdb` and is not stored in this source repository.

The source repository's [`LICENSE`](https://github.com/nelsonjchen/mDNSResponder/blob/master/LICENSE) describes mixed licensing: Apache License 2.0 for most source, BSD 3-Clause terms for shared-library code, and the NICTA Public Software Licence for the Name Service Switch code. Because the downloaded binary archive carries no embedded license or per-file mapping, public binary release remains blocked until the applicable terms for these three files and any Bonjour runtime redistribution are reviewed and the required license texts are packaged.

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
