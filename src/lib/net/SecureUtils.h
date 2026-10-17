/*
    InputLeap -- mouse and keyboard sharing utility
    Copyright (C) InputLeap contributors

    This package is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    found in the file LICENSE that should have accompanied this file.

    This package is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "FingerprintData.h"
#include <openssl/ossl_typ.h>
#include <cstdint>
#include <string>
#include <vector>

namespace inputleap {

std::string format_ssl_fingerprint(const std::vector<std::uint8_t>& fingerprint,
                                   bool separator = true);
std::string format_ssl_fingerprint_columns(const std::vector<uint8_t>& fingerprint);

FingerprintData get_ssl_cert_fingerprint(X509* cert, FingerprintType type);

bool is_ssl_certificate_current(X509* cert);

FingerprintData get_pem_file_cert_fingerprint(const std::string& path, FingerprintType type);

void generate_pem_self_signed_cert(const std::string& path);

// On Windows, create or protect a private file with a DACL granting access
// only to the current user, LocalSystem, and local Administrators.
bool secure_private_file_permissions(const std::string& path);

std::string create_fingerprint_randomart(const std::vector<std::uint8_t>& dgst_raw);

} // namespace inputleap
