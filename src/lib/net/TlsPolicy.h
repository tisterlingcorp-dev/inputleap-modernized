/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2026 InputLeap contributors
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#pragma once

#include <openssl/ssl.h>

namespace inputleap {

// Configure the minimum protocol used by InputLeap's control channel.
bool configureMinimumTlsVersion(SSL_CTX* context);

} // namespace inputleap
