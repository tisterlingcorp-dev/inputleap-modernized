/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2026 InputLeap contributors
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#include "TlsPolicy.h"

namespace inputleap {

bool configureMinimumTlsVersion(SSL_CTX* context)
{
    return context != nullptr && SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) == 1;
}

} // namespace inputleap
