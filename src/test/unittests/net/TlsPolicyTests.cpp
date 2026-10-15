/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2026 InputLeap contributors
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 */

#include "net/TlsPolicy.h"

#include <gtest/gtest.h>

namespace inputleap {

TEST(TlsPolicyTests, SetsTls12MinimumAndLeavesMaximumUnrestricted)
{
    SSL_CTX* context = SSL_CTX_new(TLS_method());
    ASSERT_NE(context, nullptr);

    EXPECT_TRUE(configureMinimumTlsVersion(context));
    EXPECT_EQ(SSL_CTX_get_min_proto_version(context), TLS1_2_VERSION);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(context), 0);
    EXPECT_EQ(SSL_CTX_get_max_proto_version(context), 0);

    SSL_CTX_free(context);
}

TEST(TlsPolicyTests, RejectsNullContext)
{
    EXPECT_FALSE(configureMinimumTlsVersion(nullptr));
}

} // namespace inputleap
