/*
    InputLeap -- mouse and keyboard sharing utility
    Copyright (C) 2021 InputLeap contributors

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

#include "net/SecureUtils.h"

#include <gtest/gtest.h>
#include <memory>
#include <openssl/x509.h>
#include "test/global/TestUtils.h"

namespace inputleap {

TEST(SecureUtilsTest, FormatSslFingerprintHexWithSeparators)
{
    auto fingerprint = generate_pseudo_random_bytes(0, 32);
    ASSERT_EQ(format_ssl_fingerprint(fingerprint, true),
              "28:FD:0A:98:8A:0E:A1:6C:D7:E8:6C:A7:EE:58:41:71:"
              "CA:B2:8E:49:25:94:90:25:26:05:8D:AF:63:ED:2E:30");
}

TEST(SecureUtilsTest, CreateFingerprintRandomArt)
{
    ASSERT_EQ(create_fingerprint_randomart(generate_pseudo_random_bytes(0, 32)),
              "+-----------------+\n"
              "|*X+. .           |\n"
              "|*oo +            |\n"
              "| + =             |\n"
              "|  B  . .         |\n"
              "|.+... o S        |\n"
              "|E+ ++. .         |\n"
              "|B*++..  .        |\n"
              "|+o*o o .         |\n"
              "|+o*Bo .          |\n"
              "+-----------------+");
    ASSERT_EQ(create_fingerprint_randomart(generate_pseudo_random_bytes(1, 32)),
              "+-----------------+\n"
              "|  .oo+ .    .B=. |\n"
              "| .o.+ . o   o.=  |\n"
              "|o..+.. o . E *   |\n"
              "|oo..+ .   * *    |\n"
              "|B o.....S. o .   |\n"
              "|+=o.....         |\n"
              "| + + .           |\n"
              "|o. ..            |\n"
              "|..o..            |\n"
              "+-----------------+");
    ASSERT_EQ(create_fingerprint_randomart(generate_pseudo_random_bytes(2, 32)),
              "+-----------------+\n"
              "|    ...     .o.o.|\n"
              "|     o       .=.E|\n"
              "|    . + o   ...+.|\n"
              "|     * o = o ... |\n"
              "|    * + S & .    |\n"
              "|     = + % @     |\n"
              "|    . . = X o    |\n"
              "|     . . O .     |\n"
              "|        . +      |\n"
              "+-----------------+");
}

TEST(SecureUtilsTest, CertificateMustBeWithinItsValidityPeriod)
{
    X509* certificate = X509_new();
    ASSERT_NE(certificate, nullptr);
    const auto certificate_free = std::unique_ptr<X509, decltype(&X509_free)>(certificate, X509_free);

    ASSERT_TRUE(X509_gmtime_adj(X509_get_notBefore(certificate), -60));
    ASSERT_TRUE(X509_gmtime_adj(X509_get_notAfter(certificate), 60));
    EXPECT_TRUE(is_ssl_certificate_current(certificate));

    ASSERT_TRUE(X509_gmtime_adj(X509_get_notBefore(certificate), 3600));
    EXPECT_FALSE(is_ssl_certificate_current(certificate));

    ASSERT_TRUE(X509_gmtime_adj(X509_get_notBefore(certificate), -7200));
    ASSERT_TRUE(X509_gmtime_adj(X509_get_notAfter(certificate), -3600));
    EXPECT_FALSE(is_ssl_certificate_current(certificate));
}

TEST(SecureUtilsTest, CertificateWithMissingValidityDatesIsRejected)
{
    X509* certificate = X509_new();
    ASSERT_NE(certificate, nullptr);
    const auto certificate_free = std::unique_ptr<X509, decltype(&X509_free)>(certificate, X509_free);

    EXPECT_FALSE(is_ssl_certificate_current(certificate));
}

} // namespace inputleap
