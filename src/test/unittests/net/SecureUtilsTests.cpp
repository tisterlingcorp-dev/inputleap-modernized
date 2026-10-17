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
#include <array>
#include <chrono>
#include <filesystem>
#include <system_error>
#include <memory>
#include <openssl/x509.h>
#include "base/finally.h"
#include "io/filesystem.h"
#include "test/global/TestUtils.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Aclapi.h>
#endif

namespace inputleap {

#if defined(_WIN32)
namespace {

void expectProtectedPrivateFileDacl(const fs::path& path)
{
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD result = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &dacl, nullptr, &descriptor);
    ASSERT_EQ(result, ERROR_SUCCESS);
    const auto freeDescriptor = finally([descriptor]() { LocalFree(descriptor); });

    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    ASSERT_TRUE(GetSecurityDescriptorControl(descriptor, &control, &revision));
    EXPECT_NE(control & SE_DACL_PROTECTED, 0);

    ACL_SIZE_INFORMATION aclInfo{};
    ASSERT_TRUE(GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation));
    ASSERT_EQ(aclInfo.AceCount, 3u);

    HANDLE token = nullptr;
    ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    const auto closeToken = finally([token]() { CloseHandle(token); });
    DWORD tokenUserSize = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &tokenUserSize);
    ASSERT_GT(tokenUserSize, 0u);
    std::vector<std::uint8_t> tokenUserBuffer(tokenUserSize);
    ASSERT_TRUE(GetTokenInformation(token, TokenUser, tokenUserBuffer.data(), tokenUserSize,
                                    &tokenUserSize));
    const PSID userSid = reinterpret_cast<TOKEN_USER*>(tokenUserBuffer.data())->User.Sid;

    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> systemSid{};
    DWORD systemSidSize = static_cast<DWORD>(systemSid.size());
    ASSERT_TRUE(CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &systemSidSize));
    std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> administratorsSid{};
    DWORD administratorsSidSize = static_cast<DWORD>(administratorsSid.size());
    ASSERT_TRUE(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
                                   administratorsSid.data(), &administratorsSidSize));

    bool foundUser = false;
    bool foundSystem = false;
    bool foundAdministrators = false;
    for (DWORD index = 0; index < aclInfo.AceCount; ++index) {
        LPVOID rawAce = nullptr;
        ASSERT_TRUE(GetAce(dacl, index, &rawAce));
        const auto* header = static_cast<ACE_HEADER*>(rawAce);
        ASSERT_EQ(header->AceType, ACCESS_ALLOWED_ACE_TYPE);
        const auto* allowedAce = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
        EXPECT_EQ(allowedAce->Mask, FILE_ALL_ACCESS);
        const PSID sid = const_cast<DWORD*>(&allowedAce->SidStart);
        foundUser |= EqualSid(sid, userSid) != FALSE;
        foundSystem |= EqualSid(sid, systemSid.data()) != FALSE;
        foundAdministrators |= EqualSid(sid, administratorsSid.data()) != FALSE;
    }
    EXPECT_TRUE(foundUser);
    EXPECT_TRUE(foundSystem);
    EXPECT_TRUE(foundAdministrators);
}

} // namespace
#endif

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

#if defined(_WIN32)
TEST(SecureUtilsTest, PrivateCertificateFileHasProtectedAllowlistDacl)
{
    const auto suffix = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const auto directory = fs::temp_directory_path();
    const auto existingPath = directory / ("inputleap-private-existing-" + suffix + ".pem");
    const auto generatedPath = directory / ("inputleap-private-generated-" + suffix + ".pem");
    const auto cleanup = finally([&]() {
        std::error_code ignored;
        fs::remove(existingPath, ignored);
        fs::remove(generatedPath, ignored);
    });

    EXPECT_FALSE(secure_private_file_permissions(path_to_utf8(directory)));

    HANDLE existingFile = CreateFileW(existingPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                      CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(existingFile, INVALID_HANDLE_VALUE);
    CloseHandle(existingFile);

    ASSERT_TRUE(secure_private_file_permissions(path_to_utf8(existingPath)));
    expectProtectedPrivateFileDacl(existingPath);

    ASSERT_NO_THROW(generate_pem_self_signed_cert(path_to_utf8(generatedPath)));
    ASSERT_TRUE(fs::is_regular_file(generatedPath));
    expectProtectedPrivateFileDacl(generatedPath);
}
#endif

} // namespace inputleap
