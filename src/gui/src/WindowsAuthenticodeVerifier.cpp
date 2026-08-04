#include "WindowsAuthenticodeVerifier.h"

#define NOMINMAX
#include <Windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

namespace WindowsAuthenticode {

Verification inspect(const QString& path)
{
    if (path.isEmpty())
        return {};

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = reinterpret_cast<LPCWSTR>(path.utf16());

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = WinVerifyTrust(nullptr, &policy, &trustData);
    Verification result;
    result.nativeTrustStatus = status;
    if (status == ERROR_SUCCESS) {
        const CRYPT_PROVIDER_DATA* provider =
            WTHelperProvDataFromStateData(trustData.hWVTStateData);
        const CRYPT_PROVIDER_SGNR* signer = provider == nullptr
            ? nullptr : WTHelperGetProvSignerFromChain(
                const_cast<CRYPT_PROVIDER_DATA*>(provider), 0, FALSE, 0);
        const CRYPT_PROVIDER_CERT* certificate = signer == nullptr
            ? nullptr : WTHelperGetProvCertFromChain(
                const_cast<CRYPT_PROVIDER_SGNR*>(signer), 0);
        DWORD digestSize = 0;
        if (certificate != nullptr && certificate->pCert != nullptr &&
            CertGetCertificateContextProperty(
                certificate->pCert, CERT_SHA256_HASH_PROP_ID, nullptr,
                &digestSize) && digestSize == 32) {
            result.signerSha256.resize(int(digestSize));
            if (CertGetCertificateContextProperty(
                    certificate->pCert, CERT_SHA256_HASH_PROP_ID,
                    result.signerSha256.data(), &digestSize)) {
                result.trusted = true;
            }
            else {
                result.signerSha256.clear();
            }
        }
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &trustData);
    return result;
}

bool verifyPinnedPublisher(const QString& path,
                           const QByteArray& expectedSignerSha256)
{
    if (expectedSignerSha256.size() != 32)
        return false;
    const Verification result = inspect(path);
    return result.trusted && result.signerSha256 == expectedSignerSha256;
}

}
