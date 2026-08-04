/* InputLeap -- authenticated password-encrypted sensitive configuration envelope. */
#pragma once

#include "SensitiveBytes.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QJsonObject>
#include <QString>

#include <optional>

class ConfigurationSensitiveEnvelope
{
public:
    static constexpr int KdfIterations = 600000;
    static constexpr qsizetype MaxPlaintextBytes = 1024 * 1024;
    static constexpr qsizetype MaxPasswordBytes = 1024;

    enum class Error {
        None,
        PasswordRequired,
        InvalidAssociatedData,
        TooLarge,
        UnknownField,
        MissingField,
        InvalidType,
        InvalidEncoding,
        UnsupportedParameters,
        CryptoFailure,
        AuthenticationFailed
    };

    struct EncryptResult {
        Error error = Error::CryptoFailure;
        std::optional<QJsonObject> envelope;
    };
    struct DecryptResult {
        Error error = Error::CryptoFailure;
        std::optional<SensitiveBytes> plaintext;
    };

    static EncryptResult encrypt(QByteArrayView plaintext, const SensitiveBytes& password,
                                 const QByteArray& publicSnapshotDigest);
    static DecryptResult decrypt(const QJsonObject& envelope, const SensitiveBytes& password,
                                 const QByteArray& publicSnapshotDigest);
};
