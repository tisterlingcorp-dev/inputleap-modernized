/* InputLeap -- authenticated password-encrypted sensitive configuration envelope. */
#include "ConfigurationSensitiveEnvelope.h"

#include <QSet>
#include <QStringList>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cmath>
#include <memory>
#include <utility>

namespace {
using Error = ConfigurationSensitiveEnvelope::Error;
constexpr int SaltBytes = 16;
constexpr int NonceBytes = 12;
constexpr int TagBytes = 16;
constexpr int KeyBytes = 32;
const QByteArray AadDomain("inputleap-configuration:sensitive:v1:");
const QString CipherValue = QStringLiteral("AES-256-GCM");
const QString KdfValue = QStringLiteral("PBKDF2-HMAC-SHA256");
const QStringList Fields{QStringLiteral("cipher"), QStringLiteral("kdf"),
                         QStringLiteral("iterations"), QStringLiteral("salt"),
                         QStringLiteral("nonce"), QStringLiteral("ciphertext"),
                         QStringLiteral("tag")};

struct CleanByteArray {
    QByteArray value;
    ~CleanByteArray()
    {
        if (!value.isEmpty())
            OPENSSL_cleanse(value.data(), static_cast<size_t>(value.size()));
    }
};

struct KeyMaterial {
    std::array<unsigned char, KeyBytes> value{};
    ~KeyMaterial() { OPENSSL_cleanse(value.data(), value.size()); }
};

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

bool deriveKey(QByteArrayView password, const QByteArray& salt, KeyMaterial& key)
{
    return PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                             reinterpret_cast<const unsigned char*>(salt.constData()),
                             static_cast<int>(salt.size()),
                             ConfigurationSensitiveEnvelope::KdfIterations, EVP_sha256(),
                             KeyBytes, key.value.data()) == 1;
}

QString encodeBase64(const QByteArray& value)
{
    return QString::fromLatin1(value.toBase64());
}

std::optional<QByteArray> decodeBase64(const QJsonValue& value)
{
    if (!value.isString())
        return std::nullopt;
    const QByteArray encoded = value.toString().toLatin1();
    const QByteArray decoded = QByteArray::fromBase64(
        encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.toBase64() != encoded)
        return std::nullopt;
    return decoded;
}

Error validateShape(const QJsonObject& envelope)
{
    const QSet<QString> allowed(Fields.begin(), Fields.end());
    for (const QString& key : envelope.keys()) {
        if (!allowed.contains(key))
            return Error::UnknownField;
    }
    for (const QString& key : Fields) {
        if (!envelope.contains(key))
            return Error::MissingField;
    }
    for (const QString& key : {QStringLiteral("cipher"), QStringLiteral("kdf"),
                               QStringLiteral("salt"), QStringLiteral("nonce"),
                               QStringLiteral("ciphertext"), QStringLiteral("tag")}) {
        if (!envelope.value(key).isString())
            return Error::InvalidType;
    }
    if (!envelope.value(QStringLiteral("iterations")).isDouble())
        return Error::InvalidType;
    return Error::None;
}

bool validPassword(const SensitiveBytes& password, Error& error)
{
    if (password.isEmpty()) {
        error = Error::PasswordRequired;
        return false;
    }
    if (password.size() > ConfigurationSensitiveEnvelope::MaxPasswordBytes) {
        error = Error::TooLarge;
        return false;
    }
    return true;
}
}

ConfigurationSensitiveEnvelope::EncryptResult
ConfigurationSensitiveEnvelope::encrypt(QByteArrayView plaintext, const SensitiveBytes& password,
                                        const QByteArray& publicSnapshotDigest)
{
    if (publicSnapshotDigest.size() != 32)
        return {Error::InvalidAssociatedData, std::nullopt};
    if (plaintext.size() > MaxPlaintextBytes)
        return {Error::TooLarge, std::nullopt};
    Error passwordError = Error::None;
    if (!validPassword(password, passwordError))
        return {passwordError, std::nullopt};

    QByteArray salt(SaltBytes, Qt::Uninitialized);
    QByteArray nonce(NonceBytes, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), SaltBytes) != 1 ||
        RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), NonceBytes) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }
    KeyMaterial key;
    if (!deriveKey(password.bytes(), salt, key))
        return {Error::CryptoFailure, std::nullopt};

    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context || EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, NonceBytes, nullptr) != 1 ||
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.value.data(),
                           reinterpret_cast<const unsigned char*>(nonce.constData())) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }
    int length = 0;
    const QByteArray associatedData = AadDomain + publicSnapshotDigest;
    if (EVP_EncryptUpdate(context.get(), nullptr, &length,
                          reinterpret_cast<const unsigned char*>(associatedData.constData()),
                          static_cast<int>(associatedData.size())) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }

    QByteArray ciphertext(plaintext.size() + TagBytes, Qt::Uninitialized);
    int ciphertextLength = 0;
    if (EVP_EncryptUpdate(context.get(), reinterpret_cast<unsigned char*>(ciphertext.data()),
                          &length, reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }
    ciphertextLength = length;
    if (EVP_EncryptFinal_ex(context.get(),
                            reinterpret_cast<unsigned char*>(ciphertext.data()) + ciphertextLength,
                            &length) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }
    ciphertextLength += length;
    ciphertext.resize(ciphertextLength);
    QByteArray tag(TagBytes, Qt::Uninitialized);
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, TagBytes, tag.data()) != 1)
        return {Error::CryptoFailure, std::nullopt};

    QJsonObject envelope{{QStringLiteral("cipher"), CipherValue},
                         {QStringLiteral("kdf"), KdfValue},
                         {QStringLiteral("iterations"), KdfIterations},
                         {QStringLiteral("salt"), encodeBase64(salt)},
                         {QStringLiteral("nonce"), encodeBase64(nonce)},
                         {QStringLiteral("ciphertext"), encodeBase64(ciphertext)},
                         {QStringLiteral("tag"), encodeBase64(tag)}};
    return {Error::None, std::move(envelope)};
}

ConfigurationSensitiveEnvelope::DecryptResult
ConfigurationSensitiveEnvelope::decrypt(const QJsonObject& envelope, const SensitiveBytes& password,
                                        const QByteArray& publicSnapshotDigest)
{
    if (publicSnapshotDigest.size() != 32)
        return {Error::InvalidAssociatedData, std::nullopt};
    Error result = validateShape(envelope);
    if (result != Error::None)
        return {result, std::nullopt};
    if (envelope.value(QStringLiteral("cipher")).toString() != CipherValue ||
        envelope.value(QStringLiteral("kdf")).toString() != KdfValue) {
        return {Error::UnsupportedParameters, std::nullopt};
    }
    const double iterations = envelope.value(QStringLiteral("iterations")).toDouble();
    if (!std::isfinite(iterations) || std::floor(iterations) != iterations ||
        iterations != KdfIterations) {
        return {Error::UnsupportedParameters, std::nullopt};
    }

    const auto salt = decodeBase64(envelope.value(QStringLiteral("salt")));
    const auto nonce = decodeBase64(envelope.value(QStringLiteral("nonce")));
    const auto ciphertext = decodeBase64(envelope.value(QStringLiteral("ciphertext")));
    const auto tag = decodeBase64(envelope.value(QStringLiteral("tag")));
    if (!salt || !nonce || !ciphertext || !tag)
        return {Error::InvalidEncoding, std::nullopt};
    if (salt->size() != SaltBytes || nonce->size() != NonceBytes || tag->size() != TagBytes)
        return {Error::InvalidEncoding, std::nullopt};
    if (ciphertext->size() > MaxPlaintextBytes)
        return {Error::TooLarge, std::nullopt};

    Error passwordError = Error::None;
    if (!validPassword(password, passwordError))
        return {passwordError, std::nullopt};
    KeyMaterial key;
    if (!deriveKey(password.bytes(), *salt, key))
        return {Error::CryptoFailure, std::nullopt};

    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context || EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN, NonceBytes, nullptr) != 1 ||
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.value.data(),
                           reinterpret_cast<const unsigned char*>(nonce->constData())) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }
    int length = 0;
    const QByteArray associatedData = AadDomain + publicSnapshotDigest;
    if (EVP_DecryptUpdate(context.get(), nullptr, &length,
                          reinterpret_cast<const unsigned char*>(associatedData.constData()),
                          static_cast<int>(associatedData.size())) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }

    CleanByteArray plaintext;
    plaintext.value.resize(ciphertext->size() + TagBytes);
    int plaintextLength = 0;
    if (EVP_DecryptUpdate(context.get(), reinterpret_cast<unsigned char*>(plaintext.value.data()),
                          &length, reinterpret_cast<const unsigned char*>(ciphertext->constData()),
                          static_cast<int>(ciphertext->size())) != 1) {
        return {Error::CryptoFailure, std::nullopt};
    }
    plaintextLength = length;
    QByteArray mutableTag = *tag;
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, TagBytes, mutableTag.data()) != 1)
        return {Error::CryptoFailure, std::nullopt};
    if (EVP_DecryptFinal_ex(context.get(),
                            reinterpret_cast<unsigned char*>(plaintext.value.data()) + plaintextLength,
                            &length) != 1) {
        return {Error::AuthenticationFailed, std::nullopt};
    }
    plaintextLength += length;
    plaintext.value.resize(plaintextLength);
    SensitiveBytes output(std::move(plaintext.value));
    return {Error::None, std::move(output)};
}
