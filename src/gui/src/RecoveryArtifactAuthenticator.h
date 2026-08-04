/* InputLeap -- authenticated recovery artifact bindings. */
#pragma once

#include "SecureCredentialStore.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QScopeGuard>
#include <QString>
#include <QVector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <optional>

class RecoveryArtifactAuthenticator
{
public:
    static constexpr qsizetype KeySize = 32;

    static std::optional<SensitiveBytes> loadKey(
        const SecureCredentialStore& store, const QString& account)
    {
        auto stored = store.read(account);
        if (!stored || stored->size() != KeySize) return std::nullopt;
        return std::move(stored.value);
    }

    static std::optional<SensitiveBytes> loadOrCreateKey(
        const SecureCredentialStore& store, const QString& account)
    {
        auto stored = store.read(account);
        if (stored.status == SecureCredentialStore::ReadResult::Status::Found)
            return stored->size() == KeySize
                ? std::optional<SensitiveBytes>(std::move(stored.value))
                : std::nullopt;
        if (stored.status != SecureCredentialStore::ReadResult::Status::NotFound)
            return std::nullopt;

        QByteArray generated(KeySize, Qt::Uninitialized);
        const auto cleanse = qScopeGuard([&generated] {
            if (!generated.isEmpty())
                OPENSSL_cleanse(generated.data(), static_cast<size_t>(generated.size()));
        });
        if (RAND_bytes(reinterpret_cast<unsigned char*>(generated.data()),
                       static_cast<int>(generated.size())) != 1 ||
            !store.write(account, generated)) {
            return std::nullopt;
        }
        auto verified = store.read(account);
        if (!verified || verified->size() != KeySize ||
            !verified->securelyEquals(QByteArrayView(generated))) {
            return std::nullopt;
        }
        return std::move(verified.value);
    }

    static QByteArray authenticate(QByteArrayView key, QByteArrayView domain,
                                   const QVector<QByteArrayView>& parts)
    {
        if (key.size() != KeySize) return {};
        QByteArray payload;
        const auto append = [&payload](QByteArrayView value) {
            const QByteArray size = QByteArray::number(value.size());
            payload.append(size);
            payload.append(':');
            payload.append(value.data(), value.size());
        };
        append(domain);
        for (const auto part : parts) append(part);
        const auto cleanse = qScopeGuard([&payload] {
            if (!payload.isEmpty())
                OPENSSL_cleanse(payload.data(), static_cast<size_t>(payload.size()));
        });
        unsigned int outputSize = EVP_MAX_MD_SIZE;
        QByteArray output(outputSize, Qt::Uninitialized);
        if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                 reinterpret_cast<const unsigned char*>(payload.constData()),
                 static_cast<size_t>(payload.size()),
                 reinterpret_cast<unsigned char*>(output.data()), &outputSize) == nullptr) {
            return {};
        }
        output.resize(static_cast<qsizetype>(outputSize));
        return output;
    }

    static bool verify(QByteArrayView key, QByteArrayView domain,
                       const QVector<QByteArrayView>& parts,
                       QByteArrayView expected)
    {
        const QByteArray actual = authenticate(key, domain, parts);
        return !actual.isEmpty() && actual.size() == expected.size() &&
            CRYPTO_memcmp(actual.constData(), expected.data(),
                          static_cast<size_t>(actual.size())) == 0;
    }
};
