/* InputLeap -- strict versioned plaintext format inside the authenticated sensitive envelope. */
#include "ConfigurationSensitivePayload.h"

#include <QtEndian>
#include <QScopeGuard>

#include <cstring>

namespace {
constexpr char Magic[] = {'I', 'L', 'S', 'P'};
constexpr quint8 Version = 1;
constexpr quint8 Absent = 0;
constexpr quint8 Present = 1;
constexpr qsizetype HeaderBytes = 10;

bool validUtf8(const QByteArray& bytes)
{
    qsizetype i = 0;
    while (i < bytes.size()) {
        const auto first = static_cast<unsigned char>(bytes.at(i));
        if (first <= 0x7f) {
            ++i;
            continue;
        }
        int count = 0;
        quint32 codePoint = 0;
        quint32 minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 2; codePoint = first & 0x1f; minimum = 0x80;
        }
        else if (first >= 0xe0 && first <= 0xef) {
            count = 3; codePoint = first & 0x0f; minimum = 0x800;
        }
        else if (first >= 0xf0 && first <= 0xf4) {
            count = 4; codePoint = first & 0x07; minimum = 0x10000;
        }
        else {
            return false;
        }
        if (i + count > bytes.size())
            return false;
        for (int offset = 1; offset < count; ++offset) {
            const auto continuation = static_cast<unsigned char>(bytes.at(i + offset));
            if ((continuation & 0xc0) != 0x80)
                return false;
            codePoint = (codePoint << 6) | (continuation & 0x3f);
        }
        if (codePoint < minimum || codePoint > 0x10ffff ||
            (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
            return false;
        }
        i += count;
    }
    return true;
}
}

SensitiveBytes ConfigurationSensitivePayload::encode(const Snapshot& snapshot)
{
    const QByteArrayView code = snapshot.pairingCode ? snapshot.pairingCode->bytes()
                                                     : QByteArrayView{};
    if (code.size() > MaxPairingCodeBytes)
        return SensitiveBytes{};
    const quint32 length = snapshot.pairingCode ? static_cast<quint32>(code.size()) : 0;
    QByteArray encoded(HeaderBytes + length, Qt::Uninitialized);
    for (qsizetype i = 0; i < 4; ++i)
        encoded[i] = Magic[i];
    encoded[4] = static_cast<char>(Version);
    encoded[5] = static_cast<char>(snapshot.pairingCode ? Present : Absent);
    qToBigEndian(length, encoded.data() + 6);
    if (!code.isEmpty())
        std::memcpy(encoded.data() + HeaderBytes, code.data(), static_cast<size_t>(code.size()));
    return SensitiveBytes(std::move(encoded));
}

ConfigurationSensitivePayload::DecodeResult
ConfigurationSensitivePayload::decode(const SensitiveBytes& plaintext)
{
    const QByteArrayView bytes = plaintext.bytes();
    if (bytes.size() < HeaderBytes ||
        std::memcmp(bytes.data(), Magic, sizeof(Magic)) != 0) {
        return {Error::Malformed, std::nullopt};
    }
    if (static_cast<quint8>(bytes.at(4)) != Version)
        return {Error::UnsupportedVersion, std::nullopt};
    const quint8 state = static_cast<quint8>(bytes.at(5));
    if (state != Absent && state != Present)
        return {Error::InvalidState, std::nullopt};
    const quint32 length = qFromBigEndian<quint32>(bytes.data() + 6);
    if (length > MaxPairingCodeBytes)
        return {Error::TooLarge, std::nullopt};
    if (bytes.size() != HeaderBytes + static_cast<qsizetype>(length) ||
        (state == Absent && length != 0) || (state == Present && length == 0)) {
        return {Error::Malformed, std::nullopt};
    }

    Snapshot snapshot;
    if (state == Present) {
        QByteArray code(bytes.data() + HeaderBytes, static_cast<qsizetype>(length));
        const auto cleanseCode = qScopeGuard([&code] {
            if (!code.isEmpty())
                OPENSSL_cleanse(code.data(), static_cast<size_t>(code.size()));
        });
        if (!validUtf8(code)) {
            return {Error::InvalidUtf8, std::nullopt};
        }
        QString text = QString::fromUtf8(code);
        const auto cleanseText = qScopeGuard([&text] {
            if (!text.isEmpty())
                OPENSSL_cleanse(text.data(),
                                static_cast<size_t>(text.size() * sizeof(QChar)));
        });
        QString normalizedText = text.trimmed();
        const auto cleanseNormalizedText = qScopeGuard([&normalizedText] {
            if (!normalizedText.isEmpty())
                OPENSSL_cleanse(normalizedText.data(),
                                static_cast<size_t>(normalizedText.size() * sizeof(QChar)));
        });
        QByteArray normalized = normalizedText.toUtf8();
        if (normalized.isEmpty())
            return {Error::Malformed, std::nullopt};
        snapshot.pairingCode.emplace(std::move(normalized));
    }
    return {Error::None, std::move(snapshot)};
}
