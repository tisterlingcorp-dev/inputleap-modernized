/* InputLeap -- move-only owned sensitive byte buffer with deterministic cleansing. */
#pragma once

#include <QByteArray>
#include <QByteArrayView>

#include <openssl/crypto.h>

#include <utility>

class SensitiveBytes
{
public:
    SensitiveBytes() = default;
    explicit SensitiveBytes(QByteArray bytes) : bytes_(std::move(bytes))
    {
        bytes_.detach();
    }

    SensitiveBytes(const SensitiveBytes&) = delete;
    SensitiveBytes& operator=(const SensitiveBytes&) = delete;

    SensitiveBytes(SensitiveBytes&& other) noexcept : bytes_(std::move(other.bytes_))
    {
        other.bytes_.clear();
    }

    SensitiveBytes& operator=(SensitiveBytes&& other) noexcept
    {
        if (this != &other) {
            cleanse();
            bytes_ = std::move(other.bytes_);
            other.bytes_.clear();
        }
        return *this;
    }

    ~SensitiveBytes() { cleanse(); }

    bool isEmpty() const { return bytes_.isEmpty(); }
    qsizetype size() const { return bytes_.size(); }
    QByteArrayView bytes() const { return QByteArrayView(bytes_); }

    bool securelyEquals(QByteArrayView other) const
    {
        return bytes_.size() == other.size() &&
               (bytes_.isEmpty() ||
                CRYPTO_memcmp(bytes_.constData(), other.data(),
                              static_cast<size_t>(bytes_.size())) == 0);
    }

    void clear()
    {
        cleanse();
        bytes_.clear();
    }

private:
    void cleanse()
    {
        if (!bytes_.isEmpty())
            OPENSSL_cleanse(bytes_.data(), static_cast<size_t>(bytes_.size()));
    }

    QByteArray bytes_;
};
