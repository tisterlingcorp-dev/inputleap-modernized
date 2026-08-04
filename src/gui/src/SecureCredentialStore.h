#pragma once

#include "SensitiveBytes.h"

#include <QByteArray>
#include <QString>
#include <functional>
#include <optional>

class QSettings;

class SecureCredentialStore
{
public:
    enum class CompareAndSwapResult { Success, Mismatch, Error, Indeterminate };
    struct ReadResult {
        enum class Status { Found, NotFound, Error };
        Status status = Status::Error;
        SensitiveBytes value;

        static ReadResult found(QByteArray value)
        {
            return {Status::Found, SensitiveBytes(std::move(value))};
        }
        static ReadResult notFound() { return {Status::NotFound, SensitiveBytes{}}; }
        static ReadResult error() { return {Status::Error, SensitiveBytes{}}; }
        bool has_value() const { return status == Status::Found; }
        explicit operator bool() const { return has_value(); }
        SensitiveBytes& operator*() { return value; }
        const SensitiveBytes& operator*() const { return value; }
        SensitiveBytes* operator->() { return &value; }
        const SensitiveBytes* operator->() const { return &value; }
    };
    using Read = std::function<ReadResult(const QString&)>;
    using LegacyRead = std::function<std::optional<QByteArray>(const QString&)>;
    using Write = std::function<bool(const QString&, const QByteArray&)>;
    using Remove = std::function<bool(const QString&)>;

    SecureCredentialStore(Read read = {}, Write write = {}, Remove remove = {});
    SecureCredentialStore(LegacyRead read, Write write, Remove remove);
    bool available() const;
    ReadResult read(const QString& account) const;
    bool write(const QString& account, const QByteArray& secret) const;
    bool remove(const QString& account) const;
    // Atomic for InputLeap processes that honor the per-account lock. Native
    // credential backends do not expose CAS against unrelated direct writers.
    CompareAndSwapResult compareAndSwap(
        const QString& account,
        const std::optional<QByteArrayView>& expected,
        const std::optional<QByteArrayView>& candidate) const;

    // Moves a legacy QSettings value without exposing it in diagnostics. On
    // failure it never intentionally removes the last verified durable copy;
    // an indeterminate rollback may conservatively leave both copies.
    static bool migrate(QSettings& settings, const QString& legacyKey,
                        SecureCredentialStore& store, const QString& account,
                        const std::function<bool(QSettings&)>& sync = {},
                        bool settingsLockHeld = false);

private:
    Read read_;
    Write write_;
    Remove remove_;
};
