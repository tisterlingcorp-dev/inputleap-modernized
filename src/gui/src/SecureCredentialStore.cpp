#include "SecureCredentialStore.h"

#include <QSettings>
#include <QScopeGuard>
#include <QCryptographicHash>
#include <QDir>
#include <QLockFile>

#include <openssl/crypto.h>
#include <limits>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincred.h>
#endif

namespace {
QString credentialLockPath(const QString& account)
{
    const QByteArray digest = QCryptographicHash::hash(
        account.toUtf8(), QCryptographicHash::Sha256).toHex();
    return QDir(QDir::tempPath()).filePath(
        QStringLiteral("inputleap-credential-%1.lock").arg(QString::fromLatin1(digest)));
}

QString portableSettingsLockPath()
{
    return QDir(QDir::tempPath()).filePath(
        QStringLiteral("inputleap-portable-settings.lock"));
}

bool sameCredential(const SecureCredentialStore::ReadResult& current,
                    const std::optional<QByteArrayView>& expected)
{
    if (current.status == SecureCredentialStore::ReadResult::Status::Error)
        return false;
    if (!expected)
        return current.status == SecureCredentialStore::ReadResult::Status::NotFound;
    return current.status == SecureCredentialStore::ReadResult::Status::Found &&
           current.value.securelyEquals(*expected);
}

#ifdef Q_OS_WIN
SecureCredentialStore::ReadResult winRead(const QString& account)
{
    PCREDENTIALW credential = nullptr;
    const auto target = account.toStdWString();
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        return GetLastError() == ERROR_NOT_FOUND
            ? SecureCredentialStore::ReadResult::notFound()
            : SecureCredentialStore::ReadResult::error();
    }
    const auto credentialGuard = qScopeGuard([&credential] {
        if (credential != nullptr) {
            if (credential->CredentialBlob != nullptr && credential->CredentialBlobSize != 0)
                SecureZeroMemory(credential->CredentialBlob, credential->CredentialBlobSize);
            CredFree(credential);
        }
    });
    if ((credential->CredentialBlobSize != 0 && credential->CredentialBlob == nullptr) ||
        credential->CredentialBlobSize > static_cast<DWORD>((std::numeric_limits<int>::max)()))
        return SecureCredentialStore::ReadResult::error();
    QByteArray value(reinterpret_cast<const char*>(credential->CredentialBlob),
                     static_cast<qsizetype>(credential->CredentialBlobSize));
    return SecureCredentialStore::ReadResult::found(std::move(value));
}
bool winWrite(const QString& account, const QByteArray& value)
{
    if (value.size() > static_cast<qsizetype>(CRED_MAX_CREDENTIAL_BLOB_SIZE) ||
        value.size() > static_cast<qsizetype>((std::numeric_limits<DWORD>::max)()))
        return false;
    const auto target = account.toStdWString();
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(target.c_str());
    credential.CredentialBlobSize = static_cast<DWORD>(value.size());
    credential.CredentialBlob = const_cast<LPBYTE>(reinterpret_cast<const BYTE*>(value.constData()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    return CredWriteW(&credential, 0) != FALSE;
}
bool winRemove(const QString& account)
{
    const BOOL deleted = CredDeleteW(account.toStdWString().c_str(), CRED_TYPE_GENERIC, 0);
    if (deleted == FALSE && GetLastError() != ERROR_NOT_FOUND) return false;
    return true;
}
#endif
}

SecureCredentialStore::SecureCredentialStore(Read read, Write write, Remove remove)
    : read_(std::move(read)), write_(std::move(write)), remove_(std::move(remove))
{
#ifdef Q_OS_WIN
    // Any explicit seam injection is a test seam.  Never silently combine it
    // with the production backend: a partial seam must fail closed.
    if (!read_ && !write_ && !remove_) {
        read_ = winRead;
        write_ = winWrite;
        remove_ = winRemove;
    }
#endif
}

SecureCredentialStore::SecureCredentialStore(LegacyRead read, Write write, Remove remove)
    : SecureCredentialStore(
          Read([read = std::move(read)](const QString& account) {
              auto value = read ? read(account) : std::nullopt;
              if (!value)
                  return ReadResult::notFound();
              QByteArray owned = std::move(*value);
              value.reset();
              return ReadResult::found(std::move(owned));
          }),
          std::move(write), std::move(remove))
{
}

bool SecureCredentialStore::available() const { return bool(read_) && bool(write_) && bool(remove_); }
SecureCredentialStore::ReadResult SecureCredentialStore::read(const QString& account) const
{
    if (!read_) return ReadResult::error();
    try {
        return read_(account);
    } catch (...) {
        return ReadResult::error();
    }
}
bool SecureCredentialStore::write(const QString& account, const QByteArray& secret) const
{
    if (account.isEmpty() || secret.isEmpty() || !write_ || !read_)
        return false;
    QLockFile lock(credentialLockPath(account));
    try {
        if (!lock.tryLock(5000))
            return false;
        const ReadResult before = read_(account);
        const bool wrote = write_(account, secret);
        if (!wrote) {
            const ReadResult after = read_(account);
            const bool changed = after.status != before.status ||
                (after.status == ReadResult::Status::Found &&
                 before.status == ReadResult::Status::Found &&
                 !after->securelyEquals(before->bytes()));
            if (changed) {
                if (before.status == ReadResult::Status::Found)
                    write_(account, QByteArray(before->bytes().data(),
                                               before->bytes().size()));
                else if (before.status == ReadResult::Status::NotFound)
                    remove_(account);
            }
            return false;
        }
        const auto verified = read_(account);
        if (verified && verified->securelyEquals(secret))
            return true;
        if (before.status == ReadResult::Status::Found)
            write_(account, QByteArray(before->bytes().data(), before->bytes().size()));
        else if (before.status == ReadResult::Status::NotFound)
            remove_(account);
        const auto restored = read_(account);
        Q_UNUSED(restored);
        return false;
    } catch (...) {
        return false;
    }
}
bool SecureCredentialStore::remove(const QString& account) const
{
    if (account.isEmpty() || !remove_ || !read_)
        return false;
    QLockFile lock(credentialLockPath(account));
    try {
        if (!lock.tryLock(5000))
            return false;
        const ReadResult before = read_(account);
        const bool removed = remove_(account);
        const ReadResult after = read_(account);
        if (removed && after.status == ReadResult::Status::NotFound)
            return true;
        if (before.status == ReadResult::Status::Found)
            remove_(account), write_(account,
                QByteArray(before->bytes().data(), before->bytes().size()));
        return false;
    } catch (...) {
        return false;
    }
}

SecureCredentialStore::CompareAndSwapResult SecureCredentialStore::compareAndSwap(
    const QString& account,
    const std::optional<QByteArrayView>& expected,
    const std::optional<QByteArrayView>& candidate) const
{
    if (account.isEmpty() || !read_ || !write_ || !remove_ ||
        (candidate && candidate->isEmpty())) {
        return CompareAndSwapResult::Error;
    }
    QLockFile lock(credentialLockPath(account));
    if (!lock.tryLock(5000))
        return CompareAndSwapResult::Error;
    ReadResult current;
    try {
        current = read_(account);
    } catch (...) {
        return CompareAndSwapResult::Error;
    }
    if (current.status == ReadResult::Status::Error)
        return CompareAndSwapResult::Error;
    if (!sameCredential(current, expected))
        return CompareAndSwapResult::Mismatch;

    bool mutated = false;
    try {
        if (candidate) {
            QByteArray owned(candidate->data(), candidate->size());
            const auto cleanseOwned = qScopeGuard([&owned] {
                if (!owned.isEmpty())
                    OPENSSL_cleanse(owned.data(), static_cast<size_t>(owned.size()));
            });
            mutated = write_(account, owned);
        } else {
            mutated = remove_(account);
        }
    } catch (...) {
        return CompareAndSwapResult::Indeterminate;
    }
    if (!mutated)
        return CompareAndSwapResult::Error;
    ReadResult verified;
    try {
        verified = read_(account);
    } catch (...) {
        verified = ReadResult::error();
    }
    if (verified.status == ReadResult::Status::Error) {
        bool restored = false;
        try {
            if (expected) {
                QByteArray previous(expected->data(), expected->size());
                const auto cleansePrevious = qScopeGuard([&previous] {
                    if (!previous.isEmpty())
                        OPENSSL_cleanse(previous.data(), static_cast<size_t>(previous.size()));
                });
                restored = write_(account, previous);
            } else {
                restored = remove_(account);
            }
        } catch (...) {
            return CompareAndSwapResult::Indeterminate;
        }
        if (!restored)
            return CompareAndSwapResult::Indeterminate;
        ReadResult rollbackVerified;
        try {
            rollbackVerified = read_(account);
        } catch (...) {
            return CompareAndSwapResult::Indeterminate;
        }
        return sameCredential(rollbackVerified, expected)
            ? CompareAndSwapResult::Error
            : CompareAndSwapResult::Indeterminate;
    }
    if (sameCredential(verified, candidate))
        return CompareAndSwapResult::Success;
    bool restored = false;
    try {
        if (expected) {
            QByteArray previous(expected->data(), expected->size());
            restored = write_(account, previous);
            OPENSSL_cleanse(previous.data(), static_cast<size_t>(previous.size()));
        }
        else {
            restored = remove_(account);
        }
    }
    catch (...) {
        return CompareAndSwapResult::Indeterminate;
    }
    if (!restored)
        return CompareAndSwapResult::Indeterminate;
    ReadResult rollback;
    try { rollback = read_(account); }
    catch (...) { return CompareAndSwapResult::Indeterminate; }
    Q_UNUSED(rollback);
    return CompareAndSwapResult::Indeterminate;
}

bool SecureCredentialStore::migrate(QSettings& settings, const QString& legacyKey,
                                    SecureCredentialStore& store, const QString& account,
                                    const std::function<bool(QSettings&)>& syncFn,
                                    bool settingsLockHeld)
{
    std::unique_ptr<QLockFile> settingsLock;
    if (!settingsLockHeld) {
        settingsLock = std::make_unique<QLockFile>(portableSettingsLockPath());
        if (!settingsLock->tryLock(5000)) return false;
    }
    if (!store.available() || !settings.contains(legacyKey))
        return !settings.contains(legacyKey);
    QString legacyText = settings.value(legacyKey).toString();
    const auto cleanseLegacyText = qScopeGuard([&legacyText] {
        if (!legacyText.isEmpty())
            OPENSSL_cleanse(legacyText.data(),
                            static_cast<size_t>(legacyText.size() * sizeof(QChar)));
    });
    QByteArray legacy = legacyText.toUtf8();
    const auto cleanseLegacy = qScopeGuard([&legacy] {
        if (!legacy.isEmpty())
            OPENSSL_cleanse(legacy.data(), static_cast<size_t>(legacy.size()));
    });
    if (legacy.isEmpty())
        return false;

    const auto existing = store.read(account);
    if (existing.status == ReadResult::Status::Error)
        return false;
    if (existing && !existing->securelyEquals(QByteArrayView(legacy)))
        return false;
    bool installedLegacy = false;
    if (!existing) {
        const auto installed = store.compareAndSwap(
            account, std::nullopt, QByteArrayView(legacy));
        if (installed != CompareAndSwapResult::Success)
            return false;
        installedLegacy = true;
    }

    const auto rollbackInstalledCredential = [&] {
        if (!installedLegacy) return true;
        return store.compareAndSwap(
            account, QByteArrayView(legacy), std::nullopt) ==
            CompareAndSwapResult::Success;
    };

    settings.sync();
    if (settings.status() != QSettings::NoError ||
        !settings.contains(legacyKey) ||
        settings.value(legacyKey).toString() != legacyText) {
        if (settings.status() == QSettings::NoError &&
            settings.contains(legacyKey) &&
            !settings.value(legacyKey).toString().isEmpty()) {
            rollbackInstalledCredential();
        }
        return false;
    }

    settings.remove(legacyKey);
    const auto sync = syncFn ? syncFn : [](QSettings& s) {
        s.sync();
        return s.status() == QSettings::NoError;
    };
    const bool removalSynced = sync(settings);
    QSettings persisted(settings.fileName(), settings.format());
    persisted.sync();
    const bool persistedReadable = persisted.status() == QSettings::NoError;
    const bool persistedPresent = persistedReadable && persisted.contains(legacyKey);
    QString persistedText = persistedPresent
        ? persisted.value(legacyKey).toString() : QString();
    const auto cleansePersistedText = qScopeGuard([&persistedText] {
        if (!persistedText.isEmpty())
            OPENSSL_cleanse(persistedText.data(),
                            static_cast<size_t>(persistedText.size() * sizeof(QChar)));
    });
    if (removalSynced && persistedReadable && !persistedPresent)
        return true;

    bool durableLegacyAvailable = persistedPresent;
    if (persistedPresent) {
        settings.setValue(legacyKey, persistedText);
        settings.sync();
    } else if (persistedReadable) {
        settings.setValue(legacyKey, legacyText);
        if (sync(settings)) {
            QSettings restored(settings.fileName(), settings.format());
            restored.sync();
            durableLegacyAvailable = restored.status() == QSettings::NoError &&
                restored.contains(legacyKey) &&
                restored.value(legacyKey).toString() == legacyText;
        }
    }
    if (durableLegacyAvailable)
        rollbackInstalledCredential();
    return false;
}
