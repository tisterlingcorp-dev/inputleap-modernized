#include "SecureCredentialStore.h"
#include "AppConfig.h"
#include <gtest/gtest.h>
#include <QHash>
#include <QMutex>
#include <QScopeGuard>
#include <QSettings>
#include <QTemporaryDir>
#include <QUuid>
#include <QWaitCondition>

#include <atomic>
#include <future>
#include <stdexcept>
#include <thread>

TEST(SecureCredentialStoreTests, NativeCredentialManagerRoundTripUsesEphemeralTarget)
{
#ifdef Q_OS_WIN
    SecureCredentialStore store;
    ASSERT_TRUE(store.available());
    const QString account = QStringLiteral("InputLeap/tests/SecureCredentialStore/%1")
        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces));
    const QByteArray secret = QUuid::createUuid().toRfc4122() +
                              QUuid::createUuid().toRfc4122();
    ASSERT_TRUE(store.remove(account));
    const auto cleanup = qScopeGuard([&store, &account] { store.remove(account); });

    ASSERT_TRUE(store.write(account, secret));
    const auto stored = store.read(account);
    ASSERT_EQ(stored.status, SecureCredentialStore::ReadResult::Status::Found);
    EXPECT_TRUE(stored->securelyEquals(QByteArrayView(secret)));
    ASSERT_TRUE(store.remove(account));
    EXPECT_EQ(store.read(account).status,
              SecureCredentialStore::ReadResult::Status::NotFound);
#else
    GTEST_SKIP() << "Windows Credential Manager is Windows-only";
#endif
}

TEST(SecureCredentialStoreTests, NativeCredentialManagerMigratesNativeFormatLegacyValue)
{
#ifdef Q_OS_WIN
    const QString uniqueId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString organization = QStringLiteral("InputLeapTests-%1").arg(uniqueId);
    const QString application = QStringLiteral("SecureCredentialNativeMigration");
    const QString legacyKey = QStringLiteral("fileTransferPairingCode");
    const QString account = QStringLiteral("InputLeap/tests/native-migration/%1").arg(uniqueId);
    const QByteArray secret = QByteArrayLiteral("[REDACTED]");

    QSettings settings(QSettings::NativeFormat, QSettings::UserScope,
                       organization, application);
    SecureCredentialStore store;
    ASSERT_TRUE(store.available());
    settings.clear();
    settings.sync();
    ASSERT_EQ(settings.status(), QSettings::NoError);
    ASSERT_TRUE(store.remove(account));
    const auto cleanup = qScopeGuard([&] {
        store.remove(account);
        settings.clear();
        settings.sync();
    });

    settings.setValue(legacyKey, QString::fromUtf8(secret));
    settings.sync();
    ASSERT_EQ(settings.status(), QSettings::NoError);

    ASSERT_TRUE(SecureCredentialStore::migrate(
        settings, legacyKey, store, account));

    QSettings reopened(QSettings::NativeFormat, QSettings::UserScope,
                       organization, application);
    reopened.sync();
    ASSERT_EQ(reopened.status(), QSettings::NoError);
    EXPECT_FALSE(reopened.contains(legacyKey));
    const auto stored = store.read(account);
    ASSERT_EQ(stored.status, SecureCredentialStore::ReadResult::Status::Found);
    EXPECT_TRUE(stored->securelyEquals(QByteArrayView(secret)));

    ASSERT_TRUE(store.remove(account));
    EXPECT_EQ(store.read(account).status,
              SecureCredentialStore::ReadResult::Status::NotFound);
#else
    GTEST_SKIP() << "Windows Credential Manager and NativeFormat are Windows-only";
#endif
}

TEST(SecureCredentialStoreTests, UnavailableProviderFailsClosed)
{
    SecureCredentialStore store(
        [](const QString&) -> std::optional<QByteArray> { return std::nullopt; },
        [](const QString&, const QByteArray&) { return false; },
        [](const QString&) { return false; });
    EXPECT_FALSE(store.write(QStringLiteral("account"), QByteArrayLiteral("secret")));
    EXPECT_FALSE(store.read(QStringLiteral("account")));
}

TEST(SecureCredentialStoreTests, ProviderExceptionsFailClosed)
{
    SecureCredentialStore throwingRead(
        SecureCredentialStore::Read([](const QString&) -> SecureCredentialStore::ReadResult {
            throw std::runtime_error("read failure");
        }),
        [](const QString&, const QByteArray&) { return true; },
        [](const QString&) { return true; });
    EXPECT_EQ(throwingRead.read(QStringLiteral("account")).status,
              SecureCredentialStore::ReadResult::Status::Error);
    const QByteArray secret = QByteArrayLiteral("secret");
    EXPECT_EQ(throwingRead.compareAndSwap(
                  QStringLiteral("account"), std::nullopt, QByteArrayView(secret)),
              SecureCredentialStore::CompareAndSwapResult::Error);

    SecureCredentialStore throwingWrite(
        [](const QString&) -> std::optional<QByteArray> { return std::nullopt; },
        [](const QString&, const QByteArray&) -> bool {
            throw std::runtime_error("write failure");
        },
        [](const QString&) { return true; });
    EXPECT_FALSE(throwingWrite.write(QStringLiteral("account"),
                                     QByteArrayLiteral("secret")));
    EXPECT_EQ(throwingWrite.compareAndSwap(
                  QStringLiteral("account"), std::nullopt, QByteArrayView(secret)),
              SecureCredentialStore::CompareAndSwapResult::Indeterminate);

    SecureCredentialStore throwingRemove(
        [](const QString&) -> std::optional<QByteArray> {
            return QByteArrayLiteral("secret");
        },
        [](const QString&, const QByteArray&) { return true; },
        [](const QString&) -> bool { throw std::runtime_error("remove failure"); });
    EXPECT_FALSE(throwingRemove.remove(QStringLiteral("account")));
    EXPECT_EQ(throwingRemove.compareAndSwap(
                  QStringLiteral("account"), QByteArrayView(secret), std::nullopt),
              SecureCredentialStore::CompareAndSwapResult::Indeterminate);
}

TEST(SecureCredentialStoreTests, MigrationRollsBackWhenSettingsSyncFails)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("credentials.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("legacy"), QStringLiteral("secret-value"));
    QHash<QString, QByteArray> values;
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            auto it = values.constFind(key); return it == values.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&](const QString& key, const QByteArray& value) { values[key] = value; return true; },
        [&](const QString& key) { values.remove(key); return true; });
    EXPECT_FALSE(SecureCredentialStore::migrate(settings, QStringLiteral("legacy"), store,
                                                QStringLiteral("account"), [](QSettings&) { return false; }));
    EXPECT_EQ(settings.value(QStringLiteral("legacy")).toString(), QStringLiteral("secret-value"));
    EXPECT_EQ(values.value(QStringLiteral("account")), QByteArrayLiteral("secret-value"));
    settings.clear();
}

TEST(SecureCredentialStoreTests, MigrationFailureNeverRemovesLastDurableSecretCopy)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("migration-last-copy.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("legacy"), QStringLiteral("secret-value"));
    settings.sync();
    QHash<QString, QByteArray> values;
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            return values.contains(key) ? std::optional<QByteArray>(values.value(key))
                                        : std::nullopt;
        },
        [&](const QString& key, const QByteArray& value) {
            values.insert(key, value); return true;
        },
        [&](const QString& key) { values.remove(key); return true; });
    int syncCalls = 0;
    const auto sync = [&](QSettings& target) {
        ++syncCalls;
        if (syncCalls == 1) {
            target.sync();
        } else {
            target.remove(QStringLiteral("legacy"));
            target.sync();
        }
        return false;
    };

    EXPECT_FALSE(SecureCredentialStore::migrate(
        settings, QStringLiteral("legacy"), store, QStringLiteral("account"), sync));
    QSettings persisted(path, QSettings::IniFormat);
    persisted.sync();
    EXPECT_FALSE(persisted.contains(QStringLiteral("legacy")));
    EXPECT_EQ(values.value(QStringLiteral("account")), QByteArrayLiteral("secret-value"));
}

TEST(SecureCredentialStoreTests, MigrationNeverWritesSecretToQSettingsAfterSuccess)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("credentials-success.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("legacy"), QStringLiteral("secret-value"));
    QHash<QString, QByteArray> values;
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> { return values.contains(key) ? std::optional<QByteArray>(values[key]) : std::nullopt; },
        [&](const QString& key, const QByteArray& value) { values[key] = value; return true; },
        [&](const QString& key) { values.remove(key); return true; });
    ASSERT_TRUE(SecureCredentialStore::migrate(settings, QStringLiteral("legacy"), store, QStringLiteral("account")));
    EXPECT_FALSE(settings.contains(QStringLiteral("legacy")));
    EXPECT_EQ(values.value(QStringLiteral("account")), QByteArrayLiteral("secret-value"));
    settings.clear();
}

TEST(SecureCredentialStoreTests, MigrationPreservesConcurrentLegacyUpdateBeforeRemoval)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("migration-race.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("legacy"), QStringLiteral("OLD"));
    settings.sync();
    QHash<QString, QByteArray> values;
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            return values.contains(key) ? std::optional<QByteArray>(values.value(key))
                                        : std::nullopt;
        },
        [&](const QString& key, const QByteArray& value) {
            values.insert(key, value);
            QSettings concurrent(path, QSettings::IniFormat);
            concurrent.setValue(QStringLiteral("legacy"), QStringLiteral("NEW"));
            concurrent.sync();
            return true;
        },
        [&](const QString& key) { values.remove(key); return true; });

    EXPECT_FALSE(SecureCredentialStore::migrate(
        settings, QStringLiteral("legacy"), store, QStringLiteral("account")));
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("legacy")).toString(), QStringLiteral("NEW"));
    EXPECT_FALSE(values.contains(QStringLiteral("account")));
}

TEST(SecureCredentialStoreTests, MigrationRollbackNeverOverwritesConcurrentLegacyUpdate)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("migration-rollback-race.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("legacy"), QStringLiteral("OLD"));
    settings.sync();
    QHash<QString, QByteArray> values;
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            return values.contains(key) ? std::optional<QByteArray>(values.value(key))
                                        : std::nullopt;
        },
        [&](const QString& key, const QByteArray& value) {
            values.insert(key, value); return true;
        },
        [&](const QString& key) { values.remove(key); return true; });
    int syncCalls = 0;
    const auto sync = [&](QSettings&) {
        ++syncCalls;
        if (syncCalls == 1) {
            QSettings concurrent(path, QSettings::IniFormat);
            concurrent.setValue(QStringLiteral("legacy"), QStringLiteral("NEW"));
            concurrent.sync();
            return false;
        }
        settings.sync();
        return settings.status() == QSettings::NoError;
    };

    EXPECT_FALSE(SecureCredentialStore::migrate(
        settings, QStringLiteral("legacy"), store, QStringLiteral("account"), sync));
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("legacy")).toString(), QStringLiteral("NEW"));
    EXPECT_FALSE(values.contains(QStringLiteral("account")));
}

TEST(SecureCredentialStoreTests, MigrationFailureLeavesAppConfigPairingUnavailable)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("appconfig-load-failure.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("fileTransferPairingCode"), QStringLiteral("secret-value"));
    SecureCredentialStore store(
        [](const QString&) -> std::optional<QByteArray> { return std::nullopt; },
        [](const QString&, const QByteArray&) { return false; },
        [](const QString&) { return true; });
    AppConfig config(&settings, std::move(store));
    EXPECT_TRUE(config.settingsLoadFailed());
    EXPECT_TRUE(config.fileTransferPairingCode().isEmpty());
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("fileTransferPairingCode")).toString(),
              QStringLiteral("secret-value"));
    settings.clear();
}

TEST(SecureCredentialStoreTests, AppConfigRejectsInvalidAuthorityWithoutMutatingCredentialStore)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("invalid.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("port"), QStringLiteral("24800"));
    settings.sync();
    int reads = 0;
    int writes = 0;
    int removes = 0;
    SecureCredentialStore store(
        [&](const QString&) -> std::optional<QByteArray> {
            ++reads;
            return std::nullopt;
        },
        [&](const QString&, const QByteArray&) {
            ++writes;
            return true;
        },
        [&](const QString&) {
            ++removes;
            return true;
        });

    AppConfig config(&settings, std::move(store));

    EXPECT_TRUE(config.settingsLoadFailed());
    // Startup recovery must probe protected marker/capsule artifacts before
    // strict public preflight; invalid public settings must not mutate them.
    EXPECT_EQ(reads, 2);
    EXPECT_EQ(writes, 0);
    EXPECT_EQ(removes, 0);
}

TEST(SecureCredentialStoreTests, UnavailableBackendPreservesLegacySecretWithoutActivatingIt)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("unavailable-provider.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("fileTransferPairingCode"),
                      QStringLiteral("legacy-secret"));
    settings.sync();
    SecureCredentialStore store(
        SecureCredentialStore::Read([](const QString&) {
            return SecureCredentialStore::ReadResult::error();
        }), {}, {});

    AppConfig config(&settings, std::move(store));

    EXPECT_TRUE(config.settingsLoadFailed());
    EXPECT_TRUE(config.fileTransferPairingCode().isEmpty());
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("fileTransferPairingCode")).toString(),
              QStringLiteral("legacy-secret"));
}

TEST(SecureCredentialStoreTests, RemoveFailsWhenReadBackStillFindsCredential)
{
    QHash<QString, QByteArray> values{{QStringLiteral("account"), QByteArrayLiteral("secret")}};
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            return values.contains(key) ? std::optional<QByteArray>(values.value(key)) : std::nullopt;
        },
        [](const QString&, const QByteArray&) { return true; },
        [](const QString&) { return true; });
    EXPECT_FALSE(store.remove(QStringLiteral("account")));
}

TEST(SecureCredentialStoreTests, ReadErrorIsNotTreatedAsAuthoritativeAbsence)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("credential-read-error.ini")),
                       QSettings::IniFormat);
    SecureCredentialStore store(
        SecureCredentialStore::Read([](const QString&) {
            return SecureCredentialStore::ReadResult::error();
        }),
        [](const QString&, const QByteArray&) { return true; },
        [](const QString&) { return true; });
    AppConfig config(&settings, std::move(store));
    EXPECT_TRUE(config.settingsLoadFailed());
    EXPECT_TRUE(config.fileTransferPairingCode().isEmpty());
    settings.clear();
}

TEST(SecureCredentialStoreTests, RemoveFailsWhenReadBackCannotVerifyAbsence)
{
    SecureCredentialStore store(
        SecureCredentialStore::Read([](const QString&) {
            return SecureCredentialStore::ReadResult::error();
        }),
        [](const QString&, const QByteArray&) { return true; },
        [](const QString&) { return true; });
    EXPECT_FALSE(store.remove(QStringLiteral("account")));
}

TEST(SecureCredentialStoreTests, CompareAndSwapRejectsStaleExpectedAndPreservesExternalValue)
{
    QHash<QString, QByteArray> values{
        {QStringLiteral("account"), QByteArrayLiteral("EXTERNAL-CODE")}};
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            return values.contains(key)
                ? std::optional<QByteArray>(values.value(key)) : std::nullopt;
        },
        [&](const QString& key, const QByteArray& value) {
            values.insert(key, value);
            return true;
        },
        [&](const QString& key) {
            values.remove(key);
            return true;
        });
    const QByteArray stale = QByteArrayLiteral("OLD-CODE");
    const QByteArray candidate = QByteArrayLiteral("IMPORTED-CODE");

    EXPECT_EQ(store.compareAndSwap(
                  QStringLiteral("account"), QByteArrayView(stale),
                  QByteArrayView(candidate)),
              SecureCredentialStore::CompareAndSwapResult::Mismatch);
    EXPECT_EQ(values.value(QStringLiteral("account")),
              QByteArrayLiteral("EXTERNAL-CODE"));
}

TEST(SecureCredentialStoreTests, CompareAndSwapAtomicallySetsAndClearsExpectedValue)
{
    QHash<QString, QByteArray> values;
    SecureCredentialStore store(
        [&](const QString& key) -> std::optional<QByteArray> {
            return values.contains(key)
                ? std::optional<QByteArray>(values.value(key)) : std::nullopt;
        },
        [&](const QString& key, const QByteArray& value) {
            values.insert(key, value);
            return true;
        },
        [&](const QString& key) {
            values.remove(key);
            return true;
        });
    const QByteArray candidate = QByteArrayLiteral("PAIRING-CODE");
    EXPECT_EQ(store.compareAndSwap(
                  QStringLiteral("account"), std::nullopt,
                  QByteArrayView(candidate)),
              SecureCredentialStore::CompareAndSwapResult::Success);
    ASSERT_EQ(values.value(QStringLiteral("account")), candidate);
    EXPECT_EQ(store.compareAndSwap(
                  QStringLiteral("account"), QByteArrayView(candidate),
                  std::nullopt),
              SecureCredentialStore::CompareAndSwapResult::Success);
    EXPECT_FALSE(values.contains(QStringLiteral("account")));
}

TEST(SecureCredentialStoreTests, ConcurrentStoreWritersSerializeReadAndMutation)
{
    QHash<QString, QByteArray> values{
        {QStringLiteral("account"), QByteArrayLiteral("OLD-CODE")}};
    QMutex backendMutex;
    QWaitCondition firstWriteEntered;
    QWaitCondition releaseFirstWrite;
    bool firstInsideWrite = false;
    bool releaseFirst = false;

    const auto read = [&](const QString& key) -> std::optional<QByteArray> {
        QMutexLocker locker(&backendMutex);
        return values.contains(key)
            ? std::optional<QByteArray>(values.value(key)) : std::nullopt;
    };
    SecureCredentialStore first(
        read,
        [&](const QString& key, const QByteArray& value) {
            QMutexLocker locker(&backendMutex);
            firstInsideWrite = true;
            firstWriteEntered.wakeAll();
            while (!releaseFirst)
                releaseFirstWrite.wait(&backendMutex);
            values.insert(key, value);
            return true;
        },
        [](const QString&) { return true; });
    SecureCredentialStore second(
        read,
        [&](const QString& key, const QByteArray& value) {
            QMutexLocker locker(&backendMutex);
            values.insert(key, value);
            return true;
        },
        [](const QString&) { return true; });

    const QByteArray expected = QByteArrayLiteral("OLD-CODE");
    const QByteArray firstCandidate = QByteArrayLiteral("FIRST-CODE");
    const QByteArray secondCandidate = QByteArrayLiteral("SECOND-CODE");
    auto firstResult = std::async(std::launch::async, [&] {
        return first.compareAndSwap(QStringLiteral("account"),
                                    QByteArrayView(expected),
                                    QByteArrayView(firstCandidate));
    });
    {
        QMutexLocker locker(&backendMutex);
        while (!firstInsideWrite)
            firstWriteEntered.wait(&backendMutex);
    }
    std::atomic_bool secondStarted = false;
    auto secondResult = std::async(std::launch::async, [&] {
        secondStarted.store(true, std::memory_order_release);
        return second.compareAndSwap(QStringLiteral("account"),
                                     QByteArrayView(expected),
                                     QByteArrayView(secondCandidate));
    });
    while (!secondStarted.load(std::memory_order_acquire))
        std::this_thread::yield();
    {
        QMutexLocker locker(&backendMutex);
        releaseFirst = true;
        releaseFirstWrite.wakeAll();
    }

    EXPECT_EQ(firstResult.get(),
              SecureCredentialStore::CompareAndSwapResult::Success);
    EXPECT_EQ(secondResult.get(),
              SecureCredentialStore::CompareAndSwapResult::Mismatch);
    QMutexLocker locker(&backendMutex);
    EXPECT_EQ(values.value(QStringLiteral("account")), firstCandidate);
}

TEST(SecureCredentialStoreTests, CompareAndSwapReportsErrorBeforeMutation)
{
    int writeCalls = 0;
    SecureCredentialStore store(
        SecureCredentialStore::Read([](const QString&) {
            return SecureCredentialStore::ReadResult::error();
        }),
        [&](const QString&, const QByteArray&) {
            ++writeCalls;
            return true;
        },
        [](const QString&) { return true; });

    const QByteArray expected = QByteArrayLiteral("OLD-CODE");
    const QByteArray candidate = QByteArrayLiteral("NEW-CODE");
    EXPECT_EQ(store.compareAndSwap(
                  QStringLiteral("account"), QByteArrayView(expected),
                  QByteArrayView(candidate)),
              SecureCredentialStore::CompareAndSwapResult::Error);
    EXPECT_EQ(writeCalls, 0);
}

TEST(SecureCredentialStoreTests, CompareAndSwapRollsBackReadbackFailureBeforeUnlock)
{
    QHash<QString, QByteArray> values{
        {QStringLiteral("account"), QByteArrayLiteral("OLD-CODE")}};
    int readCalls = 0;
    SecureCredentialStore store(
        SecureCredentialStore::Read([&](const QString& key) {
            ++readCalls;
            if (readCalls == 2)
                return SecureCredentialStore::ReadResult::error();
            return SecureCredentialStore::ReadResult::found(values.value(key));
        }),
        [&](const QString& key, const QByteArray& value) {
            values.insert(key, value);
            return true;
        },
        [&](const QString& key) {
            values.remove(key);
            return true;
        });

    const QByteArray expected = QByteArrayLiteral("OLD-CODE");
    const QByteArray candidate = QByteArrayLiteral("NEW-CODE");
    EXPECT_EQ(store.compareAndSwap(
                  QStringLiteral("account"), QByteArrayView(expected),
                  QByteArrayView(candidate)),
              SecureCredentialStore::CompareAndSwapResult::Error);
    EXPECT_EQ(values.value(QStringLiteral("account")), expected);
}
