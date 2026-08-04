#include "ConfigurationAppTarget.h"

#include "AppConfig.h"
#include "AppConfigSettingsJournal.h"
#include "ConfigurationPackageCodec.h"
#include "ConfigurationTransactionLock.h"
#include "EnvironmentProfileController.h"
#include "SecureCredentialStore.h"
#include "StartupSettingsPreflight.h"
#include "StartupLaunchPolicy.h"

#include <gtest/gtest.h>

#include <QDir>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QLockFile>
#include <QMap>
#include <QProcess>
#include <QSettings>
#include <QTemporaryDir>

#include <functional>
#include <future>
#include <utility>

namespace {
const QUuid AppTargetUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));

QByteArray forgeCapsuleSecretWithPublicDigest(QByteArray capsule,
                                             const QByteArray& forgedSecret)
{
    constexpr qsizetype MagicSize = 6;
    constexpr qsizetype UuidSize = 36;
    constexpr qsizetype DigestSize = 32;
    const qsizetype commonOffset = MagicSize + UuidSize;
    const qsizetype roleOffset = commonOffset + DigestSize;
    const qsizetype digestOffset = roleOffset + 1;
    const qsizetype lengthOffset = digestOffset + DigestSize;
    if (capsule.size() < lengthOffset + 5) return {};
    const auto* length = reinterpret_cast<const unsigned char*>(
        capsule.constData() + lengthOffset);
    const quint32 snapshotSize = (quint32(length[0]) << 24) |
        (quint32(length[1]) << 16) | (quint32(length[2]) << 8) |
        quint32(length[3]);
    const qsizetype snapshotOffset = lengthOffset + 4;
    const qsizetype stateOffset = snapshotOffset + snapshotSize;
    if (stateOffset >= capsule.size()) return {};
    capsule.resize(stateOffset + 1);
    capsule[stateOffset] = '\1';
    capsule.append(forgedSecret);

    QCryptographicHash hash(QCryptographicHash::Sha256);
    const auto append = [&hash](QByteArrayView value) {
        const QByteArray size = QByteArray::number(value.size());
        hash.addData(QByteArrayView(size));
        hash.addData(QByteArrayView(":", 1));
        hash.addData(value);
    };
    const QByteArray oldDomain = QByteArrayLiteral("inputleap-import-capsule-v3");
    append(QByteArrayView(oldDomain));
    append(QByteArrayView(capsule.constData() + commonOffset, DigestSize));
    append(QByteArrayView(capsule.constData() + roleOffset, 1));
    append(QByteArrayView(capsule.constData() + snapshotOffset, snapshotSize));
    append(QByteArrayView(capsule.constData() + stateOffset, 1));
    append(QByteArrayView(forgedSecret));
    capsule.replace(digestOffset, DigestSize, hash.result());
    return capsule;
}

class TestAppConfig : public AppConfig
{
public:
    using AppConfig::AppConfig;
    using AppConfig::setFileTransferPairingCode;
    using AppConfig::setLanguage;
};

EnvironmentProfile appTargetProfile(EnvironmentProfile::Kind kind)
{
    ScreenLayout::Device layoutDevice{
        AppTargetUuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100),
        {{QStringLiteral("display"), QRect(0, 0, 100, 100), 1.0,
          Qt::PrimaryOrientation, false}}};
    EnvironmentProfile profile;
    profile.kind = kind;
    profile.layout = {1, 1, {QStringLiteral("desktop")}, ScreenLayout({layoutDevice})};
    profile.devices = {{AppTargetUuid, QStringLiteral("desktop"),
                        DevicePermissions::ControlMouseKeyboard}};
    return profile;
}

struct ProfileHarness {
    QList<EnvironmentProfile> profiles;
    EnvironmentProfile::Kind active = EnvironmentProfile::Kind::Home;
    QString generation = QStringLiteral("generation-1");
    EnvironmentProfileStore::SaveResult replaceAllResult =
        EnvironmentProfileStore::SaveResult::Success;
    std::function<void()> beforeReplaceAllCommit;

    ProfileHarness()
    {
        for (const auto kind : EnvironmentProfile::canonicalKinds())
            profiles.push_back(appTargetProfile(kind));
    }

    std::optional<EnvironmentProfile> profile(EnvironmentProfile::Kind kind) const
    {
        for (const auto& candidate : profiles) {
            if (candidate.kind == kind)
                return candidate;
        }
        return std::nullopt;
    }

    EnvironmentProfileController::Services services()
    {
        return {
            [] { return EnvironmentProfileStore::LoadStatus::Loaded; },
            [this](EnvironmentProfile::Kind kind) { return profile(kind); },
            [this] { return std::optional<EnvironmentProfile::Kind>{active}; },
            [this] { return std::optional<QString>{generation}; },
            [](const EnvironmentProfile&) { return EnvironmentProfileStore::SaveResult::AlreadyInitialized; },
            [](const EnvironmentProfile&, const QString&, const std::optional<QString>&) {
                return EnvironmentProfileStore::Mutation{};
            },
            [](EnvironmentProfile::Kind, const QString&, const std::optional<QString>&) {
                return EnvironmentProfileStore::Mutation{};
            },
            [this](const QString& expected) {
                return expected == generation ? EnvironmentProfileStore::SaveResult::Success
                                              : EnvironmentProfileStore::SaveResult::ConcurrentModification;
            },
            [this](const QString& expected,
                   const EnvironmentProfileStore::VerifiedConsumer& consumer) {
                if (expected != generation)
                    return EnvironmentProfileStore::SaveResult::ConcurrentModification;
                const auto activeProfile = profile(active);
                if (!activeProfile)
                    return EnvironmentProfileStore::SaveResult::InvalidProfile;
                return consumer({active, generation, *activeProfile})
                    ? EnvironmentProfileStore::SaveResult::Success
                    : EnvironmentProfileStore::SaveResult::InvalidProfile;
            },
            [this] { return profile(active)->layout; },
            [](const EnvironmentProfile::Layout&) { return true; },
            [](const QUuid&) { return DevicePermissions::ControlMouseKeyboard; },
            [](const QUuid&, DevicePermissions::Permission) { return true; },
            [] { return false; },
            [] { return false; },
            [this] { return profiles; },
            [this](const QList<EnvironmentProfile>& replacements,
                   EnvironmentProfile::Kind replacementActive,
                   const QString& expected, const std::optional<QString>&) {
                EnvironmentProfileStore::Mutation mutation;
                mutation.previousGeneration = expected;
                mutation.resultingGeneration = generation;
                if (expected != generation) {
                    mutation.result = EnvironmentProfileStore::SaveResult::ConcurrentModification;
                    return mutation;
                }
                if (replaceAllResult != EnvironmentProfileStore::SaveResult::Success) {
                    mutation.result = replaceAllResult;
                    return mutation;
                }
                if (beforeReplaceAllCommit) {
                    auto callback = std::move(beforeReplaceAllCommit);
                    callback();
                }
                profiles = replacements;
                active = replacementActive;
                generation = generation == QStringLiteral("generation-1")
                    ? QStringLiteral("generation-2") : QStringLiteral("generation-3");
                mutation.result = EnvironmentProfileStore::SaveResult::Success;
                mutation.resultingGeneration = generation;
                return mutation;
            }};
    }
};

TEST(StartupLaunchPolicyTests, ExplicitNoAutoStartSuppressesOnlyAutomaticLaunch)
{
    EXPECT_TRUE(StartupLaunchPolicy::suppressAutoStart(
        {QStringLiteral("input-leap.exe"), QStringLiteral("--no-auto-start")}));
    EXPECT_FALSE(StartupLaunchPolicy::suppressAutoStart(
        {QStringLiteral("input-leap.exe")}));
}

TEST(ConfigurationAppTargetTests, AppliesAndVerifiesRealAppConfigCredentialAndProfileController)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("app.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), false);
    settings.sync();

    QMap<QString, QByteArray> credentials;
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore credentialStore(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value);
            return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key);
            return true;
        });
    AppConfig appConfig(&settings, std::move(credentialStore));
    ProfileHarness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(appConfig, controller);
    const auto current = appTarget.snapshot();
    ASSERT_TRUE(current);

    ConfigurationImportPreview::Preview preview;
    preview.candidate.snapshot = *current;
    preview.candidate.snapshot.preferences = *ConfigurationPortablePreferences::create(
        24801, 5, QStringLiteral("en"), true, false, true, false, true);
    preview.candidate.snapshot.environmentProfiles.activeKind = EnvironmentProfile::Kind::Travel;
    preview.candidate.snapshot.environmentProfiles.profiles[1].devices[0].requestedResources =
        DevicePermissions::SendFiles;
    preview.candidate.sensitive.emplace();
    preview.candidate.sensitive->pairingCode.emplace(QByteArrayLiteral("NEW-CODE"));
    preview.summary.includesPairingCode = true;
    const QString backupPath = directory.filePath(QStringLiteral("automatic-backup.ilconfig"));
    SensitiveBytes backupPassword(QByteArrayLiteral("backup-password"));

    const auto result = ConfigurationImportService::apply(
        preview, *current, backupPath,
        ConfigurationImportService::Options{&backupPassword, false, true},
        appTarget.target());

    ASSERT_EQ(result, ConfigurationImportService::Error::None);
    const auto applied = appTarget.snapshot();
    ASSERT_TRUE(applied);
    EXPECT_EQ(applied->preferences.port(), 24801);
    EXPECT_EQ(applied->preferences.logLevel(), 5);
    EXPECT_EQ(applied->preferences.language(), QStringLiteral("en"));
    EXPECT_EQ(applied->environmentProfiles.activeKind, EnvironmentProfile::Kind::Travel);
    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
    EXPECT_FALSE(settings.contains(QStringLiteral("fileTransferPairingCode")));
    QFile backup(backupPath);
    ASSERT_TRUE(backup.open(QIODevice::ReadOnly));
    EXPECT_EQ(ConfigurationPackageCodec::decode(backup.readAll()).error,
              ConfigurationPackageCodec::Error::None);
}

TEST(ConfigurationAppTargetTests, ControllerFailureRestoresAlreadyPersistedPortablePreferences)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("app.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), false);
    settings.sync();
    QMap<QString, QByteArray> credentials;
    int credentialReads = 0;
    int credentialWrites = 0;
    int credentialRemoves = 0;
    SecureCredentialStore credentialStore(
        [&credentials, &credentialReads](const QString& key) -> std::optional<QByteArray> {
            ++credentialReads;
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials, &credentialWrites](const QString& key, const QByteArray& value) {
            ++credentialWrites;
            credentials.insert(key, value); return true;
        },
        [&credentials, &credentialRemoves](const QString& key) {
            ++credentialRemoves;
            credentials.remove(key); return true;
        });
    AppConfig appConfig(&settings, std::move(credentialStore));
    credentialReads = credentialWrites = credentialRemoves = 0;
    ProfileHarness harness;
    harness.replaceAllResult = EnvironmentProfileStore::SaveResult::ConcurrentModification;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(appConfig, controller);
    const auto current = appTarget.snapshot();
    ASSERT_TRUE(current);
    ConfigurationImportPreview::Preview preview;
    preview.candidate.snapshot = *current;
    preview.candidate.snapshot.preferences = *ConfigurationPortablePreferences::create(
        24801, 5, QStringLiteral("en"), true, false, true, false, true);
    preview.candidate.snapshot.environmentProfiles.activeKind = EnvironmentProfile::Kind::Travel;

    SensitiveBytes backupPassword(QByteArrayLiteral("backup-password"));
    const auto result = ConfigurationImportService::apply(
        preview, *current, directory.filePath(QStringLiteral("backup.ilconfig")),
        ConfigurationImportService::Options{&backupPassword, false, true}, appTarget.target());

    EXPECT_EQ(result, ConfigurationImportService::Error::ConcurrentModification);
    EXPECT_EQ(appConfig.port(), 24800);
    EXPECT_EQ(appConfig.logLevel(), 3);
    EXPECT_EQ(appConfig.language(), QStringLiteral("pt-BR"));
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("port")).toInt(), 24800);
    EXPECT_EQ(settings.value(QStringLiteral("logLevel")).toInt(), 3);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(), QStringLiteral("pt-BR"));
    EXPECT_EQ(harness.active, EnvironmentProfile::Kind::Home);
    EXPECT_EQ(harness.generation, QStringLiteral("generation-1"));
    EXPECT_GE(credentialReads, 2);
    EXPECT_EQ(credentials.value(QStringLiteral("InputLeap/file-transfer-pairing-code")),
              QByteArray());
    EXPECT_FALSE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    EXPECT_EQ(credentialWrites, 5);
    EXPECT_EQ(credentialRemoves, 4);
}

TEST(ConfigurationAppTargetTests, CredentialReadbackErrorCompensatesAndDestructorDoesNotRetry)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("app.ini"));
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();

    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials;
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    bool failNextRead = false;
    bool injectReadbackFailure = true;
    SecureCredentialStore credentialStore(
        [&credentials, &failNextRead](const QString& key) {
            if (failNextRead) {
                failNextRead = false;
                return SecureCredentialStore::ReadResult::error();
            }
            const auto found = credentials.constFind(key);
            return found == credentials.cend()
                ? SecureCredentialStore::ReadResult::notFound()
                : SecureCredentialStore::ReadResult::found(*found);
        },
        [&credentials, &failNextRead, &injectReadbackFailure](
            const QString& key, const QByteArray& value) {
            credentials.insert(key, value);
            if (injectReadbackFailure && value == QByteArrayLiteral("NEW-CODE")) {
                injectReadbackFailure = false;
                failNextRead = true;
            }
            return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key);
            return true;
        });

    {
        TestAppConfig appConfig(&settings, std::move(credentialStore));
        appConfig.setLanguage(QStringLiteral("en"));
        appConfig.setFileTransferPairingCode(QStringLiteral("NEW-CODE"));

        EXPECT_FALSE(appConfig.saveSettings());
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("OLD-CODE"));
        QSettings observer(settingsPath, QSettings::IniFormat);
        observer.sync();
        EXPECT_EQ(observer.value(QStringLiteral("language")).toString(),
                  QStringLiteral("pt-BR"));
    }

    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("OLD-CODE"));
}

TEST(ConfigurationAppTargetTests, PreMutationCredentialErrorDoesNotCompensateMatchingExternalValue)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("app.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();

    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials;
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore credentialStore(
        [&credentials](const QString& key) {
            const auto found = credentials.constFind(key);
            return found == credentials.cend()
                ? SecureCredentialStore::ReadResult::notFound()
                : SecureCredentialStore::ReadResult::found(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            if (value == QByteArrayLiteral("NEW-CODE")) {
                credentials.insert(key, value);
                return false;
            }
            credentials.insert(key, value);
            return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key);
            return true;
        });

    {
        TestAppConfig appConfig(&settings, std::move(credentialStore));
        appConfig.setLanguage(QStringLiteral("en"));
        appConfig.setFileTransferPairingCode(QStringLiteral("NEW-CODE"));
        EXPECT_TRUE(appConfig.saveSettings());
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
    }

    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
    QSettings observer(settings.fileName(), QSettings::IniFormat);
    observer.sync();
    EXPECT_EQ(observer.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_FALSE(observer.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(
        AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(ConfigurationAppTargetTests, AppConfigStartupRollsBackPublicOnlyInterruptedSave)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("startup-rollback.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    {
        AppConfigSettingsJournal journal(settings, store);
        ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    }
    settings.setValue(QStringLiteral("language"), QStringLiteral("en"));
    settings.sync();

    TestAppConfig recovered(&settings, std::move(store));
    EXPECT_FALSE(recovered.settingsLoadFailed());
    EXPECT_EQ(recovered.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(recovered.fileTransferPairingCode(), QStringLiteral("OLD-CODE"));
}

TEST(ConfigurationAppTargetTests, AppConfigStartupCompletesSecretAppliedInterruptedSave)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("startup-forward.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    {
        AppConfigSettingsJournal journal(settings, store);
        ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    }
    settings.setValue(QStringLiteral("language"), QStringLiteral("en"));
    settings.sync();
    AppConfigSettingsJournal applied(settings, store);
    ASSERT_TRUE(applied.markPublicApplied());
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("NEW-CODE"));

    TestAppConfig recovered(&settings, std::move(store));
    EXPECT_FALSE(recovered.settingsLoadFailed());
    EXPECT_EQ(recovered.language(), QStringLiteral("en"));
    EXPECT_EQ(recovered.fileTransferPairingCode(), QStringLiteral("NEW-CODE"));
}

TEST(ConfigurationAppTargetTests, StaleExplicitSaveIsRejectedWithoutLostUpdate)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings firstSettings(directory.filePath(QStringLiteral("stale-save.ini")),
                            QSettings::IniFormat);
    QSettings secondSettings(firstSettings.fileName(), QSettings::IniFormat);
    firstSettings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    firstSettings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&credentials](const QString& key) {
                credentials.remove(key); return true;
            });
    };
    TestAppConfig first(&firstSettings, makeStore());
    TestAppConfig stale(&secondSettings, makeStore());
    first.setLanguage(QStringLiteral("en"));
    first.setFileTransferPairingCode(QStringLiteral("FIRST-CODE"));
    ASSERT_TRUE(first.saveSettings());
    stale.setLanguage(QStringLiteral("fr"));
    stale.setFileTransferPairingCode(QStringLiteral("STALE-CODE"));

    EXPECT_EQ(stale.saveSettingsWithResult(),
              AppConfig::SaveSettingsResult::ConcurrentModification);
    QSettings observer(firstSettings.fileName(), QSettings::IniFormat);
    observer.sync();
    EXPECT_EQ(observer.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("FIRST-CODE"));
}

TEST(ConfigurationAppTargetTests, DestructorNeverReplaysPreviouslySavedCache)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("destructor-replay.ini"));
    QSettings firstSettings(path, QSettings::IniFormat);
    firstSettings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    firstSettings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&credentials](const QString& key) {
                credentials.remove(key); return true;
            });
    };
    {
        TestAppConfig first(&firstSettings, makeStore());
        first.setLanguage(QStringLiteral("en"));
        first.setFileTransferPairingCode(QStringLiteral("FIRST-CODE"));
        ASSERT_TRUE(first.saveSettings());
        QSettings secondSettings(path, QSettings::IniFormat);
        TestAppConfig second(&secondSettings, makeStore());
        second.setLanguage(QStringLiteral("fr"));
        second.setFileTransferPairingCode(QStringLiteral("SECOND-CODE"));
        ASSERT_TRUE(second.saveSettings());
    }
    QSettings observer(path, QSettings::IniFormat);
    observer.sync();
    EXPECT_EQ(observer.value(QStringLiteral("language")).toString(),
              QStringLiteral("fr"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("SECOND-CODE"));
}

TEST(ConfigurationAppTargetTests,
     TransactionLockCanBeReleasedSafelyByAnotherThread)
{
    auto lock = std::make_unique<ConfigurationTransactionLock>();
    ASSERT_TRUE(lock->isLocked());
    EXPECT_TRUE(std::async(std::launch::async,
                           [owned = std::move(lock)]() mutable {
                               owned.reset();
                               return true;
                           }).get());
    ConfigurationTransactionLock nextWriter(0);
    EXPECT_TRUE(nextWriter.isLocked());
}

TEST(ConfigurationAppTargetTests,
     TransactionLockRecoversAfterHoldingProcessIsTerminated)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString lockPath = directory.filePath(
        QStringLiteral("configuration-transaction.lock"));
    QProcess holder;
    holder.start(QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH),
                 {QStringLiteral("--hold-configuration-lock"), lockPath});
    ASSERT_TRUE(holder.waitForStarted());
    ASSERT_TRUE(holder.waitForReadyRead(5000));
    ASSERT_EQ(holder.readLine().trimmed(), QByteArrayLiteral("READY"));

    ConfigurationTransactionLock blockedWriter(0, lockPath);
    EXPECT_FALSE(blockedWriter.isLocked());

    holder.kill();
    ASSERT_TRUE(holder.waitForFinished(5000));
    ConfigurationTransactionLock recoveredWriter(5000, lockPath);
    EXPECT_TRUE(recoveredWriter.isLocked());
}

TEST(ConfigurationAppTargetTests, EarlyRecoveryRepairsPartialPublicStateBeforePreflight)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("early-recovery.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), true);
    settings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("cryptoEnabled"), false);
    candidate.insert(QStringLiteral("requireClientCertificate"), false);
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    settings.setValue(QStringLiteral("cryptoEnabled"), false);
    settings.sync();
    ASSERT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);

    EXPECT_TRUE(AppConfig::recoverInterruptedSave(settings, std::move(store)));
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_TRUE(settings.value(QStringLiteral("cryptoEnabled")).toBool());
    EXPECT_TRUE(settings.value(QStringLiteral("requireClientCertificate")).toBool());
}

TEST(ConfigurationAppTargetTests, AppConfigLoadRecoversInterruptedSaveBeforeStrictPreflight)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("load-recovery.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), true);
    settings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&credentials](const QString& key) {
                credentials.remove(key); return true;
            });
    };
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("cryptoEnabled"), false);
    candidate.insert(QStringLiteral("requireClientCertificate"), false);
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    auto journalStore = makeStore();
    AppConfigSettingsJournal journal(settings, journalStore);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    settings.setValue(QStringLiteral("cryptoEnabled"), false);
    settings.sync();
    ASSERT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);

    AppConfig config(&settings, makeStore());

    EXPECT_FALSE(config.settingsLoadFailed());
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_TRUE(settings.value(QStringLiteral("cryptoEnabled")).toBool());
    EXPECT_TRUE(settings.value(QStringLiteral("requireClientCertificate")).toBool());
}

TEST(ConfigurationAppTargetTests, StartupRecoveryOrchestratorRepairsBeforeStrictPreflight)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("startup-recovery.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), true);
    settings.sync();
    QMap<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&credentials](const QString& key) {
                credentials.remove(key); return true;
            });
    };
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("cryptoEnabled"), false);
    candidate.insert(QStringLiteral("requireClientCertificate"), false);
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    auto journalStore = makeStore();
    AppConfigSettingsJournal journal(settings, journalStore);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    settings.setValue(QStringLiteral("cryptoEnabled"), false);
    settings.sync();
    ASSERT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);

    EXPECT_TRUE(ConfigurationAppTarget::recoverStartupStateBeforePreflight(
        settings, makeStore()));

    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_TRUE(settings.value(QStringLiteral("cryptoEnabled")).toBool());
    EXPECT_TRUE(settings.value(QStringLiteral("requireClientCertificate")).toBool());
}

TEST(ConfigurationAppTargetTests, PairingCodeGetterReturnsStableReferenceWithoutCopy)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("detached-secret.ini")),
                       QSettings::IniFormat);
    QMap<QString, QByteArray> credentials;
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    TestAppConfig config(&settings, std::move(store));
    config.setFileTransferPairingCode(QStringLiteral("DETACHED-CODE"));

    const QString& first = config.fileTransferPairingCode();
    const QString& second = config.fileTransferPairingCode();
    EXPECT_EQ(first, QStringLiteral("DETACHED-CODE"));
    EXPECT_EQ(second, first);
    EXPECT_EQ(first.constData(), second.constData());
}

TEST(ConfigurationAppTargetTests, ConcurrentPortableWriterRefreshesCacheInsteadOfRestoringStaleValues)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("app.ini"));
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), false);
    settings.sync();

    QMap<QString, QByteArray> credentials;
    SecureCredentialStore credentialStore(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value);
            return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key);
            return true;
        });
    QSettings external(settingsPath, QSettings::IniFormat);
    {
        AppConfig appConfig(&settings, std::move(credentialStore));
        ProfileHarness harness;
        const auto originalProfiles = harness.profiles;
        const auto originalActive = harness.active;
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget appTarget(appConfig, controller);
        const auto current = appTarget.snapshot();
        ASSERT_TRUE(current);

        harness.beforeReplaceAllCommit = [&external] {
            external.setValue(QStringLiteral("language"), QStringLiteral("fr"));
            external.setValue(QStringLiteral("port"), 24999);
            external.setValue(QStringLiteral("logLevel"), 4);
            external.sync();
        };

        ConfigurationImportPreview::Preview preview;
        preview.candidate.snapshot = *current;
        preview.candidate.snapshot.preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        SensitiveBytes backupPassword(QByteArrayLiteral("backup-password"));
        const auto result = ConfigurationImportService::apply(
            preview, *current, directory.filePath(QStringLiteral("backup.ilconfig")),
            ConfigurationImportService::Options{&backupPassword, false, true}, appTarget.target());

        EXPECT_EQ(result, ConfigurationImportService::Error::ConcurrentModification);
        EXPECT_EQ(appConfig.language(), QStringLiteral("fr"));
        EXPECT_EQ(appConfig.port(), 24999);
        EXPECT_EQ(appConfig.logLevel(), 4);
        ASSERT_EQ(harness.profiles.size(), originalProfiles.size());
        for (qsizetype i = 0; i < harness.profiles.size(); ++i) {
            EXPECT_EQ(harness.profiles[i].kind, originalProfiles[i].kind);
            EXPECT_EQ(harness.profiles[i].layout.rows, originalProfiles[i].layout.rows);
            EXPECT_EQ(harness.profiles[i].layout.columns,
                      originalProfiles[i].layout.columns);
            EXPECT_EQ(harness.profiles[i].layout.gridTechnicalNames,
                      originalProfiles[i].layout.gridTechnicalNames);
            EXPECT_EQ(harness.profiles[i].devices.first().requestedResources,
                      originalProfiles[i].devices.first().requestedResources);
        }
        EXPECT_EQ(harness.active, originalActive);
        EXPECT_EQ(harness.generation, QStringLiteral("generation-3"));
    }
    external.sync();
    EXPECT_EQ(external.value(QStringLiteral("language")).toString(), QStringLiteral("fr"));
    EXPECT_EQ(external.value(QStringLiteral("port")).toInt(), 24999);
    EXPECT_EQ(external.value(QStringLiteral("logLevel")).toInt(), 4);
}

TEST(ConfigurationAppTargetTests, PendingJournalRecoversOriginalAcrossRecreatedTargets)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("crash-recovery.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), false);
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials;
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&credentials](const QString& key) {
                credentials.remove(key); return true;
            });
    };
    ProfileHarness harness;
    std::optional<ConfigurationPublicSnapshot> original;
    std::optional<ConfigurationPublicSnapshot> interruptedCandidate;

    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget appTarget(appConfig, controller);
        original = appTarget.snapshot();
        ASSERT_TRUE(original);
        auto candidate = *original;
        candidate.preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        candidate.environmentProfiles.activeKind = EnvironmentProfile::Kind::Travel;
        candidate.environmentProfiles.profiles[1].devices[0].requestedResources =
            DevicePermissions::SendFiles;
        interruptedCandidate = candidate;
        std::optional<SensitiveBytes> oldSecret;
        oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
        std::optional<SensitiveBytes> newSecret;
        newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
        auto callbacks = appTarget.target();
        ASSERT_EQ(callbacks.beginPending(*original, candidate, oldSecret, newSecret),
                  ConfigurationImportService::MutationResult::Success);
        const bool competingWriterEntered = std::async(std::launch::async, [] {
            ConfigurationTransactionLock competing(0);
            return competing.isLocked();
        }).get();
        EXPECT_FALSE(competingWriterEntered);
        EXPECT_EQ(std::async(std::launch::async, [&callbacks] {
            return callbacks.commitPending();
        }).get(), ConfigurationImportService::MutationResult::Indeterminate);
        const bool writerEnteredAfterRejectedHandoff =
            std::async(std::launch::async, [] {
                ConfigurationTransactionLock competing(0);
                return competing.isLocked();
            }).get();
        EXPECT_FALSE(writerEnteredAfterRejectedHandoff);
        ASSERT_EQ(callbacks.compareAndApplySnapshot(candidate, *original),
                  ConfigurationImportService::MutationResult::Success);
        ASSERT_EQ(callbacks.writePairingCode(newSecret, oldSecret),
                  ConfigurationImportService::MutationResult::Success);
        EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
        // Deliberately omit commitPending(): this is the process-death point.
    }

    settings.sync();
    QFile journalFile(settings.fileName());
    ASSERT_TRUE(journalFile.open(QIODevice::ReadOnly));
    const QByteArray onDisk = journalFile.readAll();
    EXPECT_FALSE(onDisk.contains("OLD-CODE"));
    EXPECT_FALSE(onDisk.contains("NEW-CODE"));
    journalFile.close();

    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget appTarget(appConfig, controller);
        const auto interrupted = appTarget.snapshot();
        ASSERT_TRUE(interrupted);
        ASSERT_TRUE(interruptedCandidate);
        EXPECT_EQ(ConfigurationPublicSnapshotCodec::encode(*interrupted),
                  ConfigurationPublicSnapshotCodec::encode(*interruptedCandidate));
        EXPECT_EQ(interrupted->preferences.language(), QStringLiteral("en"));
        EXPECT_EQ(interrupted->environmentProfiles.activeKind,
                  EnvironmentProfile::Kind::Travel);
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
        EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
        EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
        EXPECT_EQ(settings.value(QStringLiteral("configurationImportJournal/state")).toString(),
                  QStringLiteral("pending"));
        const auto sensitiveBeforeRecovery = appTarget.target().readPairingCode();
        ASSERT_TRUE(sensitiveBeforeRecovery.readable);
        ASSERT_TRUE(sensitiveBeforeRecovery.value);
        EXPECT_TRUE(sensitiveBeforeRecovery.value->securelyEquals(
            QByteArrayLiteral("NEW-CODE")));
        const QString oldCapsuleAccount =
            QStringLiteral("InputLeap/import-recovery/old");
        const QString newCapsuleAccount =
            QStringLiteral("InputLeap/import-recovery/new");
        const QByteArray authenticOldCapsule = credentials.value(oldCapsuleAccount);
        const QByteArray authenticNewCapsule = credentials.value(newCapsuleAccount);
        const QString authenticationKeyAccount =
            QStringLiteral("InputLeap/import-recovery/auth-key");
        const QByteArray authenticAuthenticationKey =
            credentials.value(authenticationKeyAccount);
        ASSERT_EQ(authenticAuthenticationKey.size(), 32);
        credentials.insert(authenticationKeyAccount, QByteArray(32, 'F'));
        EXPECT_EQ(appTarget.recoverPendingImport(),
                  ConfigurationAppTarget::PendingRecoveryResult::Blocked);
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
        EXPECT_TRUE(settings.contains(
            QStringLiteral("configurationImportJournal/state")));
        credentials.insert(authenticationKeyAccount,
                           authenticAuthenticationKey);
        const QByteArray forgedOldCapsule = forgeCapsuleSecretWithPublicDigest(
            authenticOldCapsule, QByteArrayLiteral("ATTACKER-CODE"));
        ASSERT_FALSE(forgedOldCapsule.isEmpty());
        credentials.insert(oldCapsuleAccount, forgedOldCapsule);
        EXPECT_EQ(appTarget.recoverPendingImport(),
                  ConfigurationAppTarget::PendingRecoveryResult::Blocked);
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
        EXPECT_TRUE(settings.contains(
            QStringLiteral("configurationImportJournal/state")));
        credentials.insert(oldCapsuleAccount, authenticOldCapsule);
        credentials.insert(oldCapsuleAccount, authenticNewCapsule);
        credentials.insert(newCapsuleAccount, authenticOldCapsule);
        EXPECT_EQ(appTarget.recoverPendingImport(),
                  ConfigurationAppTarget::PendingRecoveryResult::Blocked);
        EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
        const auto afterCapsuleSwap = appTarget.snapshot();
        ASSERT_TRUE(afterCapsuleSwap);
        EXPECT_EQ(ConfigurationPublicSnapshotCodec::encode(*afterCapsuleSwap),
                  ConfigurationPublicSnapshotCodec::encode(*interruptedCandidate));
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
        credentials.insert(oldCapsuleAccount, authenticOldCapsule);
        credentials.insert(newCapsuleAccount, authenticNewCapsule);
        const QString originalJournalKey =
            QStringLiteral("configurationImportJournal/originalPublic");
        const QByteArray authenticOriginal = settings.value(originalJournalKey).toByteArray();
        auto forgedOriginal = *original;
        forgedOriginal.preferences = *ConfigurationPortablePreferences::create(
            25000, 2, QStringLiteral("fr"), false, false, false, false, false);
        settings.setValue(
            originalJournalKey,
            QJsonDocument(ConfigurationPublicSnapshotCodec::encode(forgedOriginal))
                .toJson(QJsonDocument::Compact));
        settings.sync();
        EXPECT_EQ(appTarget.recoverPendingImport(),
                  ConfigurationAppTarget::PendingRecoveryResult::Blocked);
        EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
        const auto afterTamper = appTarget.snapshot();
        ASSERT_TRUE(afterTamper);
        EXPECT_EQ(ConfigurationPublicSnapshotCodec::encode(*afterTamper),
                  ConfigurationPublicSnapshotCodec::encode(*interruptedCandidate));
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
        settings.setValue(originalJournalKey, authenticOriginal);
        settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
        settings.sync();
        const auto recoveryResult = appTarget.recoverPendingImport();
        EXPECT_EQ(recoveryResult,
                  ConfigurationAppTarget::PendingRecoveryResult::Recovered);
        EXPECT_EQ(harness.active, EnvironmentProfile::Kind::Home);
        EXPECT_EQ(harness.generation, QStringLiteral("generation-3"));
        EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
                  QStringLiteral("pt-BR"));
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("OLD-CODE"));
        const auto restored = appTarget.snapshot();
        ASSERT_TRUE(restored);
        EXPECT_EQ(ConfigurationPublicSnapshotCodec::encode(*restored),
                  ConfigurationPublicSnapshotCodec::encode(*original));
        EXPECT_EQ(credentials.value(account), QByteArrayLiteral("OLD-CODE"));
        EXPECT_FALSE(settings.contains(QStringLiteral("configurationImportJournal/state")));
        EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
        EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
        EXPECT_EQ(appTarget.recoverPendingImport(),
                  ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    }
}

TEST(ConfigurationAppTargetTests, StrippedImportJournalRecoversFromSelfContainedCapsules)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("stripped-import-journal.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), false);
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials{{account, QByteArrayLiteral("OLD-CODE")}};
    bool failNewCapsuleCleanup = false;
    const auto makeStore = [&] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&](const QString& key) {
                if (failNewCapsuleCleanup && key ==
                        QStringLiteral("InputLeap/import-recovery/new"))
                    return false;
                credentials.remove(key); return true;
            });
    };
    ProfileHarness harness;
    std::optional<ConfigurationPublicSnapshot> original;
    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget target(appConfig, controller);
        original = target.snapshot();
        ASSERT_TRUE(original);
        auto candidate = *original;
        candidate.preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        candidate.environmentProfiles.activeKind = EnvironmentProfile::Kind::Travel;
        std::optional<SensitiveBytes> oldSecret;
        oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
        std::optional<SensitiveBytes> newSecret;
        newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
        auto callbacks = target.target();
        ASSERT_EQ(callbacks.beginPending(*original, candidate, oldSecret, newSecret),
                  ConfigurationImportService::MutationResult::Success);
        constexpr qsizetype WindowsGenericCredentialLimit = 5 * 512;
        EXPECT_LE(credentials.value(
                      QStringLiteral("InputLeap/import-recovery/old")).size(),
                  WindowsGenericCredentialLimit);
        EXPECT_LE(credentials.value(
                      QStringLiteral("InputLeap/import-recovery/new")).size(),
                  WindowsGenericCredentialLimit);
        ASSERT_EQ(callbacks.compareAndApplySnapshot(candidate, *original),
                  ConfigurationImportService::MutationResult::Success);
        ASSERT_EQ(callbacks.writePairingCode(newSecret, oldSecret),
                  ConfigurationImportService::MutationResult::Success);
        settings.remove(QStringLiteral("configurationImportJournal"));
        settings.sync();
    }

    AppConfig appConfig(&settings, makeStore());
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget target(appConfig, controller);
    failNewCapsuleCleanup = true;
    EXPECT_EQ(target.recoverPendingImport(),
              ConfigurationAppTarget::PendingRecoveryResult::Blocked);
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
    EXPECT_TRUE(credentials.value(QStringLiteral("InputLeap/import-recovery/prepare"))
                    .startsWith(QByteArrayLiteral("ILIMP1")));
    failNewCapsuleCleanup = false;
    EXPECT_EQ(target.recoverPendingImport(),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    const auto restored = target.snapshot();
    ASSERT_TRUE(restored);
    ASSERT_TRUE(original);
    EXPECT_EQ(ConfigurationPublicSnapshotCodec::encode(*restored),
              ConfigurationPublicSnapshotCodec::encode(*original));
    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("OLD-CODE"));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
}

TEST(ConfigurationAppTargetTests, CommittedImportSurvivesCrashDuringCapsuleCleanup)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("committed-import-cleanup.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), false);
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials{{account, QByteArrayLiteral("OLD-CODE")}};
    bool failCapsuleCleanup = false;
    const auto makeStore = [&] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&](const QString& key) {
                if (failCapsuleCleanup && key.startsWith(
                        QStringLiteral("InputLeap/import-recovery/")) &&
                        key != QStringLiteral("InputLeap/import-recovery/commit")) {
                    return false;
                }
                credentials.remove(key); return true;
            });
    };
    ProfileHarness harness;
    std::optional<ConfigurationPublicSnapshot> candidate;
    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget target(appConfig, controller);
        const auto original = target.snapshot();
        ASSERT_TRUE(original);
        candidate = *original;
        candidate->preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        candidate->environmentProfiles.activeKind = EnvironmentProfile::Kind::Travel;
        std::optional<SensitiveBytes> oldSecret;
        oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
        std::optional<SensitiveBytes> newSecret;
        newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
        auto callbacks = target.target();
        ASSERT_EQ(callbacks.beginPending(*original, *candidate, oldSecret, newSecret),
                  ConfigurationImportService::MutationResult::Success);
        ASSERT_EQ(callbacks.compareAndApplySnapshot(*candidate, *original),
                  ConfigurationImportService::MutationResult::Success);
        ASSERT_EQ(callbacks.writePairingCode(newSecret, oldSecret),
                  ConfigurationImportService::MutationResult::Success);
        failCapsuleCleanup = true;
        EXPECT_EQ(callbacks.commitPending(),
                  ConfigurationImportService::MutationResult::Indeterminate);
        EXPECT_FALSE(settings.contains(
            QStringLiteral("configurationImportJournal/state")));
        EXPECT_TRUE(credentials.contains(
            QStringLiteral("InputLeap/import-recovery/old")));
        EXPECT_TRUE(credentials.contains(
            QStringLiteral("InputLeap/import-recovery/new")));
        EXPECT_TRUE(credentials.contains(
            QStringLiteral("InputLeap/import-recovery/commit")));
    }

    failCapsuleCleanup = false;
    const QString markerAccount =
        QStringLiteral("InputLeap/import-recovery/commit");
    const QByteArray authenticMarker = credentials.value(markerAccount);
    ASSERT_FALSE(authenticMarker.isEmpty());
    QByteArray tamperedMarker = authenticMarker;
    tamperedMarker[tamperedMarker.size() - 1] ^= char(0x01);
    credentials.insert(markerAccount, tamperedMarker);
    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::Blocked);
    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
    ASSERT_TRUE(candidate);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              candidate->preferences.language());

    credentials.insert(markerAccount, authenticMarker);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    AppConfig appConfig(&settings, makeStore());
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget target(appConfig, controller);
    EXPECT_EQ(target.recoverPendingImport(),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    const auto current = target.snapshot();
    ASSERT_TRUE(current);
    EXPECT_EQ(current->preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(current->preferences.port(), candidate->preferences.port());
    EXPECT_EQ(current->environmentProfiles.activeKind,
              candidate->environmentProfiles.activeKind);
    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("NEW-CODE"));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
}

TEST(ConfigurationAppTargetTests, CrashDuringCapsulePublicationIsCleanedWithoutBlockingStartup)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("capsule-publication-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QMap<QString, QByteArray> credentials;
    bool crashOnNewCapsule = false;
    bool failPrepareFinalize = false;
    bool failAbortOldCleanup = false;
    const auto makeStore = [&] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&](const QString& key, const QByteArray& value) {
                if (crashOnNewCapsule && key ==
                        QStringLiteral("InputLeap/import-recovery/new")) {
                    throw std::runtime_error("simulated capsule publication crash");
                }
                credentials.insert(key, value); return true;
            },
            [&](const QString& key) {
                if (crashOnNewCapsule && key ==
                        QStringLiteral("InputLeap/import-recovery/old")) {
                    return false;
                }
                if (failPrepareFinalize && key ==
                        QStringLiteral("InputLeap/import-recovery/prepare")) {
                    return false;
                }
                if (failAbortOldCleanup && key ==
                        QStringLiteral("InputLeap/import-recovery/old")) {
                    return false;
                }
                credentials.remove(key); return true;
            });
    };
    ProfileHarness harness;
    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget target(appConfig, controller);
        const auto original = target.snapshot();
        ASSERT_TRUE(original);
        auto candidate = *original;
        candidate.preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        auto callbacks = target.target();
        crashOnNewCapsule = true;
        EXPECT_EQ(callbacks.beginPending(
                      *original, candidate, std::nullopt, std::nullopt),
                  ConfigurationImportService::MutationResult::Failed);
    }
    crashOnNewCapsule = false;
    ASSERT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    ASSERT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
    const QString prepareAccount =
        QStringLiteral("InputLeap/import-recovery/prepare");
    const QByteArray authenticPrepare = credentials.value(prepareAccount);
    ASSERT_FALSE(authenticPrepare.isEmpty());
    QByteArray tamperedPrepare = authenticPrepare;
    tamperedPrepare[tamperedPrepare.size() - 1] ^= char(0x01);
    credentials.insert(prepareAccount, tamperedPrepare);
    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::Blocked);
    EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    credentials.insert(prepareAccount, authenticPrepare);

    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("pt-BR"));
    EXPECT_FALSE(credentials.contains(prepareAccount));

    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget target(appConfig, controller);
        const auto original = target.snapshot();
        ASSERT_TRUE(original);
        auto candidate = *original;
        candidate.preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        failPrepareFinalize = true;
        EXPECT_EQ(target.target().beginPending(
                      *original, candidate, std::nullopt, std::nullopt),
                  ConfigurationImportService::MutationResult::Indeterminate);
    }
    failPrepareFinalize = false;
    EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
    EXPECT_TRUE(credentials.contains(prepareAccount));
    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    EXPECT_FALSE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
    EXPECT_FALSE(credentials.contains(prepareAccount));

    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget target(appConfig, controller);
        const auto original = target.snapshot();
        ASSERT_TRUE(original);
        auto candidate = *original;
        candidate.preferences = *ConfigurationPortablePreferences::create(
            24801, 5, QStringLiteral("en"), true, false, true, false, true);
        auto callbacks = target.target();
        ASSERT_EQ(callbacks.beginPending(
                      *original, candidate, std::nullopt, std::nullopt),
                  ConfigurationImportService::MutationResult::Success);
        failAbortOldCleanup = true;
        EXPECT_EQ(callbacks.abortPending(),
                  ConfigurationImportService::MutationResult::Indeterminate);
    }
    failAbortOldCleanup = false;
    EXPECT_FALSE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    EXPECT_TRUE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
    EXPECT_TRUE(credentials.contains(prepareAccount));
    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(prepareAccount));
}

TEST(ConfigurationAppTargetTests, EarlyImportRecoveryRepairsPartialPreferencesBeforePreflight)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("early-import-recovery.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.setValue(QStringLiteral("port"), 24800);
    settings.setValue(QStringLiteral("logLevel"), 3);
    settings.setValue(QStringLiteral("cryptoEnabled"), true);
    settings.setValue(QStringLiteral("requireClientCertificate"), true);
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials{{account, QByteArrayLiteral("OLD-CODE")}};
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& key) -> std::optional<QByteArray> {
                const auto found = credentials.constFind(key);
                return found == credentials.cend() ? std::nullopt
                                                   : std::optional<QByteArray>(*found);
            },
            [&credentials](const QString& key, const QByteArray& value) {
                credentials.insert(key, value); return true;
            },
            [&credentials](const QString& key) {
                credentials.remove(key); return true;
            });
    };
    ProfileHarness harness;
    {
        AppConfig appConfig(&settings, makeStore());
        EnvironmentProfileController controller(harness.services());
        ASSERT_TRUE(controller.initialize());
        ConfigurationAppTarget target(appConfig, controller);
        const auto original = target.snapshot();
        ASSERT_TRUE(original);
        auto candidate = *original;
        candidate.preferences = *ConfigurationPortablePreferences::create(
            24800, 3, QStringLiteral("pt-BR"), false, false,
            false, false, false);
        std::optional<SensitiveBytes> oldSecret;
        oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
        std::optional<SensitiveBytes> newSecret;
        newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
        ASSERT_EQ(target.target().beginPending(
                      *original, candidate, oldSecret, newSecret),
                  ConfigurationImportService::MutationResult::Success);
        settings.setValue(QStringLiteral("cryptoEnabled"), false);
        settings.sync();
    }
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::InvalidValue);

    EXPECT_EQ(ConfigurationAppTarget::recoverPortablePreferencesBeforePreflight(
                  settings, makeStore()),
              ConfigurationAppTarget::PendingRecoveryResult::Recovered);
    EXPECT_EQ(StartupSettingsPreflight::inspect(settings),
              StartupSettingsPreflight::Status::Valid);
    EXPECT_TRUE(settings.value(QStringLiteral("cryptoEnabled")).toBool());
    EXPECT_TRUE(settings.value(QStringLiteral("requireClientCertificate")).toBool());
    EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
}

TEST(ConfigurationAppTargetTests, PendingRecoveryNeverOverwritesExternalSensitiveWriter)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("external-writer.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials;
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    AppConfig appConfig(&settings, std::move(store));
    ProfileHarness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(appConfig, controller);
    const auto original = appTarget.snapshot();
    ASSERT_TRUE(original);
    auto candidate = *original;
    candidate.preferences = *ConfigurationPortablePreferences::create(
        24801, 5, QStringLiteral("en"), true, false, true, false, true);
    std::optional<SensitiveBytes> oldSecret;
    oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
    std::optional<SensitiveBytes> newSecret;
    newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    auto callbacks = appTarget.target();
    ASSERT_EQ(callbacks.beginPending(*original, candidate, oldSecret, newSecret),
              ConfigurationImportService::MutationResult::Success);
    credentials.insert(account, QByteArrayLiteral("EXTERNAL-CODE"));

    EXPECT_EQ(appTarget.recoverPendingImport(),
              ConfigurationAppTarget::PendingRecoveryResult::Blocked);
    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("EXTERNAL-CODE"));
    EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    const auto unchanged = appTarget.snapshot();
    ASSERT_TRUE(unchanged);
    EXPECT_EQ(ConfigurationPublicSnapshotCodec::encode(*unchanged),
              ConfigurationPublicSnapshotCodec::encode(*original));
}

TEST(ConfigurationAppTargetTests, CommitRejectsPublicStateChangedAfterFinalVerification)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("commit-race.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials;
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    AppConfig appConfig(&settings, std::move(store));
    ProfileHarness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(appConfig, controller);
    const auto original = appTarget.snapshot();
    ASSERT_TRUE(original);
    auto candidate = *original;
    candidate.preferences = *ConfigurationPortablePreferences::create(
        24801, 5, QStringLiteral("en"), true, false, true, false, true);
    std::optional<SensitiveBytes> oldSecret;
    oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
    std::optional<SensitiveBytes> newSecret;
    newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    auto callbacks = appTarget.target();
    ASSERT_EQ(callbacks.beginPending(*original, candidate, oldSecret, newSecret),
              ConfigurationImportService::MutationResult::Success);
    ASSERT_EQ(callbacks.compareAndApplySnapshot(candidate, *original),
              ConfigurationImportService::MutationResult::Success);
    ASSERT_EQ(callbacks.writePairingCode(newSecret, oldSecret),
              ConfigurationImportService::MutationResult::Success);
    auto external = candidate;
    external.preferences = *ConfigurationPortablePreferences::create(
        24801, 5, QStringLiteral("fr"), true, false, true, false, true);
    ASSERT_EQ(callbacks.compareAndApplySnapshot(external, candidate),
              ConfigurationImportService::MutationResult::Success);

    EXPECT_EQ(callbacks.commitPending(),
              ConfigurationImportService::MutationResult::ConcurrentModification);
    EXPECT_TRUE(settings.contains(QStringLiteral("configurationImportJournal/state")));
}

TEST(ConfigurationAppTargetTests, ConcurrentJournalPublisherCannotMutateCapsulesOrJournal)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("journal-lock.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    const QString account = QStringLiteral("InputLeap/file-transfer-pairing-code");
    QMap<QString, QByteArray> credentials;
    credentials.insert(account, QByteArrayLiteral("OLD-CODE"));
    SecureCredentialStore store(
        [&credentials](const QString& key) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(key);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& key, const QByteArray& value) {
            credentials.insert(key, value); return true;
        },
        [&credentials](const QString& key) {
            credentials.remove(key); return true;
        });
    AppConfig appConfig(&settings, std::move(store));
    ProfileHarness harness;
    EnvironmentProfileController controller(harness.services());
    ASSERT_TRUE(controller.initialize());
    ConfigurationAppTarget appTarget(appConfig, controller);
    const auto original = appTarget.snapshot();
    ASSERT_TRUE(original);
    auto candidate = *original;
    candidate.preferences = *ConfigurationPortablePreferences::create(
        24801, 5, QStringLiteral("en"), true, false, true, false, true);
    std::optional<SensitiveBytes> oldSecret;
    oldSecret.emplace(QByteArrayLiteral("OLD-CODE"));
    std::optional<SensitiveBytes> newSecret;
    newSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    QLockFile competingPublisher(QDir(QDir::tempPath()).filePath(
        QStringLiteral("inputleap-import-journal.lock")));
    ASSERT_TRUE(competingPublisher.tryLock(1000));

    EXPECT_EQ(appTarget.target().beginPending(
                  *original, candidate, oldSecret, newSecret),
              ConfigurationImportService::MutationResult::ConcurrentModification);
    EXPECT_FALSE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    EXPECT_EQ(credentials.value(account), QByteArrayLiteral("OLD-CODE"));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));

    competingPublisher.unlock();
    auto callbacks = appTarget.target();
    ASSERT_EQ(callbacks.beginPending(
                  *original, candidate, oldSecret, newSecret),
              ConfigurationImportService::MutationResult::Success);
    EXPECT_FALSE(competingPublisher.tryLock(1000));
    EXPECT_EQ(callbacks.abortPending(),
              ConfigurationImportService::MutationResult::Success);
    EXPECT_FALSE(settings.contains(QStringLiteral("configurationImportJournal/state")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/old")));
    EXPECT_FALSE(credentials.contains(QStringLiteral("InputLeap/import-recovery/new")));
    ASSERT_TRUE(competingPublisher.tryLock(1000));
    EXPECT_EQ(appTarget.recoverPendingImport(),
              ConfigurationAppTarget::PendingRecoveryResult::Blocked);
    competingPublisher.unlock();
    EXPECT_EQ(appTarget.recoverPendingImport(),
              ConfigurationAppTarget::PendingRecoveryResult::NotNeeded);
}

} // namespace
