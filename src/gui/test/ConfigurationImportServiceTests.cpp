#include "ConfigurationImportService.h"
#include "ConfigurationExportService.h"
#include "ConfigurationPackageCodec.h"

#include <gtest/gtest.h>

#include <QFile>
#include <QTemporaryDir>

#include <stdexcept>

namespace {
ConfigurationPublicSnapshot transactionSnapshot(const QString& language)
{
    ConfigurationPublicSnapshot snapshot;
    snapshot.preferences = *ConfigurationPortablePreferences::create(
        24800, 3, language, true, false, false, false, false);
    const QUuid uuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        ScreenLayout::Device layoutDevice{uuid, QStringLiteral("desktop"), QRect(0, 0, 100, 100),
                                           {{QStringLiteral("display"), QRect(0, 0, 100, 100), 1.0,
                                             Qt::PrimaryOrientation, false}}};
        EnvironmentProfile profile;
        profile.kind = kind;
        profile.layout = {1, 1, {QStringLiteral("desktop")}, ScreenLayout({layoutDevice})};
        profile.devices = {{uuid, QStringLiteral("desktop"), DevicePermissions::ControlMouseKeyboard}};
        snapshot.environmentProfiles.profiles.push_back(profile);
    }
    snapshot.environmentProfiles.activeKind = EnvironmentProfile::Kind::Home;
    return snapshot;
}

struct MemoryTarget {
    ConfigurationPublicSnapshot snapshot = transactionSnapshot(QStringLiteral("pt-BR"));
    std::optional<QByteArray> secret = QByteArrayLiteral("OLD-CODE");
    bool rejectCandidateSecret = false;
    bool rejectCas = false;
    bool secretReadable = true;
    bool publicIndeterminate = false;
    bool publicFailedAfterMutation = false;
    bool publicIndeterminateAfterMutation = false;
    bool indeterminateAfterSecretMutation = false;
    bool externalChangeBeforeSensitiveWrite = false;
    int publicMutations = 0;
    int secretMutations = 0;
    int journalBegins = 0;
    int journalCommits = 0;
    int journalAborts = 0;
    bool journalPending = false;
    bool rejectJournalBegin = false;
    bool rejectJournalCommit = false;
    bool concurrentJournalCommit = false;
    bool externalSecretChangeAtCommit = false;
    QString backupPath;

    ConfigurationImportService::Target callbacks()
    {
        return {
            [this] { return std::optional<ConfigurationPublicSnapshot>{snapshot}; },
            [this] {
                ConfigurationImportService::SensitiveReadResult result;
                result.readable = secretReadable;
                if (secret)
                    result.value.emplace(QByteArray(*secret));
                return result;
            },
            [this](const ConfigurationPublicSnapshot& candidate,
                   const ConfigurationPublicSnapshot&) {
                if (publicIndeterminate)
                    return ConfigurationImportService::MutationResult::Indeterminate;
                if (rejectCas)
                    return ConfigurationImportService::MutationResult::ConcurrentModification;
                EXPECT_TRUE(QFile::exists(backupPath));
                snapshot = candidate;
                ++publicMutations;
                if (publicFailedAfterMutation) {
                    publicFailedAfterMutation = false;
                    return ConfigurationImportService::MutationResult::Failed;
                }
                if (publicIndeterminateAfterMutation) {
                    publicIndeterminateAfterMutation = false;
                    return ConfigurationImportService::MutationResult::Indeterminate;
                }
                return ConfigurationImportService::MutationResult::Success;
            },
            [this](const std::optional<SensitiveBytes>& value,
                   const std::optional<SensitiveBytes>& expected) {
                ++secretMutations;
                if (externalChangeBeforeSensitiveWrite) {
                    secret = QByteArrayLiteral("EXTERNAL-CODE");
                    externalChangeBeforeSensitiveWrite = false;
                }
                const bool expectedMatches = (!secret && !expected) ||
                    (secret && expected && expected->securelyEquals(*secret));
                if (!expectedMatches)
                    return ConfigurationImportService::MutationResult::ConcurrentModification;
                if (rejectCandidateSecret && value &&
                    value->bytes() == QByteArrayLiteral("NEW-CODE"))
                    return ConfigurationImportService::MutationResult::Failed;
                secret = value
                    ? std::optional<QByteArray>{QByteArray(value->bytes().data(), value->bytes().size())}
                    : std::nullopt;
                if (indeterminateAfterSecretMutation) {
                    indeterminateAfterSecretMutation = false;
                    return ConfigurationImportService::MutationResult::Indeterminate;
                }
                return ConfigurationImportService::MutationResult::Success;
            },
            [this](const ConfigurationPublicSnapshot&,
                   const ConfigurationPublicSnapshot&,
                   const std::optional<SensitiveBytes>&,
                   const std::optional<SensitiveBytes>&) {
                ++journalBegins;
                if (rejectJournalBegin)
                    return ConfigurationImportService::MutationResult::Failed;
                journalPending = true;
                return ConfigurationImportService::MutationResult::Success;
            },
            [this] {
                ++journalCommits;
                if (concurrentJournalCommit) {
                    if (externalSecretChangeAtCommit)
                        secret = QByteArrayLiteral("EXTERNAL-CODE");
                    return ConfigurationImportService::MutationResult::ConcurrentModification;
                }
                if (rejectJournalCommit)
                    return ConfigurationImportService::MutationResult::Failed;
                journalPending = false;
                return ConfigurationImportService::MutationResult::Success;
            },
            [this] {
                ++journalAborts;
                journalPending = false;
                return ConfigurationImportService::MutationResult::Success;
            }};
    }
};

ConfigurationImportPreview::Preview candidatePreview()
{
    ConfigurationImportPreview::Preview preview;
    preview.candidate.snapshot = transactionSnapshot(QStringLiteral("en"));
    preview.candidate.sensitive.emplace();
    preview.candidate.sensitive->pairingCode.emplace(QByteArrayLiteral("NEW-CODE"));
    preview.summary.includesPairingCode = true;
    return preview;
}

ConfigurationImportService::Error applyWithPassword(
    const ConfigurationImportPreview::Preview& preview,
    MemoryTarget& target,
    bool authorizeDowngrade = false)
{
    SensitiveBytes password(QByteArrayLiteral("backup-password"));
    return ConfigurationImportService::apply(
        preview, target.snapshot, target.backupPath,
        ConfigurationImportService::Options{&password, authorizeDowngrade, true},
        target.callbacks());
}

TEST(ConfigurationImportServiceTests, BackupExistsBeforeSuccessfulMutationAndReadbackMatches)
{
    MemoryTarget target;
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    target.backupPath = directory.filePath(QStringLiteral("automatic-backup.ilconfig"));

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::None);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("en"));
    EXPECT_EQ(target.secret, std::optional<QByteArray>{QByteArrayLiteral("NEW-CODE")});
    EXPECT_EQ(target.publicMutations, 1);
    EXPECT_TRUE(QFile::exists(target.backupPath));
    QFile backup(target.backupPath);
    ASSERT_TRUE(backup.open(QIODevice::ReadOnly));
    EXPECT_EQ(ConfigurationPackageCodec::decode(backup.readAll()).error,
              ConfigurationPackageCodec::Error::None);
}

TEST(ConfigurationImportServiceTests, ConcurrentChangeAtCommitIsNeverReportedAsSuccess)
{
    MemoryTarget target;
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    target.backupPath = directory.filePath(QStringLiteral("automatic-backup.ilconfig"));
    target.concurrentJournalCommit = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::ConcurrentModification);
    EXPECT_FALSE(target.journalPending);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.journalAborts, 1);
}

TEST(ConfigurationImportServiceTests, ConcurrentCredentialChangeAtCommitRollsBackPublicState)
{
    MemoryTarget target;
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    target.backupPath = directory.filePath(QStringLiteral("commit-race-backup.ilconfig"));
    target.concurrentJournalCommit = true;
    target.externalSecretChangeAtCommit = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::ConcurrentModification);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.secret,
              std::optional<QByteArray>{QByteArrayLiteral("EXTERNAL-CODE")});
    EXPECT_FALSE(target.journalPending);
    EXPECT_EQ(target.journalAborts, 1);
}

TEST(ConfigurationImportServiceTests, BackupFailurePerformsZeroMutations)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("missing/backup.ilconfig"));

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::BackupWriteFailed);
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
}

TEST(ConfigurationImportServiceTests, SecurityDowngradeRequiresExplicitConsentBeforeAnyMutation)
{
    MemoryTarget blocked;
    QTemporaryDir directory;
    blocked.backupPath = directory.filePath(QStringLiteral("blocked-backup.ilconfig"));
    auto preview = candidatePreview();
    preview.candidate.snapshot.preferences = *ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("en"), false, false, false, false, false);

    const auto blockedResult = applyWithPassword(preview, blocked);

    EXPECT_EQ(blockedResult,
              ConfigurationImportService::Error::SecurityDowngradeRequiresConsent);
    EXPECT_EQ(blocked.publicMutations, 0);
    EXPECT_EQ(blocked.secretMutations, 0);
    EXPECT_FALSE(QFile::exists(blocked.backupPath));

    MemoryTarget authorized;
    authorized.backupPath = directory.filePath(QStringLiteral("authorized-backup.ilconfig"));
    const auto authorizedResult = applyWithPassword(preview, authorized, true);
    EXPECT_EQ(authorizedResult, ConfigurationImportService::Error::None);
    EXPECT_FALSE(authorized.snapshot.preferences.cryptoEnabled());
}

TEST(ConfigurationImportServiceTests, UnauthenticatedImportRequiresExplicitServiceConsent)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    auto preview = candidatePreview();
    preview.summary.authenticated = false;
    SensitiveBytes password(QByteArrayLiteral("backup-password"));

    const auto result = ConfigurationImportService::apply(
        preview, target.snapshot, target.backupPath,
        ConfigurationImportService::Options{&password, false, false},
        target.callbacks());

    EXPECT_EQ(result,
              ConfigurationImportService::Error::UnauthenticatedImportRequiresConsent);
    EXPECT_FALSE(QFile::exists(target.backupPath));
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, CompareAndSwapFailureReportsConcurrencyWithoutMutation)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.rejectCas = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::ConcurrentModification);
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, UnreadableSensitiveStateFailsBeforeBackupOrMutation)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.secretReadable = false;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::TargetReadFailed);
    EXPECT_FALSE(QFile::exists(target.backupPath));
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, IndeterminatePublicMutationIsNotMisreportedAsConcurrency)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.publicIndeterminate = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::IndeterminateState);
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, PublicFailureAfterMutationRestoresOriginalSnapshot)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.publicFailedAfterMutation = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::PublicApplyFailed);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.publicMutations, 2);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, PublicIndeterminateAfterMutationRestoresOriginalSnapshot)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.publicIndeterminateAfterMutation = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::IndeterminateState);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.publicMutations, 2);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, SecretFailureRollsBackPublicAndOldSecretExactly)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.rejectCandidateSecret = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::SensitiveApplyFailed);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.secret, std::optional<QByteArray>{QByteArrayLiteral("OLD-CODE")});
    EXPECT_EQ(target.publicMutations, 2);
    EXPECT_EQ(target.secretMutations, 1);
}

TEST(ConfigurationImportServiceTests, IndeterminateAfterSecretMutationRestoresPublicAndSecret)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.indeterminateAfterSecretMutation = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::IndeterminateState);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.secret, std::optional<QByteArray>{QByteArrayLiteral("OLD-CODE")});
    EXPECT_EQ(target.publicMutations, 2);
    EXPECT_EQ(target.secretMutations, 2);
}

TEST(ConfigurationImportServiceTests, PublicOnlyImportPreservesExistingSecret)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    auto preview = candidatePreview();
    preview.candidate.sensitive.reset();

    const auto result = applyWithPassword(preview, target);

    EXPECT_EQ(result, ConfigurationImportService::Error::None);
    EXPECT_EQ(target.secret, std::optional<QByteArray>{QByteArrayLiteral("OLD-CODE")});
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, AuthenticatedAbsentSecretClearsExistingSecret)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    auto preview = candidatePreview();
    ASSERT_TRUE(preview.candidate.sensitive);
    preview.candidate.sensitive->pairingCode.reset();

    const auto result = applyWithPassword(preview, target);

    EXPECT_EQ(result, ConfigurationImportService::Error::None);
    EXPECT_FALSE(target.secret.has_value());
    EXPECT_EQ(target.secretMutations, 1);
}

TEST(ConfigurationImportServiceTests, SensitiveCasPreservesExternalWriterAndRollsBackPublic)
{
    MemoryTarget target;
    QTemporaryDir directory;
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.externalChangeBeforeSensitiveWrite = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::ConcurrentModification);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("pt-BR"));
    EXPECT_EQ(target.secret,
              std::optional<QByteArray>{QByteArrayLiteral("EXTERNAL-CODE")});
    EXPECT_EQ(target.publicMutations, 2);
}

TEST(ConfigurationImportServiceTests, PreflightCallbackExceptionIsContainedWithoutMutation)
{
    MemoryTarget target;
    auto callbacks = target.callbacks();
    callbacks.readSnapshot = []() -> std::optional<ConfigurationPublicSnapshot> {
        throw std::runtime_error("injected preflight failure");
    };
    SensitiveBytes password(QByteArrayLiteral("backup-password"));

    const auto result = ConfigurationImportService::apply(
        candidatePreview(), target.snapshot, QStringLiteral("unused.ilconfig"),
        ConfigurationImportService::Options{&password, false, true}, callbacks);

    EXPECT_EQ(result, ConfigurationImportService::Error::TargetReadFailed);
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
}

TEST(ConfigurationImportServiceTests, BackupRestorabilityValidatesPublicSnapshotAndSensitiveAuthentication)
{
    const auto snapshot = transactionSnapshot(QStringLiteral("pt-BR"));
    SensitiveBytes password(QByteArrayLiteral("backup-password"));
    ConfigurationExportService::Options options;
    options.includeSensitive = true;
    options.password = &password;
    const auto backup = ConfigurationExportService::build(
        snapshot, options,
        [] {
            return ConfigurationExportService::SensitiveData{
                true, SensitiveBytes(QByteArrayLiteral("OLD-CODE"))};
        });
    ASSERT_TRUE(backup.package);

    EXPECT_TRUE(ConfigurationImportService::backupIsRestorable(
        *backup.package, snapshot, std::optional<SensitiveBytes>{
            SensitiveBytes(QByteArrayLiteral("OLD-CODE"))}, password));
    SensitiveBytes wrongPassword(QByteArrayLiteral("wrong"));
    EXPECT_FALSE(ConfigurationImportService::backupIsRestorable(
        *backup.package, snapshot, std::optional<SensitiveBytes>{
            SensitiveBytes(QByteArrayLiteral("OLD-CODE"))}, wrongPassword));

    auto transplanted = ConfigurationPackageCodec::decode(*backup.package);
    ASSERT_TRUE(transplanted.package);
    QJsonObject preferences = transplanted.package->publicData
                                  .value(QStringLiteral("preferences")).toObject();
    preferences.insert(QStringLiteral("language"), QStringLiteral("en"));
    transplanted.package->publicData.insert(QStringLiteral("preferences"), preferences);
    EXPECT_FALSE(ConfigurationImportService::backupIsRestorable(
        ConfigurationPackageCodec::encode(*transplanted.package), snapshot,
        std::optional<SensitiveBytes>{SensitiveBytes(QByteArrayLiteral("OLD-CODE"))},
        password));
}

TEST(ConfigurationImportServiceTests, JournalBeginFailurePerformsZeroMutations)
{
    MemoryTarget target;
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.rejectJournalBegin = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::JournalBeginFailed);
    EXPECT_EQ(target.journalBegins, 1);
    EXPECT_EQ(target.publicMutations, 0);
    EXPECT_EQ(target.secretMutations, 0);
    EXPECT_FALSE(target.journalPending);
}

TEST(ConfigurationImportServiceTests, JournalCommitFailureLeavesCandidatePendingForStartupRecovery)
{
    MemoryTarget target;
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    target.backupPath = directory.filePath(QStringLiteral("backup.ilconfig"));
    target.rejectJournalCommit = true;

    const auto result = applyWithPassword(candidatePreview(), target);

    EXPECT_EQ(result, ConfigurationImportService::Error::JournalCommitFailed);
    EXPECT_EQ(target.snapshot.preferences.language(), QStringLiteral("en"));
    EXPECT_EQ(target.secret, std::optional<QByteArray>{QByteArrayLiteral("NEW-CODE")});
    EXPECT_TRUE(target.journalPending);
    EXPECT_EQ(target.journalBegins, 1);
    EXPECT_EQ(target.journalCommits, 1);
}

} // namespace
