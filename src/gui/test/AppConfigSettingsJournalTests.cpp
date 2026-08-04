#include "AppConfigSettingsJournal.h"

#include <gtest/gtest.h>

#include <QHash>
#include <QSettings>
#include <QTemporaryDir>

namespace {

SecureCredentialStore credentialStore(QHash<QString, QByteArray>& credentials)
{
    return SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(account);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value);
            return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account);
            return true;
        });
}

TEST(AppConfigSettingsJournalTests, RecoveryRestoresOriginalWhenPublicChangedButSecretDidNot)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("public-only-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
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

    AppConfigSettingsJournal recovered(settings, store);
    const QByteArray authenticKey = credentials.value(
        AppConfigSettingsJournal::AuthenticationKeyAccount);
    ASSERT_EQ(authenticKey.size(), 32);
    credentials.insert(AppConfigSettingsJournal::AuthenticationKeyAccount,
                       QByteArray(32, 'F'));
    EXPECT_EQ(recovered.recover(),
              AppConfigSettingsJournal::RecoveryResult::Blocked);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_TRUE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    credentials.insert(AppConfigSettingsJournal::AuthenticationKeyAccount,
                       authenticKey);
    EXPECT_EQ(recovered.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredOriginal);
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("pt-BR"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("OLD-CODE"));
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests, PendingJournalNeverPromotesCandidateWhenBothSecretsAreAbsent)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("pre-apply-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, std::nullopt));
    ASSERT_TRUE(AppConfigSettingsJournal::apply(settings, candidate));

    EXPECT_EQ(journal.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredOriginal);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("pt-BR"));
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests,
     PendingJournalNeverPromotesCandidateWhenSecretIsUnchanged)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("unchanged-secret-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("UNCHANGED-CODE"));
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> unchangedSecret;
    unchangedSecret.emplace(QByteArrayLiteral("UNCHANGED-CODE"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, unchangedSecret));

    EXPECT_EQ(journal.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredOriginal);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("pt-BR"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("UNCHANGED-CODE"));
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests,
     InterruptedClearSecretRollsForwardCandidateAtomically)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("clear-secret-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, std::nullopt));

    credentials.remove(AppConfigSettingsJournal::PairingAccount);
    EXPECT_EQ(journal.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredCandidate);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::PairingAccount));
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests,
     ForgedPublicAppliedFlagCannotPromoteCandidate)
{
    QTemporaryDir directory;
    QSettings settings(directory.filePath(QStringLiteral("forged-phase.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, std::nullopt));
    settings.setValue(QStringLiteral("appConfigSaveJournal/state"),
                      QStringLiteral("public-applied"));
    settings.sync();

    EXPECT_EQ(journal.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredOriginal);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("pt-BR"));
}

TEST(AppConfigSettingsJournalTests, RecoveryCommitsCandidateWhenPublicAndSecretChanged)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("secret-applied-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
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

    AppConfigSettingsJournal recovered(settings, store);
    EXPECT_EQ(recovered.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredCandidate);
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("NEW-CODE"));
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests, CommitCleanupCrashRecoversConfirmedCandidate)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("commit-cleanup-crash.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    bool failCapsuleRemoval = true;
    SecureCredentialStore failingStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto found = credentials.constFind(account);
            return found == credentials.cend() ? std::nullopt
                                               : std::optional<QByteArray>(*found);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value);
            return true;
        },
        [&credentials, &failCapsuleRemoval](const QString& account) {
            if (account == AppConfigSettingsJournal::CandidateCapsuleAccount &&
                failCapsuleRemoval) {
                failCapsuleRemoval = false;
                return false;
            }
            credentials.remove(account);
            return true;
        });
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    AppConfigSettingsJournal journal(settings, failingStore);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    ASSERT_TRUE(AppConfigSettingsJournal::apply(settings, candidate));
    ASSERT_TRUE(journal.markPublicApplied());
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("NEW-CODE"));

    EXPECT_FALSE(journal.commit());
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_TRUE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));

    auto recoveryStore = credentialStore(credentials);
    AppConfigSettingsJournal recovered(settings, recoveryStore);
    EXPECT_EQ(recovered.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredCandidate);
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("NEW-CODE"));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests, TamperedCandidateCapsuleBlocksWithoutMutation)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("tampered-capsule.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    settings.setValue(QStringLiteral("language"), QStringLiteral("en"));
    settings.sync();
    credentials.insert(AppConfigSettingsJournal::CandidateCapsuleAccount,
                       QByteArrayLiteral("tampered"));

    EXPECT_EQ(journal.recover(), AppConfigSettingsJournal::RecoveryResult::Blocked);
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("OLD-CODE"));
    EXPECT_TRUE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
}

TEST(AppConfigSettingsJournalTests, UnrelatedPublicWriterBlocksWithoutBeingOverwritten)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("external-public.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    settings.setValue(QStringLiteral("language"), QStringLiteral("fr"));
    settings.sync();

    EXPECT_EQ(journal.recover(), AppConfigSettingsJournal::RecoveryResult::Blocked);
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("fr"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("OLD-CODE"));
    EXPECT_TRUE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
}

TEST(AppConfigSettingsJournalTests, TamperedCandidateSecretSuffixBlocksWithoutRollbackOrCleanup)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("tampered-secret-suffix.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    ASSERT_TRUE(AppConfigSettingsJournal::apply(settings, candidate));
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("NEW-CODE"));
    QByteArray capsule = credentials.value(
        AppConfigSettingsJournal::CandidateCapsuleAccount);
    ASSERT_FALSE(capsule.isEmpty());
    capsule[capsule.size() - 1] ^= 0x01;
    credentials.insert(AppConfigSettingsJournal::CandidateCapsuleAccount, capsule);

    EXPECT_EQ(journal.recover(), AppConfigSettingsJournal::RecoveryResult::Blocked);
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("en"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("NEW-CODE"));
    EXPECT_TRUE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_TRUE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests, OversizedPublicStateIsRejectedBeforePublishingRecoveryArtifacts)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("oversized-journal.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("logFilename"),
                     QString(1024 * 1024, QLatin1Char('x')));
    std::optional<SensitiveBytes> noSecret;
    AppConfigSettingsJournal journal(settings, store);

    EXPECT_FALSE(journal.begin(original, candidate, noSecret));
    EXPECT_FALSE(settings.contains(QStringLiteral("appConfigSaveJournal/state")));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

TEST(AppConfigSettingsJournalTests, MalformedOrphanCapsuleBlocksWithoutTouchingActiveSecret)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("orphan-capsule.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("ACTIVE-CODE"));
    credentials.insert(AppConfigSettingsJournal::CandidateCapsuleAccount,
                       QByteArrayLiteral("orphan"));
    auto store = credentialStore(credentials);

    AppConfigSettingsJournal journal(settings, store);
    EXPECT_EQ(journal.recover(), AppConfigSettingsJournal::RecoveryResult::Blocked);
    EXPECT_TRUE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("ACTIVE-CODE"));
}

TEST(AppConfigSettingsJournalTests, StrippedJournalRecoversFromBoundCapsule)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("stripped-journal.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("language"), QStringLiteral("pt-BR"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    credentials.insert(AppConfigSettingsJournal::PairingAccount,
                       QByteArrayLiteral("OLD-CODE"));
    auto store = credentialStore(credentials);
    const QJsonObject original = AppConfigSettingsJournal::capture(settings);
    QJsonObject candidate = original;
    candidate.insert(QStringLiteral("language"), QStringLiteral("en"));
    std::optional<SensitiveBytes> candidateSecret;
    candidateSecret.emplace(QByteArrayLiteral("NEW-CODE"));
    AppConfigSettingsJournal journal(settings, store);
    ASSERT_TRUE(journal.begin(original, candidate, candidateSecret));
    ASSERT_TRUE(AppConfigSettingsJournal::apply(settings, candidate));
    settings.remove(QStringLiteral("appConfigSaveJournal"));
    settings.sync();

    EXPECT_EQ(journal.recover(),
              AppConfigSettingsJournal::RecoveryResult::RecoveredOriginal);
    settings.sync();
    EXPECT_EQ(settings.value(QStringLiteral("language")).toString(),
              QStringLiteral("pt-BR"));
    EXPECT_EQ(credentials.value(AppConfigSettingsJournal::PairingAccount),
              QByteArrayLiteral("OLD-CODE"));
    EXPECT_FALSE(credentials.contains(AppConfigSettingsJournal::CandidateCapsuleAccount));
}

} // namespace
