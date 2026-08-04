/* InputLeap -- atomic environment profile persistence. */
#pragma once

#include "EnvironmentProfile.h"

#include <QList>
#include <QByteArrayView>
#include <functional>
#include <optional>

class QSettings;

class EnvironmentProfileStore
{
public:
    static constexpr int OldestSupportedSchemaVersion = 1;
    static constexpr int SchemaVersion = 2;
    enum class LoadStatus { Loaded, Missing, InvalidSchema, FutureSchema, SettingsError };
    enum class SaveResult {
        Success,
        AlreadyInitialized,
        InvalidProfile,
        ReadOnlyFutureSchema,
        ConcurrentModification,
        SettingsError,
        IndeterminateState
    };
    enum class RecoveryResult {
        Recovered,
        NotNeeded,
        Unavailable,
        ReadOnlyFutureSchema,
        ConcurrentModification,
        SettingsError,
        IndeterminateState
    };
    struct Mutation {
        SaveResult result = SaveResult::SettingsError;
        QString previousGeneration;
        QString resultingGeneration;
        std::optional<EnvironmentProfile> promotedProfile;
    };
    struct VerifiedState {
        EnvironmentProfile::Kind activeKind = EnvironmentProfile::Kind::Home;
        QString generation;
        EnvironmentProfile profile;
    };
    using VerifiedConsumer = std::function<bool(const VerifiedState&)>;
    using SyncFunction = std::function<bool(QSettings&)>;
    using AuthenticationFunction =
        std::function<std::optional<QByteArray>(QByteArrayView, bool)>;
    using AuthenticationKeyPresentFunction = std::function<bool()>;

    explicit EnvironmentProfileStore(
        QSettings& settings, SyncFunction sync = {},
        AuthenticationFunction authentication = {},
        AuthenticationKeyPresentFunction authenticationKeyPresent = {});

    // Narrow test seam for proving that path aliases serialize on one lock.
    static QString lockFilePathForSettings(const QSettings& settings);

    LoadStatus load();
    LoadStatus loadStatus() const;
    QList<EnvironmentProfile> profiles() const;
    std::optional<EnvironmentProfile> profile(EnvironmentProfile::Kind kind) const;
    std::optional<EnvironmentProfile::Kind> activeKind() const;
    std::optional<QString> currentGeneration() const;

    SaveResult initializeFromLegacy(const EnvironmentProfile& current);
    SaveResult replaceProfile(const EnvironmentProfile& profile);
    SaveResult setActive(EnvironmentProfile::Kind kind);
    Mutation replaceProfileIfGeneration(
        const EnvironmentProfile& profile, const QString& expectedGeneration,
        const std::optional<QString>& recoveryGenerationOverride = std::nullopt);
    Mutation replaceAllIfGeneration(const QList<EnvironmentProfile>& profiles,
                                    EnvironmentProfile::Kind activeKind,
                                    const QString& expectedGeneration,
                                    const std::optional<QString>& recoveryGenerationOverride = std::nullopt);
    Mutation setActiveIfGeneration(
        EnvironmentProfile::Kind kind, const QString& expectedGeneration,
        const std::optional<QString>& recoveryGenerationOverride = std::nullopt);
    SaveResult verifyGeneration(const QString& expectedGeneration);
    SaveResult consumeVerifiedGeneration(const QString& expectedGeneration,
                                         const VerifiedConsumer& consumer);
    RecoveryResult recoverLastValidGeneration();

private:
    SaveResult persist(
        const QList<EnvironmentProfile>& profiles, EnvironmentProfile::Kind activeKind,
        const std::optional<QString>& recoveryGenerationOverride = std::nullopt);
    Mutation replaceProfileImpl(
        const EnvironmentProfile& profile, const std::optional<QString>& expectedGeneration,
        const std::optional<QString>& recoveryGenerationOverride = std::nullopt);
    Mutation setActiveImpl(
        EnvironmentProfile::Kind kind, const std::optional<QString>& expectedGeneration,
        const std::optional<QString>& recoveryGenerationOverride = std::nullopt);
    bool writeGeneration(const QString& group, const QList<EnvironmentProfile>& profiles,
                         EnvironmentProfile::Kind activeKind);
    bool readGeneration(const QString& group, QList<EnvironmentProfile>& profiles,
                        EnvironmentProfile::Kind& activeKind) const;
    bool sync();
    bool mutationsAllowed() const;
    QString lockFilePath() const;
    void markIndeterminate();

    QSettings& settings_;
    SyncFunction sync_;
    AuthenticationFunction authentication_;
    AuthenticationKeyPresentFunction authenticationKeyPresent_;
    QList<EnvironmentProfile> profiles_;
    std::optional<EnvironmentProfile::Kind> activeKind_;
    std::optional<QString> generation_;
    LoadStatus loadStatus_ = LoadStatus::Missing;
    bool saveFailed_ = false;
    bool mutationInProgress_ = false;
};
