#pragma once

#include "SecureCredentialStore.h"

#include <QJsonObject>

class QSettings;

class AppConfigSettingsJournal
{
public:
    enum class RecoveryResult {
        NotNeeded,
        RecoveredOriginal,
        RecoveredCandidate,
        Blocked
    };

    inline static const QString PairingAccount =
        QStringLiteral("InputLeap/file-transfer-pairing-code");
    inline static const QString CandidateCapsuleAccount =
        QStringLiteral("InputLeap/settings-save-recovery/candidate");
    inline static const QString CommitMarkerAccount =
        QStringLiteral("InputLeap/settings-save-recovery/committed");
    inline static const QString AuthenticationKeyAccount =
        QStringLiteral("InputLeap/settings-save-recovery/auth-key");

    AppConfigSettingsJournal(QSettings& settings, SecureCredentialStore& credentials);

    static QJsonObject capture(QSettings& settings);
    static bool apply(QSettings& settings, const QJsonObject& state);

    bool begin(const QJsonObject& original, const QJsonObject& candidate,
               const std::optional<SensitiveBytes>& candidateSecret);
    bool markPublicApplied();
    bool commit();
    RecoveryResult recover();

private:
    QSettings& settings_;
    SecureCredentialStore& credentials_;
};
