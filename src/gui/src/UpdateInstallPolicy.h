#pragma once

#include "UpdateService.h"

#include <QString>

class UpdateInstallPolicy final
{
public:
    enum class Decision {
        Allowed,
        NotANewerInstallableMsi,
        PackageNotVerified,
        ActiveTransfers,
        InvalidConfiguration,
        StopPending,
        StopNotConfirmed
    };

    struct Input {
        UpdateService::Release release;
        QString currentVersion;
        QString stagedPath;
        bool activeTransfers = false;
        bool configurationValid = true;
        bool stopPending = false;
        bool stopConfirmed = false;
    };

    enum class MsiOutcome {
        Installing,
        Success,
        SuccessRestartRequired,
        Cancelled,
        FailedBeforeInstall,
        Failed
    };

    static Decision evaluate(const Input& input);
    static bool verifyStagedPackage(const QString& path,
                                    const UpdateService::Release& release);
    static MsiOutcome classifyMsiExitCode(quint32 exitCode);
    static bool transactionCompleted(MsiOutcome outcome);
    static bool platformSupportsInstallation();
};
