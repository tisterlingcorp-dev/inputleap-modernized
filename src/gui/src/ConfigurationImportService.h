/* InputLeap -- transactional configuration import with verified backup and rollback. */
#pragma once

#include "ConfigurationImportPreview.h"

#include <QString>

#include <functional>
#include <optional>

class ConfigurationImportService
{
public:
    enum class MutationResult {
        Success,
        ConcurrentModification,
        Failed,
        Indeterminate
    };

    struct SensitiveReadResult {
        bool readable = false;
        std::optional<SensitiveBytes> value;
    };

    struct Target {
        std::function<std::optional<ConfigurationPublicSnapshot>()> readSnapshot;
        std::function<SensitiveReadResult()> readPairingCode;
        std::function<MutationResult(const ConfigurationPublicSnapshot& candidate,
                                     const ConfigurationPublicSnapshot& expected)> compareAndApplySnapshot;
        std::function<MutationResult(const std::optional<SensitiveBytes>& candidate,
                                     const std::optional<SensitiveBytes>& expected)> writePairingCode;
        std::function<MutationResult(
            const ConfigurationPublicSnapshot& original,
            const ConfigurationPublicSnapshot& candidate,
            const std::optional<SensitiveBytes>& oldPairingCode,
            const std::optional<SensitiveBytes>& newPairingCode)> beginPending;
        std::function<MutationResult()> commitPending;
        std::function<MutationResult()> abortPending;
    };

    struct Options {
        const SensitiveBytes* backupPassword = nullptr;
        bool authorizeSecurityDowngrade = false;
        bool authorizeUnauthenticatedImport = false;
    };

    enum class Error {
        None,
        InvalidTarget,
        TargetReadFailed,
        UnauthenticatedImportRequiresConsent,
        SecurityDowngradeRequiresConsent,
        BackupBuildFailed,
        BackupWriteFailed,
        BackupVerificationFailed,
        JournalBeginFailed,
        JournalCommitFailed,
        ConcurrentModification,
        PublicApplyFailed,
        SensitiveApplyFailed,
        VerificationFailed,
        RollbackFailed,
        IndeterminateState
    };

    static Error apply(const ConfigurationImportPreview::Preview& preview,
                       const ConfigurationPublicSnapshot& expectedCurrent,
                       const QString& backupPath,
                       const Options& options,
                       const Target& target);
    static bool backupIsRestorable(const QByteArray& encoded,
                                   const ConfigurationPublicSnapshot& expectedSnapshot,
                                   const std::optional<SensitiveBytes>& expectedPairingCode,
                                   const SensitiveBytes& password);
};
