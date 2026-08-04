/* InputLeap -- secure configuration package export and atomic write service. */
#pragma once

#include "ConfigurationPackageCodec.h"
#include "ConfigurationPublicSnapshot.h"
#include "SensitiveBytes.h"

#include <QByteArray>
#include <QString>

#include <functional>
#include <optional>

class ConfigurationExportService
{
public:
    struct SensitiveData {
        bool readable = false;
        std::optional<SensitiveBytes> pairingCode;
    };
    using SensitiveDataReader = std::function<SensitiveData()>;

    struct Options {
        bool includeSensitive = false;
        const SensitiveBytes* password = nullptr;
    };

    enum class Error {
        None,
        InvalidPublicSnapshot,
        PasswordRequired,
        SensitiveDataUnavailable,
        SensitiveDataInvalid,
        EncryptionFailed,
        TooLarge,
        InvalidPackage,
        FileOpenFailed,
        FileWriteFailed,
        FileCommitFailed
    };

    struct BuildResult {
        Error error = Error::InvalidPublicSnapshot;
        std::optional<QByteArray> package;
    };

    static BuildResult build(const ConfigurationPublicSnapshot& snapshot);
    static BuildResult build(const ConfigurationPublicSnapshot& snapshot,
                             const Options& options,
                             SensitiveDataReader sensitiveDataReader = {});
    static Error writeAtomically(const QString& path, const QByteArray& package,
                                 bool overwriteExisting = true);
};
