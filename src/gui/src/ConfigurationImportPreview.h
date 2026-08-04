/* InputLeap -- immutable, side-effect-free configuration import preview. */
#pragma once

#include "ConfigurationPublicSnapshot.h"
#include "ConfigurationSensitivePayload.h"

#include <QByteArray>
#include <QString>

#include <optional>

class ConfigurationImportPreview
{
public:
    struct Candidate {
        ConfigurationPublicSnapshot snapshot;
        std::optional<ConfigurationSensitivePayload::Snapshot> sensitive;
    };

    struct Summary {
        enum class PairingCodeAction { Preserve, Set, Clear };

        int preferenceChanges = 0;
        int profileChanges = 0;
        int profileCount = 0;
        int deviceReferences = 0;
        bool includesPairingCode = false;
        bool authenticated = false;
        PairingCodeAction pairingCodeAction = PairingCodeAction::Preserve;
        bool weakensTransportSecurity = false;
    };

    struct Preview {
        Candidate candidate;
        Summary summary;
    };

    enum class Error {
        None,
        InvalidPackage,
        InvalidCurrentSnapshot,
        InvalidPublicSnapshot,
        PasswordRequired,
        InvalidSensitiveEnvelope,
        SensitiveAuthenticationFailed,
        InvalidSensitivePayload
    };

    struct Result {
        Error error = Error::InvalidPackage;
        std::optional<Preview> preview;
    };

    static Result create(const QByteArray& package,
                         const ConfigurationPublicSnapshot& current,
                         const SensitiveBytes& password);
};
