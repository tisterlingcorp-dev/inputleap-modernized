/* InputLeap -- strict versioned plaintext format inside the authenticated sensitive envelope. */
#pragma once

#include "SensitiveBytes.h"

#include <optional>

class ConfigurationSensitivePayload
{
public:
    static constexpr qsizetype MaxPairingCodeBytes = 1024;

    struct Snapshot {
        std::optional<SensitiveBytes> pairingCode;
    };

    enum class Error {
        None,
        Malformed,
        UnsupportedVersion,
        InvalidState,
        TooLarge,
        InvalidUtf8
    };

    struct DecodeResult {
        Error error = Error::Malformed;
        std::optional<Snapshot> snapshot;
    };

    static SensitiveBytes encode(const Snapshot& snapshot);
    static DecodeResult decode(const SensitiveBytes& plaintext);
};
