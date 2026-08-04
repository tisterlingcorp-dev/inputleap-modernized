/* InputLeap -- immutable, side-effect-free configuration import preview. */
#include "ConfigurationImportPreview.h"

#include "ConfigurationPackageCodec.h"
#include "ConfigurationSensitiveEnvelope.h"
#include "ConfigurationPortablePreferences.h"
#include "EnvironmentProfileJsonCodec.h"

#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMap>


#include <utility>

namespace {
int preferenceChangeCount(const ConfigurationPortablePreferences& current,
                          const ConfigurationPortablePreferences& candidate)
{
    const QJsonObject before = ConfigurationPortablePreferencesCodec::encode(current);
    const QJsonObject after = ConfigurationPortablePreferencesCodec::encode(candidate);
    int changes = 0;
    for (const QString& key : before.keys()) {
        if (before.value(key) != after.value(key))
            ++changes;
    }
    return changes;
}

bool weakensTransportSecurity(const ConfigurationPortablePreferences& current,
                              const ConfigurationPortablePreferences& candidate)
{
    return (current.cryptoEnabled() && !candidate.cryptoEnabled()) ||
           (current.requireClientCertificate() && !candidate.requireClientCertificate());
}

QMap<QString, QJsonObject> profilesByKind(const EnvironmentProfileJsonCodec::Collection& collection)
{
    const QJsonArray profiles = EnvironmentProfileJsonCodec::encode(collection)
                                    .value(QStringLiteral("profiles")).toArray();
    QMap<QString, QJsonObject> result;
    for (const auto& value : profiles) {
        const QJsonObject object = value.toObject();
        result.insert(object.value(QStringLiteral("kind")).toString(), object);
    }
    return result;
}

int profileChangeCount(const EnvironmentProfileJsonCodec::Collection& current,
                       const EnvironmentProfileJsonCodec::Collection& candidate)
{
    const auto before = profilesByKind(current);
    const auto after = profilesByKind(candidate);
    int changes = 0;
    for (const QString& kind : after.keys()) {
        if (!before.contains(kind) || before.value(kind) != after.value(kind))
            ++changes;
    }
    return changes;
}

}

ConfigurationImportPreview::Result
ConfigurationImportPreview::create(const QByteArray& packageBytes,
                                   const ConfigurationPublicSnapshot& current,
                                   const SensitiveBytes& password)
{
    const auto currentValidation = ConfigurationPublicSnapshotCodec::decode(
        ConfigurationPublicSnapshotCodec::encode(current));
    if (currentValidation.error != ConfigurationPublicSnapshotCodec::Error::None)
        return {Error::InvalidCurrentSnapshot, std::nullopt};

    const auto decodedPackage = ConfigurationPackageCodec::decode(packageBytes);
    if (decodedPackage.error != ConfigurationPackageCodec::Error::None || !decodedPackage.package)
        return {Error::InvalidPackage, std::nullopt};
    const auto decodedPublic = ConfigurationPublicSnapshotCodec::decode(
        decodedPackage.package->publicData);
    if (decodedPublic.error != ConfigurationPublicSnapshotCodec::Error::None || !decodedPublic.snapshot)
        return {Error::InvalidPublicSnapshot, std::nullopt};

    Preview preview;
    preview.candidate.snapshot = std::move(*decodedPublic.snapshot);
    preview.summary.authenticated = decodedPackage.package->sensitive.has_value();
    if (decodedPackage.package->sensitive) {
        if (password.isEmpty())
            return {Error::PasswordRequired, std::nullopt};
        const QByteArray publicBytes = QJsonDocument(decodedPackage.package->publicData)
                                           .toJson(QJsonDocument::Compact);
        const QByteArray digest = QCryptographicHash::hash(
            publicBytes, QCryptographicHash::Sha256);
        auto decrypted = ConfigurationSensitiveEnvelope::decrypt(
            *decodedPackage.package->sensitive, password, digest);
        if (decrypted.error == ConfigurationSensitiveEnvelope::Error::AuthenticationFailed)
            return {Error::SensitiveAuthenticationFailed, std::nullopt};
        if (decrypted.error != ConfigurationSensitiveEnvelope::Error::None || !decrypted.plaintext)
            return {Error::InvalidSensitiveEnvelope, std::nullopt};
        auto sensitive = ConfigurationSensitivePayload::decode(*decrypted.plaintext);
        if (sensitive.error != ConfigurationSensitivePayload::Error::None ||
            !sensitive.snapshot) {
            return {Error::InvalidSensitivePayload, std::nullopt};
        }
        preview.summary.includesPairingCode = sensitive.snapshot->pairingCode.has_value();
        preview.summary.pairingCodeAction = preview.summary.includesPairingCode
            ? Summary::PairingCodeAction::Set
            : Summary::PairingCodeAction::Clear;
        preview.candidate.sensitive = std::move(*sensitive.snapshot);
    }

    preview.summary.preferenceChanges = preferenceChangeCount(
        current.preferences, preview.candidate.snapshot.preferences);
    preview.summary.weakensTransportSecurity = weakensTransportSecurity(
        current.preferences, preview.candidate.snapshot.preferences);
    preview.summary.profileChanges = profileChangeCount(
        current.environmentProfiles, preview.candidate.snapshot.environmentProfiles);
    preview.summary.profileCount = preview.candidate.snapshot.environmentProfiles.profiles.size();
    for (const auto& profile : preview.candidate.snapshot.environmentProfiles.profiles)
        preview.summary.deviceReferences += profile.devices.size();
    return {Error::None, std::move(preview)};
}
