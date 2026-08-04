/* InputLeap -- transactional configuration import with verified backup and rollback. */
#include "ConfigurationImportService.h"

#include "ConfigurationExportService.h"
#include "ConfigurationPackageCodec.h"
#include "ConfigurationPublicSnapshot.h"
#include "ConfigurationSensitiveEnvelope.h"
#include "ConfigurationSensitivePayload.h"

#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>

namespace {
bool sameSnapshot(const ConfigurationPublicSnapshot& first,
                  const ConfigurationPublicSnapshot& second)
{
    return ConfigurationPublicSnapshotCodec::encode(first) ==
           ConfigurationPublicSnapshotCodec::encode(second);
}

bool sameSensitive(const std::optional<SensitiveBytes>& first,
                   const std::optional<SensitiveBytes>& second)
{
    if (first.has_value() != second.has_value())
        return false;
    return !first || first->securelyEquals(second->bytes());
}
}

bool ConfigurationImportService::backupIsRestorable(
    const QByteArray& encoded,
    const ConfigurationPublicSnapshot& expectedSnapshot,
    const std::optional<SensitiveBytes>& expectedPairingCode,
    const SensitiveBytes& password)
{
    const auto package = ConfigurationPackageCodec::decode(encoded);
    if (package.error != ConfigurationPackageCodec::Error::None || !package.package)
        return false;
    const auto publicSnapshot = ConfigurationPublicSnapshotCodec::decode(
        package.package->publicData);
    if (publicSnapshot.error != ConfigurationPublicSnapshotCodec::Error::None ||
        !publicSnapshot.snapshot ||
        !sameSnapshot(*publicSnapshot.snapshot, expectedSnapshot)) {
        return false;
    }
    if (!package.package->sensitive)
        return false;

    const QByteArray publicBytes = QJsonDocument(package.package->publicData)
                                       .toJson(QJsonDocument::Compact);
    const QByteArray digest = QCryptographicHash::hash(
        publicBytes, QCryptographicHash::Sha256);
    auto decrypted = ConfigurationSensitiveEnvelope::decrypt(
        *package.package->sensitive, password, digest);
    if (decrypted.error != ConfigurationSensitiveEnvelope::Error::None ||
        !decrypted.plaintext) {
        return false;
    }
    auto sensitive = ConfigurationSensitivePayload::decode(*decrypted.plaintext);
    return sensitive.error == ConfigurationSensitivePayload::Error::None &&
           sensitive.snapshot &&
           sameSensitive(sensitive.snapshot->pairingCode, expectedPairingCode);
}

ConfigurationImportService::Error
ConfigurationImportService::apply(const ConfigurationImportPreview::Preview& preview,
                                  const ConfigurationPublicSnapshot& expectedCurrent,
                                  const QString& backupPath,
                                  const Options& options,
                                  const Target& target)
{
    try {
    if (!target.readSnapshot || !target.readPairingCode ||
        !target.compareAndApplySnapshot || !target.writePairingCode ||
        !target.beginPending || !target.commitPending || !target.abortPending) {
        return Error::InvalidTarget;
    }
    const ConfigurationPublicSnapshot original = expectedCurrent;

    const auto current = target.readSnapshot();
    if (!current)
        return Error::TargetReadFailed;
    if (!sameSnapshot(*current, original))
        return Error::ConcurrentModification;
    if (!preview.summary.authenticated && !options.authorizeUnauthenticatedImport)
        return Error::UnauthenticatedImportRequiresConsent;
    const auto& beforeSecurity = original.preferences;
    const auto& afterSecurity = preview.candidate.snapshot.preferences;
    const bool weakensSecurity =
        (beforeSecurity.cryptoEnabled() && !afterSecurity.cryptoEnabled()) ||
        (beforeSecurity.requireClientCertificate() &&
         !afterSecurity.requireClientCertificate());
    if (weakensSecurity && !options.authorizeSecurityDowngrade)
        return Error::SecurityDowngradeRequiresConsent;
    const SensitiveReadResult oldSensitive = target.readPairingCode();
    if (!oldSensitive.readable)
        return Error::TargetReadFailed;
    const auto& oldPairingCode = oldSensitive.value;

    ConfigurationExportService::Options backupOptions;
    backupOptions.includeSensitive = true;
    backupOptions.password = options.backupPassword;
    const auto backup = ConfigurationExportService::build(
        original, backupOptions,
        [&oldPairingCode] {
            ConfigurationExportService::SensitiveData data;
            data.readable = true;
            if (oldPairingCode) {
                const QByteArrayView bytes = oldPairingCode->bytes();
                data.pairingCode.emplace(QByteArray(bytes.data(), bytes.size()));
            }
            return data;
        });
    if (backup.error != ConfigurationExportService::Error::None || !backup.package)
        return Error::BackupBuildFailed;
    if (ConfigurationExportService::writeAtomically(backupPath, *backup.package, false) !=
        ConfigurationExportService::Error::None) {
        return Error::BackupWriteFailed;
    }
    QFile committedBackup(backupPath);
    if (!committedBackup.open(QIODevice::ReadOnly))
        return Error::BackupVerificationFailed;
    if (committedBackup.size() > ConfigurationPackageCodec::MaxPackageBytes)
        return Error::BackupVerificationFailed;
    const QByteArray committedBytes = committedBackup.read(
        ConfigurationPackageCodec::MaxPackageBytes + 1);
    if (committedBytes.size() > ConfigurationPackageCodec::MaxPackageBytes)
        return Error::BackupVerificationFailed;
    if (committedBytes != *backup.package ||
        !options.backupPassword ||
        !backupIsRestorable(committedBytes, original, oldPairingCode,
                            *options.backupPassword)) {
        return Error::BackupVerificationFailed;
    }

    const auto immediatelyBeforeApply = target.readSnapshot();
    if (!immediatelyBeforeApply)
        return Error::TargetReadFailed;
    if (!sameSnapshot(*immediatelyBeforeApply, original))
        return Error::ConcurrentModification;
    const SensitiveReadResult sensitiveImmediatelyBeforeApply = target.readPairingCode();
    if (!sensitiveImmediatelyBeforeApply.readable)
        return Error::TargetReadFailed;
    if (!sameSensitive(sensitiveImmediatelyBeforeApply.value, oldPairingCode))
        return Error::ConcurrentModification;

    const auto& newPairingCode = preview.candidate.sensitive
        ? preview.candidate.sensitive->pairingCode : oldPairingCode;
    const MutationResult journalBegin = target.beginPending(
        original, preview.candidate.snapshot, oldPairingCode, newPairingCode);
    if (journalBegin == MutationResult::ConcurrentModification)
        return Error::ConcurrentModification;
    if (journalBegin != MutationResult::Success)
        return Error::JournalBeginFailed;

    const auto rollback = [&](bool restoreSensitive, bool verifySensitive) {
        try {
            target.compareAndApplySnapshot(original, preview.candidate.snapshot);
            if (restoreSensitive && preview.candidate.sensitive)
                target.writePairingCode(
                    oldPairingCode, preview.candidate.sensitive->pairingCode);
            const auto restoredSnapshot = target.readSnapshot();
            const SensitiveReadResult restoredPairingCode = target.readPairingCode();
            const bool snapshotVerified = restoredSnapshot &&
                                          sameSnapshot(*restoredSnapshot, original);
            const bool sensitiveVerified = !verifySensitive || !preview.candidate.sensitive ||
                (restoredPairingCode.readable &&
                 sameSensitive(restoredPairingCode.value, oldPairingCode));
            if (!snapshotVerified || !sensitiveVerified)
                return false;
            return target.abortPending() == MutationResult::Success;
        }
        catch (...) {
            return false;
        }
    };

    MutationResult publicMutation = MutationResult::Indeterminate;
    try {
        publicMutation = target.compareAndApplySnapshot(
            preview.candidate.snapshot, original);
    }
    catch (...) {
        return rollback(false, true)
            ? Error::IndeterminateState : Error::RollbackFailed;
    }
    if (publicMutation == MutationResult::ConcurrentModification)
        return target.abortPending() == MutationResult::Success
            ? Error::ConcurrentModification : Error::JournalCommitFailed;
    if (publicMutation == MutationResult::Failed)
        return rollback(false, true)
            ? Error::PublicApplyFailed : Error::RollbackFailed;
    if (publicMutation == MutationResult::Indeterminate)
        return rollback(false, true)
            ? Error::IndeterminateState : Error::RollbackFailed;

    if (preview.candidate.sensitive) {
        MutationResult sensitiveMutation = MutationResult::Indeterminate;
        try {
            sensitiveMutation = target.writePairingCode(
                preview.candidate.sensitive->pairingCode, oldPairingCode);
        }
        catch (...) {
            return rollback(true, true)
                ? Error::IndeterminateState : Error::RollbackFailed;
        }
        if (sensitiveMutation != MutationResult::Success) {
            if (sensitiveMutation == MutationResult::ConcurrentModification) {
                if (!rollback(false, false))
                    return Error::RollbackFailed;
                return Error::ConcurrentModification;
            }
            if (sensitiveMutation == MutationResult::Failed) {
                if (!rollback(false, true))
                    return Error::RollbackFailed;
                return Error::SensitiveApplyFailed;
            }
            if (!rollback(true, true))
                return Error::RollbackFailed;
            return Error::IndeterminateState;
        }
    }

    std::optional<ConfigurationPublicSnapshot> appliedSnapshot;
    SensitiveReadResult appliedPairingCode;
    try {
        appliedSnapshot = target.readSnapshot();
        appliedPairingCode = target.readPairingCode();
    }
    catch (...) {
        return rollback(true, true)
            ? Error::IndeterminateState : Error::RollbackFailed;
    }
    const bool publicVerified = appliedSnapshot &&
                                sameSnapshot(*appliedSnapshot, preview.candidate.snapshot);
    const bool sensitiveVerified = !preview.candidate.sensitive ||
        (appliedPairingCode.readable &&
         sameSensitive(appliedPairingCode.value,
                       preview.candidate.sensitive->pairingCode));
    if (!publicVerified || !sensitiveVerified)
        return rollback(true, true) ? Error::VerificationFailed : Error::RollbackFailed;
    const MutationResult committed = target.commitPending();
    if (committed == MutationResult::Success)
        return Error::None;
    if (committed == MutationResult::ConcurrentModification)
        return rollback(false, false)
            ? Error::ConcurrentModification : Error::RollbackFailed;
    return Error::JournalCommitFailed;
    }
    catch (...) {
        return Error::TargetReadFailed;
    }
}
