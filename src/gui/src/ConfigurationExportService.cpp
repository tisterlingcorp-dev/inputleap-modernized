/* InputLeap -- secure configuration package export and atomic write service. */
#include "ConfigurationExportService.h"

#include "ConfigurationSensitiveEnvelope.h"
#include "ConfigurationSensitivePayload.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QLockFile>
#include <QSaveFile>
#include <QTemporaryFile>

#include <utility>

#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {
bool promoteNoReplace(const QString& temporaryPath, const QString& destinationPath)
{
#ifdef Q_OS_WIN
    const QString nativeTemporary = QDir::toNativeSeparators(temporaryPath);
    const QString nativeDestination = QDir::toNativeSeparators(destinationPath);
    return CreateHardLinkW(reinterpret_cast<LPCWSTR>(nativeDestination.utf16()),
                           reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()), nullptr) != FALSE;
#else
    const QByteArray temporary = QFile::encodeName(temporaryPath);
    const QByteArray destination = QFile::encodeName(destinationPath);
    return ::link(temporary.constData(), destination.constData()) == 0;
#endif
}
} // namespace

ConfigurationExportService::BuildResult
ConfigurationExportService::build(const ConfigurationPublicSnapshot& snapshot)
{
    return build(snapshot, Options{}, {});
}

ConfigurationExportService::BuildResult
ConfigurationExportService::build(const ConfigurationPublicSnapshot& snapshot,
                                  const Options& options,
                                  SensitiveDataReader sensitiveDataReader)
{
    const QJsonObject publicObject = ConfigurationPublicSnapshotCodec::encode(snapshot);
    const auto validatedSnapshot = ConfigurationPublicSnapshotCodec::decode(publicObject);
    if (validatedSnapshot.error != ConfigurationPublicSnapshotCodec::Error::None)
        return {Error::InvalidPublicSnapshot, std::nullopt};

    ConfigurationPackageCodec::Package package;
    package.publicData = publicObject;

    if (options.includeSensitive) {
        if (!options.password || options.password->isEmpty())
            return {Error::PasswordRequired, std::nullopt};
        if (!sensitiveDataReader)
            return {Error::SensitiveDataUnavailable, std::nullopt};
        SensitiveData sensitiveData = sensitiveDataReader();
        if (!sensitiveData.readable)
            return {Error::SensitiveDataUnavailable, std::nullopt};
        ConfigurationSensitivePayload::Snapshot sensitiveSnapshot;
        sensitiveSnapshot.pairingCode = std::move(sensitiveData.pairingCode);
        SensitiveBytes sensitivePlaintext = ConfigurationSensitivePayload::encode(sensitiveSnapshot);
        const auto validatedSensitive = ConfigurationSensitivePayload::decode(sensitivePlaintext);
        if (validatedSensitive.error != ConfigurationSensitivePayload::Error::None)
            return {Error::SensitiveDataInvalid, std::nullopt};

        const QByteArray publicBytes =
            QJsonDocument(publicObject).toJson(QJsonDocument::Compact);
        const QByteArray publicDigest =
            QCryptographicHash::hash(publicBytes, QCryptographicHash::Sha256);
        const auto encrypted = ConfigurationSensitiveEnvelope::encrypt(
            sensitivePlaintext.bytes(), *options.password, publicDigest);
        if (encrypted.error != ConfigurationSensitiveEnvelope::Error::None ||
            !encrypted.envelope) {
            return {Error::EncryptionFailed, std::nullopt};
        }
        package.sensitive = std::move(*encrypted.envelope);
    }

    QByteArray encoded = ConfigurationPackageCodec::encode(package);
    if (encoded.size() > ConfigurationPackageCodec::MaxPackageBytes)
        return {Error::TooLarge, std::nullopt};
    return {Error::None, std::move(encoded)};
}

ConfigurationExportService::Error
ConfigurationExportService::writeAtomically(const QString& path, const QByteArray& package,
                                            bool overwriteExisting)
{
    if (package.size() > ConfigurationPackageCodec::MaxPackageBytes)
        return Error::TooLarge;
    if (ConfigurationPackageCodec::decode(package).error != ConfigurationPackageCodec::Error::None)
        return Error::InvalidPackage;

    if (!overwriteExisting) {
        QLockFile destinationLock(path + QStringLiteral(".lock"));
        if (!destinationLock.tryLock(5000))
            return Error::FileCommitFailed;

        const QFileInfo destination(path);
        QTemporaryFile temporary(destination.dir().filePath(
            QStringLiteral(".%1.XXXXXX.tmp").arg(destination.fileName())));
        temporary.setAutoRemove(true);
        if (!temporary.open())
            return Error::FileCommitFailed;
        if (temporary.write(package) != package.size())
            return Error::FileWriteFailed;
        if (!temporary.flush())
            return Error::FileWriteFailed;
        const QString temporaryPath = temporary.fileName();
        temporary.close();
        if (!promoteNoReplace(temporaryPath, destination.absoluteFilePath()))
            return Error::FileCommitFailed;
        return Error::None;
    }

    QSaveFile file(path);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly))
        return Error::FileOpenFailed;
    if (file.write(package) != package.size()) {
        file.cancelWriting();
        return Error::FileWriteFailed;
    }
    if (!file.commit())
        return Error::FileCommitFailed;
    return Error::None;
}
