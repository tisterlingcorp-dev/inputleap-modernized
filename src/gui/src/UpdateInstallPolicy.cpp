#include "UpdateInstallPolicy.h"

#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>

#include <array>
#include <optional>

#if defined(Q_OS_WIN)
#include <Windows.h>
#include <io.h>
#else
#include <sys/stat.h>
#endif

namespace {
struct FileIdentity {
    quint64 device = 0;
    quint64 index = 0;
    quint64 size = 0;
    quint64 modified = 0;
    bool operator==(const FileIdentity&) const = default;
};

std::optional<FileIdentity> identity(QFile& file)
{
#if defined(Q_OS_WIN)
    const intptr_t native = _get_osfhandle(file.handle());
    if (native == -1)
        return std::nullopt;
    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(reinterpret_cast<HANDLE>(native), &information))
        return std::nullopt;
    return FileIdentity{
        information.dwVolumeSerialNumber,
        (quint64(information.nFileIndexHigh) << 32) | information.nFileIndexLow,
        (quint64(information.nFileSizeHigh) << 32) | information.nFileSizeLow,
        (quint64(information.ftLastWriteTime.dwHighDateTime) << 32) |
            information.ftLastWriteTime.dwLowDateTime,
    };
#else
    struct stat information{};
    if (::fstat(file.handle(), &information) != 0)
        return std::nullopt;
    return FileIdentity{
        quint64(information.st_dev), quint64(information.st_ino),
        quint64(information.st_size),
        (quint64(information.st_mtim.tv_sec) * 1000000000ULL) +
            quint64(information.st_mtim.tv_nsec),
    };
#endif
}

std::optional<std::array<quint64, 3>> semanticVersion(const QString& value,
                                                      bool stableOnly)
{
    static const QRegularExpression stable(
        QStringLiteral("^(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})$"));
    static const QRegularExpression local(
        QStringLiteral("^(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})(?:-[0-9A-Za-z.-]+)?$"));
    const auto match = (stableOnly ? stable : local).match(value);
    if (!match.hasMatch())
        return std::nullopt;
    return std::array<quint64, 3>{match.captured(1).toULongLong(),
                                  match.captured(2).toULongLong(),
                                  match.captured(3).toULongLong()};
}
}

bool UpdateInstallPolicy::verifyStagedPackage(
    const QString& path, const UpdateService::Release& release)
{
    const QFileInfo information(path);
    if (!release.installable ||
        release.packageType != UpdateService::PackageType::WindowsMsi ||
        release.size == 0 || release.size > UpdateService::MaxPackageBytes ||
        release.sha256.size() != QCryptographicHash::hashLength(QCryptographicHash::Sha256) ||
        !information.isAbsolute() || !information.isFile() || information.isSymLink() ||
        information.suffix().compare(QStringLiteral("msi"), Qt::CaseInsensitive) != 0) {
        return false;
    }

    QFile package(path);
    if (!package.open(QIODevice::ReadOnly))
        return false;
    const auto before = identity(package);
    if (!before || before->size != release.size)
        return false;

    QCryptographicHash hash(QCryptographicHash::Sha256);
    quint64 bytes = 0;
    while (!package.atEnd()) {
        const QByteArray chunk = package.read(64 * 1024);
        if (chunk.isEmpty() && !package.atEnd())
            return false;
        bytes += quint64(chunk.size());
        if (bytes > release.size)
            return false;
        hash.addData(chunk);
    }
    const auto after = identity(package);
    if (!after || *before != *after || bytes != release.size ||
        hash.result() != release.sha256) {
        return false;
    }

    QFile currentPath(path);
    if (!currentPath.open(QIODevice::ReadOnly))
        return false;
    const auto current = identity(currentPath);
    return current && *current == *after;
}

UpdateInstallPolicy::Decision UpdateInstallPolicy::evaluate(const Input& input)
{
    const auto current = semanticVersion(input.currentVersion, false);
    const auto offered = semanticVersion(input.release.version, true);
    if (!current || !offered || *offered <= *current ||
        !input.release.installable ||
        input.release.packageType != UpdateService::PackageType::WindowsMsi) {
        return Decision::NotANewerInstallableMsi;
    }
    if (!verifyStagedPackage(input.stagedPath, input.release))
        return Decision::PackageNotVerified;
    if (input.activeTransfers)
        return Decision::ActiveTransfers;
    if (!input.configurationValid)
        return Decision::InvalidConfiguration;
    if (input.stopPending)
        return Decision::StopPending;
    if (!input.stopConfirmed)
        return Decision::StopNotConfirmed;
    return Decision::Allowed;
}

UpdateInstallPolicy::MsiOutcome UpdateInstallPolicy::classifyMsiExitCode(quint32 exitCode)
{
    switch (exitCode) {
    case 0:
        return MsiOutcome::Success;
    case 3010:
        return MsiOutcome::SuccessRestartRequired;
    case 1602:
        return MsiOutcome::Cancelled;
    default:
        return MsiOutcome::Failed;
    }
}

bool UpdateInstallPolicy::transactionCompleted(MsiOutcome outcome)
{
    return outcome == MsiOutcome::Success ||
           outcome == MsiOutcome::SuccessRestartRequired;
}

bool UpdateInstallPolicy::platformSupportsInstallation()
{
#if defined(Q_OS_WIN)
    return true;
#else
    return false;
#endif
}
