/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2008 Volker Lanz (vl@fidra.de)
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>

#include "MainWindow.h"
#include "ui_MainWindow.h"

#include "AboutDialog.h"
#include "ServerConfigDialog.h"
#include "SettingsDialog.h"
#include "ConfigurationAppTarget.h"
#include "RecoveryArtifactAuthenticator.h"
#include "EnvironmentProfileSelector.h"
#include "EnvironmentProfileUiBinding.h"
#include "ZeroconfService.h"
#include "NetworkRecoveryCoordinator.h"
#include "DataDownloader.h"
#include "CommandProcess.h"
#include "FingerprintAcceptDialog.h"
#include "FileTransferController.h"
#include "FileTransferService.h"
#include "TransferPerformance.h"
#include "DeviceCardDropPolicy.h"
#include "QUtility.h"
#include "ProcessorArch.h"
#include "SslCertificate.h"
#include "LocalDeviceIdentity.h"
#include "LocalMonitorCollector.h"
#include "DeviceDisplayNameResolver.h"
#include "DevicePermissionsDialog.h"
#include "PairingWizard.h"
#include "DiagnosticsService.h"
#include "NotificationService.h"
#include "DiagnosticsRemediationService.h"
#include "SupportReportBuilder.h"
#include "UpdateDownloadService.h"
#include "UpdateHelperProtocol.h"
#include "UpdateInstallPolicy.h"
#include "UpdateTrustConfig.h"
#include "ClipboardHistoryDialog.h"
#include "EndpointPolicy.h"
#include "ProtectionPanel.h"
#include "base/String.h"
#include "common/DataDirectories.h"
#include "net/FingerprintDatabase.h"
#include "net/SecureUtils.h"

#include <QtCore>
#include <QtGui>
#include <QLabel>
#include <openssl/crypto.h>
#include <QVBoxLayout>
#include <QtNetwork>
#include <algorithm>
#include <limits>
#include <vector>
#include <QNetworkAccessManager>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QDialogButtonBox>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QFileDialog>
#include <QLineEdit>
#include <QInputDialog>
#include <QDesktopServices>
#include <QDir>
#include <QDialogButtonBox>
#include <QDirIterator>
#include <QProgressDialog>
#include <QPushButton>
#include <QAbstractButton>
#include <QPlainTextEdit>
#include <QRegularExpression>
#include <QHeaderView>
#include <QTableWidget>
#include <QFrame>
#include <QGridLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QSpinBox>
#include <QProgressBar>
#include <QScrollArea>
#include <QScreen>
#include <QStandardPaths>

#if defined(Q_OS_MAC)
#include <ApplicationServices/ApplicationServices.h>
#endif

#if defined(Q_OS_WIN)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#endif
#if !defined(Q_OS_WIN)
#include <sys/stat.h>
#endif

#include <signal.h>

#if !defined(Q_OS_WIN)
namespace {
bool pathContainsWindowsReparsePoint(const QString&)
{
    return false;
}
}
#endif

namespace {

void ensureAccessibleNames(QWidget* root)
{
    if (!root)
        return;
    for (QWidget* widget : root->findChildren<QWidget*>()) {
        if (!widget->accessibleName().isEmpty())
            continue;
        if (auto* button = qobject_cast<QAbstractButton*>(widget)) {
            QString name = button->text().simplified();
            if (name.isEmpty())
                name = button->objectName().simplified();
            if (!name.isEmpty())
                button->setAccessibleName(name);
        } else if (widget->focusPolicy() != Qt::NoFocus &&
                   !widget->objectName().isEmpty()) {
            widget->setAccessibleName(widget->objectName());
        }
    }
}

static const QString allFilesFilter(QObject::tr("All files (*.*)"));
#if defined(Q_OS_WIN)
static const char APP_CONFIG_NAME[] = "input-leap.sgc";
static const QString APP_CONFIG_FILTER(QObject::tr("InputLeap Configurations (*.sgc)"));
static QString bonjourBaseUrl = "http://binaries.symless.com/bonjour/";
static const char bonjourFilename32[] = "Bonjour.msi";
static const char bonjourFilename64[] = "Bonjour64.msi";
static const char bonjourTargetFilename[] = "Bonjour.msi";

bool setLowLatencyPriority(QProcess* process)
{
    if (process == nullptr || process->processId() == 0) {
        return false;
    }

    HANDLE handle = OpenProcess(PROCESS_SET_INFORMATION, FALSE, static_cast<DWORD>(process->processId()));
    if (handle == nullptr) {
        return false;
    }

    const BOOL ok = SetPriorityClass(handle, ABOVE_NORMAL_PRIORITY_CLASS);
    CloseHandle(handle);
    return ok == TRUE;
}

bool pathContainsWindowsReparsePoint(const QString& path)
{
    QString current = QFileInfo(path).absoluteFilePath();
    while (!current.isEmpty()) {
        const DWORD attributes = GetFileAttributesW(
            reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(current).utf16()));
        if (attributes != INVALID_FILE_ATTRIBUTES &&
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return true;
        }
        const QString parent = QFileInfo(current).absolutePath();
        if (parent == current)
            break;
        current = parent;
    }
    return false;
}

bool removeFileWithoutReparseRace(const QString& path)
{
    const QString native = QDir::toNativeSeparators(path);
    HANDLE handle = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),
                                DELETE | FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                nullptr, OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    BY_HANDLE_FILE_INFORMATION information{};
    const bool safe = GetFileInformationByHandle(handle, &information) &&
        (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    FILE_DISPOSITION_INFO disposition{TRUE};
    const bool removed = safe && SetFileInformationByHandle(
        handle, FileDispositionInfo, &disposition, sizeof(disposition));
    CloseHandle(handle);
    return removed;
}

bool writeAtomicFileWithoutReparseRace(const QString& path, const QByteArray& payload)
{
    const QFileInfo target(path);
    const QString temporaryPath = QDir(target.absolutePath()).filePath(
        QStringLiteral(".%1.%2.tmp").arg(target.fileName(),
            QString::number(QDateTime::currentMSecsSinceEpoch())));
    const QString nativeTemporary = QDir::toNativeSeparators(temporaryPath);
    HANDLE temporary = CreateFileW(
        reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()),
        GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (temporary == INVALID_HANDLE_VALUE)
        return false;
    BY_HANDLE_FILE_INFORMATION temporaryInfo{};
    if (!GetFileInformationByHandle(temporary, &temporaryInfo) ||
        (temporaryInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (temporaryInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        CloseHandle(temporary);
        DeleteFileW(reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()));
        return false;
    }
    DWORD written = 0;
    const bool wrote = WriteFile(temporary, payload.constData(),
                                 DWORD(payload.size()), &written, nullptr) &&
        written == DWORD(payload.size()) && FlushFileBuffers(temporary) == TRUE;
    const std::wstring finalWide = QDir::toNativeSeparators(path).toStdWString();
    const DWORD renameBytes = DWORD(sizeof(FILE_RENAME_INFO) +
                                     finalWide.size() * sizeof(wchar_t));
    std::vector<unsigned char> renameStorage(renameBytes);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(renameStorage.data());
    rename->ReplaceIfExists = TRUE;
    rename->RootDirectory = nullptr;
    rename->FileNameLength = DWORD(finalWide.size() * sizeof(wchar_t));
    memcpy(rename->FileName, finalWide.data(), rename->FileNameLength);
    const bool renamed = wrote && SetFileInformationByHandle(
        temporary, FileRenameInfo, rename, renameBytes) == TRUE;
    CloseHandle(temporary);
    if (!renamed)
        DeleteFileW(reinterpret_cast<LPCWSTR>(nativeTemporary.utf16()));
    return renamed;
}

class StagingDirectoryLock final
{
public:
    explicit StagingDirectoryLock(const QString& path)
    {
        const QString native = QDir::toNativeSeparators(path);
        handle_ = CreateFileW(reinterpret_cast<LPCWSTR>(native.utf16()),
                              FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                              nullptr);
        if (handle_ == INVALID_HANDLE_VALUE || pathContainsWindowsReparsePoint(path)) {
            if (handle_ != INVALID_HANDLE_VALUE)
                CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    ~StagingDirectoryLock()
    {
        if (handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
    }

    bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};
#else
bool removeFileWithoutReparseRace(const QString& path)
{
    return QFile::remove(path);
}

class StagingDirectoryLock final
{
public:
    explicit StagingDirectoryLock(const QString& path) : valid_{QFileInfo(path).isDir()} {}

    bool valid() const noexcept { return valid_; }

private:
    bool valid_ = false;
};

static const char APP_CONFIG_NAME[] = "input-leap.conf";
static const QString APP_CONFIG_FILTER(QObject::tr("InputLeap Configurations (*.conf)"));
#endif
static const QString APP_CONFIG_OPEN_FILTER(APP_CONFIG_FILTER + ";;" + allFilesFilter);
static const QString APP_CONFIG_SAVE_FILTER(APP_CONFIG_FILTER);
constexpr quint16 FILE_TRANSFER_PORT = 24810;
constexpr int DASHBOARD_DEVICE_TTL_SECONDS = 30;
constexpr int DASHBOARD_EXPIRY_CHECK_MS = 5000;

QByteArray updateFileSha256(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(64 * 1024);
        if (chunk.isEmpty() && !file.atEnd()) return {};
        hash.addData(chunk);
    }
    return hash.result();
}

struct UpdateResultFileIdentity {
    quint64 volume = 0;
    quint64 inode = 0;
    quint64 size = 0;
};

bool captureFileIdentity(QFile& file, UpdateResultFileIdentity& identity)
{
#if defined(Q_OS_WIN)
    const intptr_t native = _get_osfhandle(file.handle());
    if (native == -1)
        return false;
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(reinterpret_cast<HANDLE>(native), &info) ||
        (info.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        return false;
    }
    identity = {
        quint64(info.dwVolumeSerialNumber),
        (quint64(info.nFileIndexHigh) << 32) | info.nFileIndexLow,
        (quint64(info.nFileSizeHigh) << 32) | info.nFileSizeLow,
    };
    return true;
#else
    struct stat info{};
    if (::fstat(file.handle(), &info) != 0 || !S_ISREG(info.st_mode))
        return false;
    identity = {
        quint64(info.st_dev),
        quint64(info.st_ino),
        quint64(info.st_size),
    };
    return true;
#endif
}

bool sameFileIdentity(const UpdateResultFileIdentity& first,
                      const UpdateResultFileIdentity& second)
{
    return first.volume == second.volume && first.inode == second.inode &&
        first.size == second.size;
}

bool openResultFileWithoutReparsePoint(const QString& path, QFile& resultFile)
{
#if defined(Q_OS_WIN)
    const QString nativePath =
        QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    HANDLE handle = CreateFileW(reinterpret_cast<LPCWSTR>(nativePath.utf16()),
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE |
                                   FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                               nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),
                                  _O_BINARY | _O_RDONLY | _O_NOINHERIT);
    if (fd < 0) {
        CloseHandle(handle);
        return false;
    }
    if (!resultFile.open(fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle)) {
        _close(fd);
        return false;
    }
    return true;
#else
    if (QFileInfo(path).isSymLink())
        return false;
    resultFile.setFileName(path);
    return resultFile.open(QIODevice::ReadOnly);
#endif
}

bool readResultPayloadWithIdentity(const QString& path,
                                  QByteArray& encoded,
                                  UpdateResultFileIdentity* identity = nullptr)
{
    QFile first(path);
    if (!openResultFileWithoutReparsePoint(path, first))
        return false;
    UpdateResultFileIdentity pre{};
    if (!captureFileIdentity(first, pre)) {
        first.close();
        return false;
    }

    const QByteArray readBack =
        first.read(UpdateHelperProtocol::MaxResultBytes + 1);
    first.close();
    if (readBack.isEmpty() || readBack.size() > UpdateHelperProtocol::MaxResultBytes)
        return false;

    QFile second(path);
    if (!openResultFileWithoutReparsePoint(path, second))
        return false;
    UpdateResultFileIdentity post{};
    if (!captureFileIdentity(second, post))
        return false;
    second.close();
    if (!sameFileIdentity(pre, post))
        return false;

    encoded = readBack;
    if (identity)
        *identity = post;
    return true;
}

bool updateProcessPathMatches(qint64 pid, const QString& expectedPath)
{
#if defined(Q_OS_WIN)
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, DWORD(pid));
    if (process == nullptr) return false;
    std::vector<wchar_t> buffer(512);
    bool matches = false;
    while (buffer.size() <= 32768) {
        DWORD size = DWORD(buffer.size());
        if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
            const QString actual = QFileInfo(
                QString::fromWCharArray(buffer.data(), int(size))).canonicalFilePath();
            const QString expected = QFileInfo(expectedPath).canonicalFilePath();
            matches = !actual.isEmpty() &&
                actual.compare(expected, Qt::CaseInsensitive) == 0;
            break;
        }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) break;
        buffer.resize(buffer.size() * 2);
    }
    CloseHandle(process);
    return matches;
#else
    Q_UNUSED(pid);
    Q_UNUSED(expectedPath);
    return false;
#endif
}

bool terminateVerifiedUpdateProcess(qint64 pid, const QString& expectedPath)
{
#if defined(Q_OS_WIN)
    HANDLE process = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
        FALSE, DWORD(pid));
    if (!process) return false;
    std::vector<wchar_t> buffer(32768);
    DWORD size = DWORD(buffer.size());
    bool terminated = false;
    if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        const QString actual = QFileInfo(
            QString::fromWCharArray(buffer.data(), int(size))).canonicalFilePath();
        const QString expected = QFileInfo(expectedPath).canonicalFilePath();
        if (!actual.isEmpty() && actual.compare(expected, Qt::CaseInsensitive) == 0) {
            terminated = TerminateProcess(process, ERROR_CANCELLED) &&
                WaitForSingleObject(process, 5000) == WAIT_OBJECT_0;
        }
    }
    CloseHandle(process);
    return terminated;
#else
    Q_UNUSED(pid);
    Q_UNUSED(expectedPath);
    return false;
#endif
}

bool acquireUpdateInstallMutex(void*& storage)
{
#if defined(Q_OS_WIN)
    if (storage) return true;
    const QString name = UpdateHelperProtocol::installMutexName();
    HANDLE mutex = CreateMutexW(nullptr, TRUE,
        reinterpret_cast<LPCWSTR>(name.utf16()));
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        if (mutex) CloseHandle(mutex);
        return false;
    }
    storage = mutex;
    return true;
#else
    Q_UNUSED(storage);
    return false;
#endif
}

void releaseUpdateInstallMutex(void*& storage)
{
#if defined(Q_OS_WIN)
    if (!storage) return;
    HANDLE mutex = static_cast<HANDLE>(storage);
    ReleaseMutex(mutex);
    CloseHandle(mutex);
    storage = nullptr;
#else
    Q_UNUSED(storage);
#endif
}

DeviceConnectionModel::State dashboardState(AppConnectionState state)
{
    switch (state) {
    case AppConnectionState::CONNECTING: return DeviceConnectionModel::State::Connecting;
    case AppConnectionState::CONNECTED: return DeviceConnectionModel::State::Connected;
    case AppConnectionState::TRANSFERRING: return DeviceConnectionModel::State::Transferring;
    case AppConnectionState::DISCONNECTED: return DeviceConnectionModel::State::Offline;
    }
    return DeviceConnectionModel::State::Offline;
}

QString formatTransferProgress(const QString& action,
                               const QString& fileName,
                               quint64 bytesDone,
                               quint64 bytesTotal,
                               const QString& details = QString())
{
    const double doneMb = bytesDone / 1024.0 / 1024.0;
    const double totalMb = bytesTotal / 1024.0 / 1024.0;
    const int percent = bytesTotal == 0 ? 100 : static_cast<int>((bytesDone * 100) / bytesTotal);
    QString message = QObject::tr("%1 %2: %3% (%4/%5 MB)")
        .arg(action, fileName)
        .arg(percent)
        .arg(QString::number(doneMb, 'f', 2), QString::number(totalMb, 'f', 2));
    if (!details.isEmpty()) {
        message += "\n" + details;
    }
    return message;
}

QString formatDuration(qint64 seconds)
{
    if (seconds < 0) {
        return QObject::tr("calculating");
    }

    const qint64 minutes = seconds / 60;
    const qint64 remainingSeconds = seconds % 60;
    if (minutes > 0) {
        return QObject::tr("%1 min %2 sec").arg(minutes).arg(remainingSeconds);
    }
    return QObject::tr("%1 sec").arg(remainingSeconds);
}

const char* icon_file_for_connection_state(AppConnectionState state)
{
#if defined(Q_OS_MAC)
    switch (state) {
        default:
        case AppConnectionState::DISCONNECTED: return ":/res/icons/128x128/input-leap-disconnected-mask.png";
        case AppConnectionState::CONNECTING:   return ":/res/icons/128x128/input-leap-disconnected-mask.png";
        case AppConnectionState::CONNECTED:    return ":/res/icons/128x128/input-leap-connected-mask.png";
        case AppConnectionState::TRANSFERRING: return ":/res/icons/128x128/input-leap-transfering-mask.png";
    }
#else
    switch (state) {
        default:
        case AppConnectionState::DISCONNECTED: return ":/res/icons/128x128/input-leap-disconnected.png";
        case AppConnectionState::CONNECTING:   return ":/res/icons/128x128/input-leap-disconnected.png";
        case AppConnectionState::CONNECTED:    return ":/res/icons/128x128/input-leap-connected.png";
        case AppConnectionState::TRANSFERRING: return ":/res/icons/128x128/input-leap-transfering.png";
    }
#endif
}

const char* icon_name_for_connection_state(AppConnectionState state)
{
    switch (state) {
        default:
        case AppConnectionState::DISCONNECTED: return "input-leap-disconnected";
        case AppConnectionState::CONNECTING: return "input-leap-disconnected";
        case AppConnectionState::CONNECTED: return "input-leap-connected";
        case AppConnectionState::TRANSFERRING: return "input-leap-transfering";
    }
}

static const char* APP_LARGE_ICON = ":/res/icons/256x256/input-leap.png";

void modernizeUtilityDialog(QDialog& dialog, QVBoxLayout& layout,
                            const QString& title, const QString& subtitle)
{
    dialog.setStyleSheet(
        "QDialog { background: #f5f7fa; }"
        "QFrame#utilityHeader { background: #0f172a; border-radius: 10px; }"
        "QLabel#utilityTitle { color: #f8fafc; font-size: 15px; font-weight: 700; }"
        "QLabel#utilitySubtitle { color: #94a3b8; }"
        "QTableWidget { background: #ffffff; alternate-background-color: #f8fafc; border: 1px solid #d5deea; border-radius: 8px; gridline-color: #e2e8f0; selection-background-color: #dbeafe; selection-color: #1e3a8a; }"
        "QHeaderView::section { background: #eef2f7; color: #334155; border: none; border-bottom: 1px solid #cbd5e1; padding: 8px; font-weight: 700; }"
        "QLineEdit, QComboBox { background: #ffffff; border: 1px solid #94a3b8; border-radius: 6px; padding: 7px 9px; min-height: 22px; }"
        "QLineEdit:focus, QComboBox:focus { border-color: #2563eb; }"
        "QPushButton { background: #ffffff; color: #334155; border: 1px solid #aab4c3; border-radius: 6px; padding: 8px 15px; font-weight: 600; }"
        "QPushButton:hover { background: #eef4ff; border-color: #7aa2e3; }"
        "QPushButton:default { background: #2563eb; color: #ffffff; border-color: #2563eb; }"
    );
    auto* header = new QFrame(&dialog);
    header->setObjectName("utilityHeader");
    auto* headerLayout = new QVBoxLayout(header);
    headerLayout->setContentsMargins(16, 11, 16, 11);
    headerLayout->setSpacing(2);
    auto* titleLabel = new QLabel(title, header);
    titleLabel->setObjectName("utilityTitle");
    auto* subtitleLabel = new QLabel(subtitle, header);
    subtitleLabel->setObjectName("utilitySubtitle");
    subtitleLabel->setWordWrap(true);
    headerLayout->addWidget(titleLabel);
    headerLayout->addWidget(subtitleLabel);
    layout.insertWidget(0, header);
}

class CompactUpdateDialog final : public QDialog
{
public:
    using QDialog::QDialog;
    QSize minimumSizeHint() const override { return QSize(1, 1); }
};

} // namespace

MainWindow::MainWindow(QSettings& settings, AppConfig& appConfig,
                       bool enableSystemIpc,
                       std::function<void()> serviceStopOverride,
                       std::optional<quint16> fileTransferPortOverride,
                       std::optional<quint16> ipcPortOverride) :
    ui_{std::make_unique<Ui::MainWindow>()},
    m_Settings(settings),
    m_AppConfig(&appConfig),
    cmd_app_process_(nullptr),
    m_DeviceRegistry(settings, {}, DeviceRegistry::PersistenceMode::ReadOnly),
    m_LocalDeviceUuid(LocalDeviceIdentity::loadExisting(m_Settings).uuid),
    m_CoreConnectionStateController(m_DeviceRegistry, m_DeviceConnectionModel),
    m_ServerConfig(&m_Settings, 5, 3, m_AppConfig->screenName(), this),
    m_EnvironmentProfileStore(
        m_Settings, {},
        [&appConfig](QByteArrayView payload, bool createKey)
            -> std::optional<QByteArray> {
            const QString account = QStringLiteral(
                "InputLeap/environment-profiles/auth-key");
            auto key = createKey
                ? RecoveryArtifactAuthenticator::loadOrCreateKey(
                      appConfig.m_CredentialStore, account)
                : RecoveryArtifactAuthenticator::loadKey(
                      appConfig.m_CredentialStore, account);
            if (!key) return std::nullopt;
            const QByteArray domain = QByteArrayLiteral(
                "inputleap-environment-profile-manifest-v2");
            const QByteArray mac = RecoveryArtifactAuthenticator::authenticate(
                key->bytes(), QByteArrayView(domain), {payload});
            return mac.isEmpty() ? std::nullopt
                                 : std::optional<QByteArray>(mac);
        },
        [&appConfig] {
            return RecoveryArtifactAuthenticator::loadKey(
                appConfig.m_CredentialStore,
                QStringLiteral("InputLeap/environment-profiles/auth-key"))
                .has_value();
        }),
    m_EnvironmentProfileController(
        m_EnvironmentProfileStore, m_ServerConfig, m_DeviceRegistry,
        [this] { return m_LocalDeviceUuid; },
        [this] { return environmentProfileBusy(); },
        [this] { return ui_ && ui_->m_pRadioExternalConfig->isChecked(); }),
    m_pTempConfigFile(nullptr),
    m_TempConfigFileFactory([] { return new QTemporaryFile(); }),
    m_pTrayIcon(nullptr),
    m_pTrayIconMenu(nullptr),
    m_AlreadyHidden(false),
    m_IpcClient(ipcPortOverride.value_or(IPC_PORT)),
    m_SystemIpcEnabled(enableSystemIpc),
    m_ServiceStopOverride(std::move(serviceStopOverride)),
    m_pMenuBar(nullptr),
    main_menu_(nullptr),
    m_pMenuHelp(nullptr),
    m_pActionSendFiles(nullptr),
    m_pActionSendFolder(nullptr),
    m_pActionSendClipboardImage(nullptr),
    m_pActionSendQuickText(nullptr),
    m_pActionSendTestFile(nullptr),
    m_pActionTransferHistory(nullptr),
    m_pActionRecentReceivedFiles(nullptr),
    m_pActionTransferQueue(nullptr),
    m_pActionOpenReceiveFolder(nullptr),
    m_pActionDiagnostics(nullptr),
    m_pActionClipboardHistory(nullptr),
    m_pActionReleaseNotes(nullptr),
    m_pActionCheckUpdates(nullptr),
    m_pUpdateNetwork(nullptr),
    m_pUpdateService(nullptr),
    m_pZeroconfService(nullptr),
    m_pDataDownloader(nullptr),
    m_DownloadMessageBox(nullptr),
    m_pCancelButton(nullptr),
    m_SuppressAutoConfigWarning(false),
    m_BonjourInstall(nullptr),
    m_SuppressEmptyServerWarning(false),
    m_ExpectedRunningState(kStopped),
    m_pSslCertificate(nullptr),
    m_pFileTransferService(new FileTransferService(this)),
    m_FileTransferDestinationHosts(m_Settings.value("fileTransferDestinationHosts").toStringList()),
    m_pLogWindow(new LogWindow(nullptr))
{
    // explicitly unset DeleteOnClose
    // repeatedly until InputLeap is finished
    setAttribute(Qt::WA_DeleteOnClose, false);
    // mark the windows as sort of "dialog" window so that tiling window
    // managers will float it by default (X11)
    setAttribute(Qt::WA_X11NetWmWindowTypeDialog, true);

    ui_->setupUi(this);
    connect(&m_EnvironmentProfileController,
            &EnvironmentProfileController::authorizationInvalidated,
            this, &MainWindow::handleRuntimeInvalidation);
    loadSettings();
    if (m_LocalDeviceUuid.isNull() &&
        m_EnvironmentProfileStore.loadStatus() == EnvironmentProfileStore::LoadStatus::Missing) {
        const auto localIdentity = LocalDeviceIdentity::loadOrCreate(m_Settings);
        if (localIdentity.ok)
            m_LocalDeviceUuid = localIdentity.uuid;
    }
    m_EnvironmentProfilesInitialized = m_EnvironmentProfileController.initialize();
    ConfigurationAppTarget::PendingRecoveryResult importRecovery =
        ConfigurationAppTarget::PendingRecoveryResult::NotNeeded;
    if (m_EnvironmentProfilesInitialized) {
        ConfigurationAppTarget recoveryTarget(*m_AppConfig,
                                               m_EnvironmentProfileController);
        importRecovery = recoveryTarget.recoverPendingImport();
        if (importRecovery == ConfigurationAppTarget::PendingRecoveryResult::Blocked) {
            m_EnvironmentProfilesInitialized = false;
            m_EnvironmentProfileController.invalidate();
        }
        else if (importRecovery ==
                 ConfigurationAppTarget::PendingRecoveryResult::Recovered)
            loadSettings();
    }
    m_RuntimeConsumersEnabled = m_EnvironmentProfilesInitialized &&
        importRecovery != ConfigurationAppTarget::PendingRecoveryResult::Blocked;
    if (m_RuntimeConsumersEnabled && !m_DeviceRegistry.enablePersistence()) {
        m_RuntimeConsumersEnabled = false;
        m_EnvironmentProfilesInitialized = false;
        m_EnvironmentProfileController.invalidate();
        m_RuntimeBlockMessage = tr(
            "The device registry could not be promoted to writable storage. "
            "InputLeap was not started.");
    }
    if (importRecovery == ConfigurationAppTarget::PendingRecoveryResult::Blocked) {
        m_RuntimeBlockMessage = tr(
            "An interrupted configuration import could not be recovered safely. "
            "InputLeap will not be started.");
    }
    else if (!m_RuntimeConsumersEnabled && m_RuntimeBlockMessage.isEmpty()) {
        m_RuntimeBlockMessage = tr(
            "Startup blocked: the core stop was requested and confirmation is pending.");
    }
    m_ServerConfig.setPersistenceEnabled(m_RuntimeConsumersEnabled);

    if (m_RuntimeConsumersEnabled) {
        const auto localIdentity = LocalDeviceIdentity::loadOrCreate(m_Settings);
        if (localIdentity.ok) m_LocalDeviceUuid = localIdentity.uuid;
    }
    if (!m_LocalDeviceUuid.isNull()) {
        QtLocalScreenSource source;
        const auto localMonitors=LocalMonitorCollector::collect(source);
        if(localMonitors.ok){auto layout=m_ServerConfig.screenLayout();if(layout.bindLocalDevice(m_LocalDeviceUuid,m_AppConfig->screenName(),localMonitors.monitors))m_ServerConfig.setScreenLayout(layout);}
    }
    m_DiscoveredDevicesModel = std::make_unique<DiscoveredDevicesModel>(
        m_DeviceRegistry, m_DeviceConnectionModel, m_LocalDeviceUuid, this);
    m_ClipboardHistoryModel = std::make_unique<ClipboardHistoryModel>(this);
    auto* localClipboard = QGuiApplication::clipboard();
    connect(localClipboard, &QClipboard::dataChanged, this, [this, localClipboard] {
        if (!m_RuntimeConsumersEnabled)
            return;
        if (const QMimeData* mime = localClipboard->mimeData()) {
            if (!deviceAllows(m_DashboardDeviceUuid, DevicePermissions::ShareClipboard, tr("compartilhar área de transferência")))
                return;
            // Qt does not expose a reliable password-field signal here. Fail closed;

            ClipboardProtectionPolicy::Metadata metadata;
            m_ClipboardHistoryModel->addProtectedMimeData(*mime, metadata);
        }
    });
    auto* clipboardExpiryTimer = new QTimer(this);
    clipboardExpiryTimer->setInterval(60 * 1000);
    connect(clipboardExpiryTimer, &QTimer::timeout,
            m_ClipboardHistoryModel.get(), &ClipboardHistoryModel::expire);
    clipboardExpiryTimer->start();
    const QString queueDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    m_TransferQueue = std::make_unique<TransferQueue>(QDir(queueDir).filePath(QStringLiteral("transfer-queue-v1.json")));
    if (m_RuntimeConsumersEnabled) {
        QString queueLoadError;
        const auto queueLoad = m_TransferQueue->load(&queueLoadError);
        if (queueLoad == TransferQueue::LoadResult::Corrupt ||
            queueLoad == TransferQueue::LoadResult::Unsupported)
            appendLogError(tr("A fila persistente não pôde ser carregada: %1").arg(queueLoadError));
    }
    else {
        m_TransferQueue->disablePersistence();
    }
    connect(m_DiscoveredDevicesModel.get(),&DiscoveredDevicesModel::devicesChanged,this,[this]{refreshTransferQueueDialog();dispatchNextTransfer();});
    QTimer::singleShot(0,this,&MainWindow::dispatchNextTransfer);
    m_ReconnectTimer = new QTimer(this); m_ReconnectTimer->setSingleShot(true);
    m_ReconnectCountdownTimer = new QTimer(this); m_ReconnectCountdownTimer->setInterval(250);
    m_ReconnectStableTimer = new QTimer(this); m_ReconnectStableTimer->setSingleShot(true);
    m_ReconnectionPolicy = std::make_unique<ReconnectionPolicy>(
        [] { return QDateTime::currentMSecsSinceEpoch(); },
        [](int delay, int percent) { const int spread=delay*percent/100; return delay+QRandomGenerator::global()->bounded(-spread,spread+1); },
        [this](int delay, quint64 generation) { m_ReconnectTimerGeneration=generation; m_ReconnectDeadlineMs=QDateTime::currentMSecsSinceEpoch()+delay; m_ReconnectTimer->start(delay); m_ReconnectCountdownTimer->start(); updateReconnectCountdown(); },
        [this] { m_ReconnectTimer->stop(); m_ReconnectCountdownTimer->stop(); },
        [this](const QUuid& uuid)->std::optional<QString> {
            const auto device=m_DiscoveredDevicesModel->find(uuid);
            if(!device||!device->discoveryAvailable||!device->compatible||device->role!=ZeroconfRole::Server||!device->controlPort)return std::nullopt;
            const QString endpoint = EndpointPolicy::firstUsable(device->addresses.values());
            if(endpoint.isEmpty())return std::nullopt;m_AppConfig->setPort(device->controlPort);return endpoint;
        },
        [this](const QString& endpoint){return performReconnectAttempt(endpoint);},
        [this](ReconnectionPolicy::Notice notice){
            if (!m_NotificationService)
                return;
            if (notice == ReconnectionPolicy::Notice::FirstFailure) {
                m_NotificationService->publish(
                    QStringLiteral("reconnection-failure"), tr("Conexão"),
                    tr("Conexão perdida; a reconexão automática foi iniciada."));
            }
            else if (notice == ReconnectionPolicy::Notice::Recovery) {
                m_NotificationService->publish(
                    QStringLiteral("reconnection-recovery"), tr("Conexão"),
                    tr("Conexão recuperada e estável."));
            }
            else if (notice == ReconnectionPolicy::Notice::Terminal ||
                     notice == ReconnectionPolicy::Notice::Exhausted) {
                const QString guidance = tr("Verifique o outro computador e clique em Iniciar novamente.");
                m_NotificationService->publish(
                    notice == ReconnectionPolicy::Notice::Terminal
                        ? QStringLiteral("reconnection-terminal")
                        : QStringLiteral("reconnection-exhausted"),
                    tr("Reconexão"), guidance, NotificationService::Severity::Warning);
            }
            else if (notice == ReconnectionPolicy::Notice::DelayTierChanged) {
                appendLogDebug(tr("Intervalo de reconexão aumentado."));
            }
        });
    connect(m_ReconnectTimer,&QTimer::timeout,this,[this]{m_ReconnectCountdownTimer->stop();m_ReconnectionPolicy->timerFired(m_ReconnectTimerGeneration);});
    connect(m_ReconnectCountdownTimer,&QTimer::timeout,this,&MainWindow::updateReconnectCountdown);
    connect(m_ReconnectStableTimer,&QTimer::timeout,this,[this]{m_ReconnectionPolicy->confirmStable();});
    m_NetworkRecoveryCoordinator = std::make_unique<NetworkRecoveryCoordinator>(
        [this] {
            NetworkRecoveryPolicy::Context c;
            c.role = app_role()==AppRole::Server ? NetworkRecoveryPolicy::Role::Server : NetworkRecoveryPolicy::Role::Client;
            c.serviceOwned = m_AppConfig->processMode()==Service;
            c.userIntendedStarted = m_ExpectedRunningState==kStarted;
            c.stablyConnected = connection_state_==AppConnectionState::CONNECTED || connection_state_==AppConnectionState::TRANSFERRING;
            c.transferActive = m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers();
            return c;
        },
        [this]{ updateZeroconfService(); },
        [this]{ if(!m_ReconnectionPolicy->active())beginReconnectionIntent();scheduleReconnectFailure(ReconnectionPolicy::Failure::DnsStale); },
        [this]{ const QString text=tr("Rede restabelecida; procurando o outro computador…");setStatus(text);if(m_pDashboardDetail){m_pDashboardDetail->setText(text);m_pDashboardDetail->setAccessibleName(text);} },
        [this]{ m_ReconnectionPolicy->pause(); },
        [this]{ m_ReconnectionPolicy->resume(false); },
        [this]{ m_ReconnectionPolicy->resetBudget(); }, this);
    connect(m_DiscoveredDevicesModel.get(), &DiscoveredDevicesModel::devicesChanged,
            this, &MainWindow::rebuildTrayMenu);
    setWindowIcon(QIcon(APP_LARGE_ICON));
    polishMainView();
    ensureAccessibleNames(this);
    m_NotificationService = std::make_unique<NotificationService>(
        [] { return QDateTime::currentMSecsSinceEpoch(); }, this);
    connect(m_NotificationService.get(), &NotificationService::notificationRaised,
            this, [this](const NotificationService::Event& event) {
        setStatus(event.message);
        if (m_pDashboardDetail) {
            m_pDashboardDetail->setText(event.message);
            m_pDashboardDetail->setAccessibleName(event.message);
        }
        appendLogInfo(event.message);
    });
    const UpdateTrustConfig updateTrust = UpdateTrustConfig::production();
    const QString updateStateDirectory = QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(updateStateDirectory);
    m_UpdateReplayStore = std::make_unique<UpdateReplayStore>(
        QDir(updateStateDirectory).filePath(QStringLiteral("secure-update-replay.ini")));
    m_pUpdateNetwork = new QNetworkAccessManager(this);
    m_pUpdateService = new UpdateService(m_pUpdateNetwork, updateTrust.trustedKeys,
                                         QStringLiteral(INPUTLEAP_VERSION), this,
                                         m_UpdateReplayStore.get(),
                                         updateTrust.minimumValidSignatures);
    m_UpdateStagingDirectory = QDir(updateStateDirectory)
        .filePath(QStringLiteral("update-staging"));
    m_UpdateDownloadService = std::make_unique<UpdateDownloadService>(
        m_pUpdateNetwork, m_UpdateStagingDirectory);
    connect(m_pUpdateService, &UpdateService::checkFinished,
            this, &MainWindow::handleUpdateCheckFinished);
    connect(m_UpdateDownloadService.get(), &UpdateDownloadService::progress,
            this, [this](qint64 received, qint64 total) {
        if (m_UpdateProgress) {
            m_UpdateProgress->setRange(0, 1000);
            m_UpdateProgress->setValue(total > 0
                ? int((received * 1000) / total) : 0);
            m_UpdateProgress->setAccessibleName(
                tr("Progresso do download da atualização: %1%").arg(
                    total > 0 ? int((received * 100) / total) : 0));
        }
    });
    connect(m_UpdateDownloadService.get(), &UpdateDownloadService::failed,
            this, [this](const QString&) {
        if (m_UpdateCancellationRequested) {
            m_UpdateCancellationRequested = false;
            return;
        }
        updateInstallationFailed(
            tr("Não foi possível baixar e verificar a atualização. Tente novamente."));
    });
    connect(m_UpdateDownloadService.get(), &UpdateDownloadService::ready,
            this, [this](const QString& path) {
        m_StagedUpdatePath = path;
        prepareUpdateInstallation();
    });
    createMenuBar();
    connect(ui_->m_pRadioExternalConfig, &QRadioButton::toggled,
            this, [this] { refreshEnvironmentProfileUi(); });
    refreshEnvironmentProfileUi();
    if (importRecovery == ConfigurationAppTarget::PendingRecoveryResult::Blocked) {
        m_RuntimeBlockMessage = tr(
            "An interrupted configuration import could not be recovered safely. "
            "InputLeap will not be started.");
        setStatus(m_RuntimeBlockMessage);
    }
    else if (importRecovery == ConfigurationAppTarget::PendingRecoveryResult::Recovered) {
        setStatus(tr("Previous configuration was restored after an interrupted import."));
    }
    else if (m_EnvironmentProfileController.recoveredOnInitialize()) {
        setStatus(tr("Previous profiles were restored after corrupted data was detected."));
    }

    if (!m_RuntimeConsumersEnabled)
        updateDashboardState(connection_state_);
    initConnections();
    updateZeroconfService();

    connect(&m_DeviceConnectionModel, &DeviceConnectionModel::deviceChanged,
            this, &MainWindow::updateDashboardFromDevice);
    connect(&m_DeviceConnectionModel, &DeviceConnectionModel::deviceRemoved,
            this, [this](const QUuid& uuid) {
                if (uuid == m_DashboardDeviceUuid) {
                    applyDashboardPeerPolicy();
                }
            });
    auto* dashboardExpiryTimer = new QTimer(this);
    dashboardExpiryTimer->setInterval(DASHBOARD_EXPIRY_CHECK_MS);
    connect(dashboardExpiryTimer, &QTimer::timeout, this, [this]() {
        m_DeviceConnectionModel.removeExpired(
            QDateTime::currentDateTimeUtc().addSecs(-DASHBOARD_DEVICE_TTL_SECONDS));
    });
    dashboardExpiryTimer->start();

    ui_->m_pLabelScreenName->setText(getScreenName());
    ui_->m_pLabelIpAddresses->setText(getIPAddresses());

#if defined(Q_OS_WIN)
    // ipc must always be enabled, so that we can disable command when switching to desktop mode.
    connect(&m_IpcClient, &IpcClient::readLogLine, this, &MainWindow::appendLogRaw);
    connect(&m_IpcClient, &IpcClient::readConnectionState,
            this, &MainWindow::handleCoreConnectionState);
    connect(&m_IpcClient, &IpcClient::errorMessage, this, &MainWindow::appendLogError);
    connect(&m_IpcClient, &IpcClient::infoMessage, this, &MainWindow::appendLogInfo);
    connect(&m_IpcClient, &IpcClient::connectionReady,
            this, &MainWindow::handleServiceReconnectReady);
    connect(&m_IpcClient, &IpcClient::startCommandApplied, this, [this] {
        if (m_ServiceStartPending) m_ServiceStartCommandApplied = true;
    });
    connect(&m_IpcClient, &IpcClient::transportUnavailable, this, [this] {
        if (!m_RuntimeConsumersEnabled) return;
        if (m_ServiceStopPending) {
            setStatus(tr("InputLeap stop was requested; confirmation is pending."));
            return;
        }
        if (m_ServiceStartPending) {
            const quint64 startGeneration = m_ServiceStartGeneration;
            handleServiceStartTimeout(startGeneration);
            setStatus(tr("The IPC connection was lost while InputLeap was starting. "
                         "A core stop was requested; confirmation is pending."));
            return;
        }
        set_connection_state(AppConnectionState::DISCONNECTED);
        setStatus(tr("InputLeap is not running."));
    });
    connect(&m_IpcClient, &IpcClient::commandApplied, this, [this] {
        if (m_ServiceStopPending) {
            const bool restartPending = m_ServiceRestartPending;
            ++m_ServiceStopGeneration;
            m_ServiceRestartPending = false;
            m_ServiceStopPending = false;
            m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
            refreshEnvironmentProfileUi();
            m_ServiceRestartAwaitingReconnect = restartPending && m_RuntimeConsumersEnabled;
            set_connection_state(AppConnectionState::DISCONNECTED);
            if (m_UpdateInstallAwaitingStop) {
                m_UpdateCoreStoppedForInstall = true;
                m_ServiceRestartAwaitingReconnect = false;
                continueUpdateInstallationAfterStop();
            }
            if (m_ServiceRestartAwaitingReconnect) {
                if (m_ServiceReconnectOverride) m_ServiceReconnectOverride();
                else m_IpcClient.connectToHost();
            }
        }
        else if (m_ServiceStopUnconfirmed) {
            m_ServiceStopUnconfirmed = false;
            setStatus(tr("InputLeap is not running."));
        }
        if (m_RuntimeConsumersEnabled || m_RuntimeBlockMessage.isEmpty()) return;
        m_RuntimeBlockMessage = tr(
            "Startup blocked: persistent configuration became unavailable. "
            "The core stop was confirmed.");
        setStatus(m_RuntimeBlockMessage);
    });
    if (m_SystemIpcEnabled)
        m_IpcClient.connectToHost();
    if (!m_RuntimeConsumersEnabled) {
        m_ServiceStopUnconfirmed = false;
        m_ServiceStopPending = true;
        const quint64 stopGeneration = ++m_ServiceStopGeneration;
        requestServiceStopAndDisconnect();
        QTimer::singleShot(kServiceStopConfirmationTimeoutMs, this, [this, stopGeneration] {
            handleServiceStopTimeout(stopGeneration);
        });
        setStatus(m_RuntimeBlockMessage);
    }
#endif

    // change default size based on os
#if defined(Q_OS_MAC)
    resize(720, 550);
    setMinimumSize(720, 0);
#elif defined(Q_OS_LINUX)
    resize(700, 530);
    setMinimumSize(700, 0);
#endif

    m_SuppressAutoConfigWarning = true;
    ui_->m_pCheckBoxAutoConfig->setChecked(appConfig.autoConfig());
    m_SuppressAutoConfigWarning = false;

    ui_->m_pComboServerList->hide();
    ui_->m_pLabelPadlock->hide();
    ui_->m_pLabelPadlock->setPixmap(QPixmap(":/res/icons/64x64/padlock.png").scaledToHeight(fontMetrics().height() * 1.5, Qt::SmoothTransformation));
    ui_->frame_fingerprint_details->hide();

    updateSSLFingerprint();

    QString fileTransferError;
    m_pFileTransferService->setReceiveDirectory(appConfig.receiveDirectory());
    m_pFileTransferService->setPairingCode(appConfig.fileTransferPairingCode());
    m_pFileTransferService->setReceivePermissionCallback([this](const QUuid& peerUuid) {
        return !m_UpdateTransferBarrierActive &&
            deviceAllows(peerUuid, DevicePermissions::ReceiveFiles, tr("receber arquivos"));
    });
    m_pFileTransferService->setIncomingFileCallback([this](const QString& fileName, quint64 bytesTotal, const QString& peerAddress, const QUuid& peerUuid) {
            if (m_UpdateTransferBarrierActive) return false;
            if (!deviceAllows(peerUuid, DevicePermissions::ReceiveFiles, tr("receber arquivos"))) {
                appendLogError(tr("Transferência recebida bloqueada: permissão não concedida."));
                return false;
            }
            const QString peer = peerAddress.isEmpty() ? tr("unknown computer") : peerAddress;
        const QString message = tr("Receiving %1 (%2 MB) from %3.")
            .arg(fileName, QString::number(bytesTotal / 1024.0 / 1024.0, 'f', 2), peer);
        appendLogInfo(tr("incoming file transfer accepted automatically: %1 from %2").arg(fileName, peer));
        if (m_pTrayIcon != nullptr && m_pTrayIcon->isVisible()) {
            m_pTrayIcon->showMessage(tr("Incoming file transfer"), message, QSystemTrayIcon::Information, 8000);
        }
        return true;
    });
    m_pFileTransferService->setConflictCallback([this](const ConflictRequest& request) {
        QMessageBox box(QMessageBox::Question,tr("Arquivo já existe"),
            tr("O arquivo “%1” já existe na pasta de destino. O que deseja fazer?").arg(request.fileName),
            QMessageBox::NoButton,this);
        auto* replace=box.addButton(tr("Substituir"),QMessageBox::DestructiveRole);
        auto* rename=box.addButton(tr("Renomear"),QMessageBox::AcceptRole);
        auto* skip=box.addButton(tr("Ignorar"),QMessageBox::RejectRole);
        auto* applyAll=new QCheckBox(tr("Aplicar a todos neste lote"),&box);
        box.setCheckBox(applyAll);
        box.setDefaultButton(qobject_cast<QPushButton*>(rename));
        box.exec();
        ConflictAction action=ConflictAction::Rename;
        if(box.clickedButton()==replace)action=ConflictAction::Replace;
        else if(box.clickedButton()==skip)action=ConflictAction::Skip;
        return ConflictDecision{action,applyAll->isChecked()};
    });
    if (m_RuntimeConsumersEnabled &&
        !m_pFileTransferService->startListening(
            fileTransferPortOverride.value_or(FILE_TRANSFER_PORT), &fileTransferError)) {
        appendLogError(tr("file transfer receiver failed to start: %1").arg(fileTransferError));
    }
    else if (m_RuntimeConsumersEnabled) {
        connect(m_pFileTransferService, &FileTransferService::info, this, &MainWindow::appendLogInfo);
        connect(m_pFileTransferService, &FileTransferService::error, this, &MainWindow::appendLogError);
        connect(m_pFileTransferService, &FileTransferService::receivingStarted, this, [this](const QString& fileName, quint64 bytesTotal) {
            if (!m_RuntimeConsumersEnabled) return;
            m_FileTransferReceiveBusy = true;
            refreshEnvironmentProfileUi();
            m_ReceivedFileNotificationOpenable = false;
            m_pDashboardTransfer->setText(tr("Recebendo %1").arg(fileName));
            m_pDashboardTransferProgress->setValue(0);
            const QString message = tr("Receiving %1 (%2 MB)...")
                .arg(fileName, QString::number(bytesTotal / 1024.0 / 1024.0, 'f', 2));
            setStatus(message);
            appendLogInfo(message);
            if (m_pTrayIcon != nullptr && m_pTrayIcon->isVisible()) {
                m_pTrayIcon->showMessage(tr("InputLeap file transfer"), message, QSystemTrayIcon::Information, 4000);
            }
        });
        connect(m_pFileTransferService, &FileTransferService::receivingProgress, this, [this](const QString& fileName, quint64 bytesDone, quint64 bytesTotal) {
            if (!m_RuntimeConsumersEnabled) return;
            const QString message = formatTransferProgress(tr("Receiving"), fileName, bytesDone, bytesTotal);
            m_pDashboardTransfer->setText(tr("Recebendo %1").arg(fileName));
            m_pDashboardTransferProgress->setValue(bytesTotal == 0 ? 100 : static_cast<int>((bytesDone * 100) / bytesTotal));
            setStatus(message);
            appendLogInfo(message);
        });
        connect(m_pFileTransferService, &FileTransferService::publicationCompleted, this,
                [this](const QString& fileName, const FileTransferService::PublicationOutcome& outcome) {
            if (!m_RuntimeConsumersEnabled) return;
            Q_UNUSED(fileName);
            if(!outcome.transferId.isEmpty())m_PendingPublicationOutcomes.insert(outcome.transferId,outcome);
        });
        connect(m_pFileTransferService, &FileTransferService::fileRejected, this,
                [this](const QString& fileName,const QString& peerAddress,const QByteArray& transferId) {
            if (!m_RuntimeConsumersEnabled) return;
            m_FileTransferReceiveBusy = false;
            refreshEnvironmentProfileUi();
            if(!transferId.isEmpty()&&m_PendingPublicationOutcomes.contains(transferId)){
                const auto outcome=m_PendingPublicationOutcomes.take(transferId);
                const bool recoveryRequired=outcome.status==FileTransferService::PublicationStatus::RecoveryRequired;
                const bool reviewRequired=outcome.status==FileTransferService::PublicationStatus::ReviewRequired;
                const QString reason=recoveryRequired
                    ? tr("falha ao publicar; o original foi preservado para recuperação em %1").arg(outcome.recoveryPath)
                    : reviewRequired
                    ? tr("uma publicação anterior ficou indeterminada; verifique manualmente %1").arg(outcome.destinationPath)
                    : tr("a publicação não foi concluída; verifique o destino antes de tentar novamente");
                m_ReceivedFileNotificationOpenable=false;
                m_pDashboardTransfer->setText(recoveryRequired?tr("Recuperação necessária: %1").arg(fileName)
                                                               :reviewRequired?tr("Revisão necessária: %1").arg(fileName)
                                                               :tr("Recebimento não publicado: %1").arg(fileName));
                m_pDashboardTransferProgress->setValue(0);
                addTransferHistoryEntry(tr("Recebido"),fileName,
                                        outcome.peerUuid.toString(QUuid::WithoutBraces),reason,
                                        recoveryRequired?QFileInfo(outcome.recoveryPath).absolutePath()
                                                        :QFileInfo(outcome.destinationPath).absolutePath());
                const QString message=tr("Transferência recebida não publicada: %1.").arg(reason);
                setStatus(message);appendLogError(message);
                if((recoveryRequired||reviewRequired)&&m_pTrayIcon!=nullptr&&m_pTrayIcon->isVisible())
                    m_pTrayIcon->showMessage(recoveryRequired?tr("Recuperação de arquivo necessária")
                                                            :tr("Revisão de arquivo necessária"),message,
                                             QSystemTrayIcon::Warning,8000);
                return;
            }
            const QString reason = tr("permissão de recebimento não concedida");
            addTransferHistoryEntry(tr("Recebido"),fileName,peerAddress,
                                    tr("Rejeitado: %1").arg(reason),QString());
            const QString message = tr("Transferência recebida rejeitada: %1.").arg(reason);
            setStatus(message);
            appendLogInfo(message);
        });
        connect(m_pFileTransferService, &FileTransferService::fileReceived, this,
                [this](const QString& fileName,const QString& destinationPath,bool verified,
                       const QUuid& peerUuid,const QByteArray& transferId) {
            if (!m_RuntimeConsumersEnabled) return;
            const bool hasOutcome=!transferId.isEmpty()&&m_PendingPublicationOutcomes.contains(transferId);
            const auto outcome=hasOutcome?m_PendingPublicationOutcomes.take(transferId)
                                         :FileTransferService::PublicationOutcome{};
            if(!verified){
                m_FileTransferReceiveBusy=false;
                refreshEnvironmentProfileUi();
                m_LastReceivedFilesFolder.clear();
                m_ReceivedFileNotificationOpenable=false;
                m_pDashboardTransfer->setText(tr("Falha na verificação: %1").arg(fileName));
                m_pDashboardTransferProgress->setValue(0);
                const QString reason=tr("falha de verificação; nenhum arquivo foi publicado");
                addTransferHistoryEntry(tr("Recebido"),fileName,
                                        peerUuid.toString(QUuid::WithoutBraces),reason,QString());
                const QString message=tr("Transferência de %1 rejeitada: nenhum arquivo foi publicado.")
                    .arg(fileName);
                setStatus(message);appendLogError(message);return;
            }
            const bool committedOutcome=hasOutcome&&
                (outcome.status==FileTransferService::PublicationStatus::Committed||
                 outcome.status==FileTransferService::PublicationStatus::CommittedWithRecovery)&&
                outcome.transferId==transferId&&outcome.peerUuid==peerUuid&&
                QDir::cleanPath(outcome.destinationPath)==QDir::cleanPath(destinationPath);
            if(verified&&!committedOutcome){
                m_FileTransferReceiveBusy=false;
                refreshEnvironmentProfileUi();
                m_ReceivedFileNotificationOpenable=false;
                m_pDashboardTransfer->setText(tr("Recebimento não confirmado: %1").arg(fileName));
                m_pDashboardTransferProgress->setValue(0);
                const QString reason=tr("resultado de publicação ausente ou incompatível");
                const QString peer=peerUuid.toString(QUuid::WithoutBraces);
                addTransferHistoryEntry(tr("Recebido"),fileName,peer,reason,QString());
                const QString message=tr("Transferência recebida não confirmada: %1.").arg(reason);
                setStatus(message);appendLogError(message);return;
            }
            const bool recoveryPreserved=committedOutcome&&
                outcome.status==FileTransferService::PublicationStatus::CommittedWithRecovery;
            m_FileTransferReceiveBusy = false;
            refreshEnvironmentProfileUi();
            m_LastReceivedFilesFolder = QFileInfo(destinationPath).absolutePath();
            m_ReceivedFileNotificationOpenable = verified&&committedOutcome;
            m_pDashboardTransfer->setText(verified ? tr("Recebido e verificado: %1").arg(fileName)
                                                    : tr("Falha na verificação: %1").arg(fileName));
            m_pDashboardTransferProgress->setValue(100);
            const QString historyStatus=recoveryPreserved
                ? tr("Verificado; original preservado em %1").arg(outcome.recoveryPath)
                : (verified?tr("Verified"):tr("Verification failed"));
            addTransferHistoryEntry(tr("Received"),fileName,
                                    peerUuid.toString(QUuid::WithoutBraces),historyStatus,
                                    m_LastReceivedFilesFolder);
            const QString message = recoveryPreserved
                ? tr("Received %1 in %2. SHA-256 verified; the previous file is preserved in %3.")
                      .arg(fileName,m_LastReceivedFilesFolder,outcome.recoveryPath)
                : verified
                ? tr("Received %1 in %2. SHA-256 verified.").arg(fileName, m_LastReceivedFilesFolder)
                : tr("Received %1 in %2, but SHA-256 verification failed.").arg(fileName, m_LastReceivedFilesFolder);
            setStatus(message);
            recoveryPreserved?appendLogError(message):appendLogInfo(message);
            QTimer::singleShot(0, this, [this, fileName, destinationPath, message, verified, peerUuid]() {
                if (!m_RuntimeConsumersEnabled) return;
                showReceivedFileNotification(fileName, destinationPath, message, verified, peerUuid);
            });
        });
    }


    connect(ui_->toolbutton_show_fingerprint, &QToolButton::clicked, this, [this](bool checked)
    {
        (void) checked;

        m_fingerprint_expanded = !m_fingerprint_expanded;
        if (m_fingerprint_expanded) {
            ui_->frame_fingerprint_details->show();
            ui_->toolbutton_show_fingerprint->setArrowType(Qt::ArrowType::UpArrow);
        } else {
            ui_->frame_fingerprint_details->hide();
            ui_->toolbutton_show_fingerprint->setArrowType(Qt::ArrowType::DownArrow);
        }
    });

    consumePendingUpdateResult();
}

MainWindow::~MainWindow()
{
    releaseUpdateInstallMutex(m_UpdateInstallMutex);
    delete m_pUpdateService;
    m_pUpdateService = nullptr;
    m_TransferQueueShuttingDown = true;
    if (m_RuntimeConsumersEnabled && m_TransferQueue) {
        m_TransferQueue->save();
    }
    for (auto it = m_TransferControllers.begin(); it != m_TransferControllers.end(); ++it) {
        m_TransferCancelIntents[it.key()] = TransferCancelIntent::Shutdown;
        if (it.value()) it.value()->cancel();
    }
    for (auto it=m_PairedSessions.begin();it!=m_PairedSessions.end();++it) if(!it->key.isEmpty()){it->key.detach();OPENSSL_cleanse(it->key.data(),size_t(it->key.size()));}
    m_PairedSessions.clear();
    if (appConfig().processMode() == Desktop) {
        m_ExpectedRunningState = kStopped;
        stopDesktop();
    }

    if (m_RuntimeConsumersEnabled)
        saveSettings();

    delete m_pZeroconfService;
    delete m_DownloadMessageBox;
    delete m_BonjourInstall;
    delete m_pSslCertificate;

    // LogWindow is created as a sibling of the MainWindow rather than a child
    // so that the main window can be hidden without hiding the log. because of
    // this it does not get properly cleaned up by the QObject system. also by
    // the time this destructor is called the event loop will no longer be able
    // to clean up the LogWindow so ->deleteLater() will not work
    delete m_pLogWindow;
}

quint16 MainWindow::controlPort() const
{
    return static_cast<quint16>(m_AppConfig->port());
}

quint16 MainWindow::pairingPort() const
{
    return m_ActivePairingWizard ? m_ActivePairingWizard->pairingPort() : 0;
}

void MainWindow::polishMainView()
{
    auto* content = takeCentralWidget();
    auto* viewport = new QScrollArea(this);
    viewport->setObjectName("mainViewport");
    viewport->setWidgetResizable(true);
    viewport->setFrameShape(QFrame::NoFrame);
    viewport->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    viewport->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    content->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    content->layout()->setSizeConstraint(QLayout::SetDefaultConstraint);
    viewport->setWidget(content);
    setCentralWidget(viewport);

    QSize available(880, 760);
    if (const auto* screen = QGuiApplication::primaryScreen())
        available = screen->availableGeometry().size() - QSize(32, 32);
    available.setWidth(std::max(320, available.width()));
    available.setHeight(std::max(320, available.height()));
    const QSize initial(std::min(880, available.width()),
                        std::min(760, available.height()));
    setMinimumSize(std::min(640, initial.width()),
                   std::min(480, initial.height()));
    resize(initial);
    ui_->centralwidget->layout()->setContentsMargins(18, 14, 18, 16);
    ui_->centralwidget->layout()->setSpacing(14);

    auto* root_layout = qobject_cast<QVBoxLayout*>(ui_->centralwidget->layout());
    if (root_layout != nullptr) {
        auto* dashboard = new QFrame(ui_->centralwidget);
        dashboard->setObjectName("dashboardCard");
        auto* dashboardLayout = new QVBoxLayout(dashboard);
        dashboardLayout->setContentsMargins(20, 18, 20, 18);
        dashboardLayout->setSpacing(14);

        auto* statusRow = new QHBoxLayout();
        auto* statusText = new QVBoxLayout();
        m_pDashboardState = new QLabel(tr("Pronto para conectar"), dashboard);
        m_pDashboardState->setObjectName("dashboardState");
        m_pDashboardDetail = new QLabel(tr("Escolha um modo e inicie o InputLeap."), dashboard);
        m_pDashboardDetail->setObjectName("dashboardDetail");
        statusText->addWidget(m_pDashboardState);
        statusText->addWidget(m_pDashboardDetail);
        statusRow->addLayout(statusText, 1);
        m_pSecurityBadge = new QLabel(ProtectionPanel::badgeLabel({}), dashboard);
        m_pSecurityBadge->setObjectName("securityBadge");
        m_pSecurityBadge->setAccessibleName(tr("Estado da proteção"));
        statusRow->addWidget(m_pSecurityBadge, 0, Qt::AlignTop);
        dashboardLayout->addLayout(statusRow);

        m_EnvironmentProfileSelector = new EnvironmentProfileSelector(dashboard);
        m_EnvironmentProfileUiBinding = std::make_unique<EnvironmentProfileUiBinding>(
            *m_EnvironmentProfileSelector, m_EnvironmentProfileController,
            [this](const QString& text) {
                return QMessageBox::question(this, tr("Perfis de ambiente"), text,
                    QMessageBox::Save | QMessageBox::Cancel,
                    QMessageBox::Cancel) == QMessageBox::Save;
            },
            [this](const QString& title, const QString& message, bool warning) {
                setStatus(message);
                if (warning) QMessageBox::warning(this, title, message);
                else QMessageBox::information(this, title, message);
            });
        connect(m_EnvironmentProfileUiBinding.get(), &EnvironmentProfileUiBinding::operationFinished,
                this, [this] { refreshEnvironmentProfileUi(); });
        dashboardLayout->addWidget(m_EnvironmentProfileSelector);

        auto* protectionPanel = new ProtectionPanel(m_DeviceRegistry, dashboard);
        m_ProtectionPanel = protectionPanel;
        protectionPanel->setConfigureHandler([this] {
            if (m_DeviceDiscoveryPanel) m_DeviceDiscoveryPanel->setFocus();
            setStatus(tr("Escolha um computador e use Parear para configurar a proteção."));
        });
        protectionPanel->setRevokeHandler([this](const QUuid& uuid) {
            // DeviceRegistry::remove is the only fallible step.  Commit it
            // before destroying the in-memory credentials so a persistence
            // failure cannot leave a half-revoked device.
            if (!m_DeviceRegistry.remove(uuid)) {
                updateProtectionFacts();
                return false;
            }
            auto session = m_PairedSessions.find(uuid);
            if (session != m_PairedSessions.end()) {
                session->key.detach();
                OPENSSL_cleanse(session->key.data(), size_t(session->key.size()));
                m_PairedSessions.erase(session);
            }
            if (m_pFileTransferService) m_pFileTransferService->removeDevicePreSharedKey(uuid);
            if (uuid == m_DashboardDeviceUuid) {
                m_DashboardDeviceUuid = {};
                set_connection_state(AppConnectionState::DISCONNECTED);
            }
            updateProtectionFacts();
            return true;
        });
        dashboardLayout->addWidget(protectionPanel);

        auto* devices = new QHBoxLayout();
        devices->setSpacing(8);

        auto makeDevice = [dashboard](const QString& objectName, const QString& icon,
                                      const QString& title, const QString& detail) {
            auto* card = new QFrame(dashboard);
            card->setObjectName(objectName);
            auto* layout = new QHBoxLayout(card);
            layout->setContentsMargins(10, 8, 10, 8);
            layout->setSpacing(8);
            auto* iconLabel = new QLabel(icon, card);
            iconLabel->setObjectName("deviceIcon");
            auto* textLayout = new QVBoxLayout();
            textLayout->setSpacing(1);
            auto* titleLabel = new QLabel(title, card);
            titleLabel->setObjectName("deviceTitle");
            auto* detailLabel = new QLabel(detail, card);
            detailLabel->setObjectName("deviceDetail");
            detailLabel->setWordWrap(true);
            layout->addWidget(iconLabel);
            textLayout->addWidget(titleLabel);
            textLayout->addWidget(detailLabel);
            layout->addLayout(textLayout, 1);
            return card;
        };
        auto* localCard = makeDevice("localDeviceCard", "▣", tr("Este computador"), getScreenName());
        localCard->setMinimumWidth(190);
        auto* linkLabel = new QLabel("⟷", dashboard);
        linkLabel->setObjectName("deviceLink");
        m_DeviceDiscoveryPanel = new DeviceDiscoveryPanel(m_DiscoveredDevicesModel.get(), dashboard);
        m_DeviceDiscoveryPanel->setConnectionInitiationAllowed(app_role()!=AppRole::Server);
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::connectRequested, this,
                [this](const DiscoveredDeviceView& device) {
            const auto current = m_DiscoveredDevicesModel->find(device.uuid);
            if (app_role() == AppRole::Server || !current || !current->discoveryAvailable ||
                !current->compatible || current->role != ZeroconfRole::Server) {
                QMessageBox::information(this, tr("Conexão"),
                    tr("Este computador não inicia conexões neste modo."));
                return;
            }
            if (current->addresses.isEmpty() || current->controlPort == 0) {
                QMessageBox::warning(this, tr("Conexão"), tr("O computador não informou um endereço válido."));
                return;
            }
            const QString endpoint = EndpointPolicy::firstUsable(current->addresses.values());
            if (endpoint.isEmpty()) {
                QMessageBox::warning(this, tr("Conexão"),
                    tr("Nenhum endereço utilizável foi encontrado para este computador."));
                return;
            }
            m_ReconnectTargetUuid = current->uuid;
            m_AppConfig->setPort(current->controlPort);
            serverDetected(endpoint);
        });
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::pairRequested, this,
                [this](const DiscoveredDeviceView& requestedDevice) {
            if (!m_RuntimeConsumersEnabled) {
                setStatus(tr("O estado seguro de configuração não está disponível. O pareamento não foi iniciado."));
                return;
            }
            const auto currentDevice=m_DiscoveredDevicesModel->find(requestedDevice.uuid);
            if(!currentDevice || !currentDevice->discoveryAvailable ||
               !currentDevice->negotiation.capability(CapabilityId::Pairing).protocolCompatible()) {
                QMessageBox::information(this,tr("Atualização necessária"),
                    currentDevice ? currentDevice->negotiation.capability(CapabilityId::Pairing).reason
                                  : tr("O computador não está mais disponível."));
                return;
            }
            const auto device=*currentDevice;
            if (m_ActivePairingWizard) { m_ActivePairingWizard->raise(); return; }
            if (m_LocalDeviceUuid.isNull()) { QMessageBox::warning(this,tr("Pareamento"),tr("A identidade deste computador não pôde ser carregada.")); return; }
            const QString show=tr("Mostrar código neste computador");
            const QString enter=tr("Digitar código mostrado no outro");
            const QString manual=tr("Opção avançada: informar IP, porta e UUID");
            bool ok=false; const QString action=QInputDialog::getItem(this,tr("Parear computador"),
                tr("Escolha uma opção:"),QStringList{show,enter,manual},0,false,&ok); if(!ok)return;
            QHostAddress endpoint; quint16 port=device.pairingPort; QUuid inviter=device.uuid;
            if(action==show){
                m_ActivePairingWizard=new PairingWizard(m_LocalDeviceUuid,device.uuid,QHostAddress::Any,this);
                if(!m_ActivePairingWizard->pairingPort()){QMessageBox::warning(this,tr("Pareamento"),tr("Não foi possível abrir a porta de pareamento."));delete m_ActivePairingWizard;return;}
                updateZeroconfService();
            } else {
                struct PairingEndpoint { int rank; QString text; QHostAddress address; };
                QList<PairingEndpoint> usable;
                for(const QString& text:device.addresses){const QHostAddress address(text);if(address.isNull())continue;if(address.protocol()==QAbstractSocket::IPv4Protocol)usable.append({0,text,address});else if(address.protocol()==QAbstractSocket::IPv6Protocol){if(address.isLinkLocal()&&address.scopeId().isEmpty())continue;usable.append({address.isLinkLocal()?2:1,text,address});}}
                std::sort(usable.begin(),usable.end(),[](const auto& left,const auto& right){return left.rank==right.rank?left.text<right.text:left.rank<right.rank;});
                if(!usable.isEmpty())endpoint=usable.first().address;
                if(action==manual){
                    const QString host=QInputDialog::getText(this,tr("Ajustes avançados"),tr("Endereço IP:"),QLineEdit::Normal,endpoint.toString(),&ok).trimmed();if(!ok)return;endpoint=QHostAddress(host);
                    const int chosen=QInputDialog::getInt(this,tr("Ajustes avançados"),tr("Porta de pareamento (não use a porta de controle):"),port?port:1,1,65535,1,&ok);if(!ok)return;port=quint16(chosen);
                    const QString uuidText=QInputDialog::getText(this,tr("Ajustes avançados"),tr("UUID de quem mostra o código:"),QLineEdit::Normal,device.uuid.toString(QUuid::WithoutBraces),&ok).trimmed();if(!ok)return;inviter=QUuid(uuidText);
                }
                if(endpoint.isNull()||!port||inviter.isNull()){QMessageBox::warning(this,tr("Pareamento"),tr("Endereço, porta de pareamento ou UUID inválido."));return;}
                m_ActivePairingWizard=new PairingWizard(inviter,m_LocalDeviceUuid,endpoint,port,this);
            }
            auto* wizard=m_ActivePairingWizard.data(); wizard->setAttribute(Qt::WA_DeleteOnClose);
            wizard->setPeerSupportsDeviceMetadata(device.features.contains("monitor-metadata-v1") &&
                device.negotiation.capability(CapabilityId::Monitor).protocolCompatible());
            { QtLocalScreenSource source; const auto metadata=LocalMonitorCollector::collect(source); if(metadata.ok)wizard->setLocalDeviceMetadata(metadata.monitors); }
            connect(wizard,&PairingWizard::authenticatedDeviceMetadata,this,[this](const QUuid& remoteUuid,const std::vector<ScreenLayout::Monitor>& monitors){
                if(!m_RuntimeConsumersEnabled||remoteUuid.isNull())return;
                auto layout=m_ServerConfig.screenLayout();
                if(layout.updateMonitorsForDevice(remoteUuid,monitors))m_ServerConfig.setScreenLayout(layout);
            });
            connect(wizard,&PairingWizard::listenerReady,this,[this](quint16){if(m_RuntimeConsumersEnabled)updateZeroconfService();});
            connect(wizard,&PairingWizard::pairingCompleted,this,[this](const QUuid& peer,const QByteArray& key,const QString& alias){
                if(!m_RuntimeConsumersEnabled||peer.isNull()||key.size()!=32)return; auto old=m_PairedSessions.find(peer);if(old!=m_PairedSessions.end()&&!old->key.isEmpty()){old->key.detach();OPENSSL_cleanse(old->key.data(),size_t(old->key.size()));}QByteArray owned=key;owned.detach();m_PairedSessions.insert(peer,{owned});
                if(m_pFileTransferService)m_pFileTransferService->setDevicePreSharedKey(peer,key);
                if(!alias.isEmpty())m_DiscoveredDevicesModel->setLocalAlias(peer,alias);
                m_DiscoveredDevicesModel->setPairedThisSession(peer,true);
                m_DashboardDeviceUuid = peer;
                updateProtectionFacts();
                setStatus(tr("Pareado nesta sessão. A confiança ainda não foi salva permanentemente."));
                if (m_NotificationService)
                    m_NotificationService->publish(
                        QStringLiteral("pairing-completed"), tr("Pareamento"),
                        tr("Computador pareado nesta sessão."));
                dispatchNextTransfer();
            });
            connect(wizard,&QObject::destroyed,this,[this]{m_ActivePairingWizard=nullptr;updateZeroconfService();});
            wizard->show();
        });
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::permissionsRequested, this,
                [this](const DiscoveredDeviceView& device) {
            if (device.uuid.isNull() || !m_DeviceRegistry.find(device.uuid)) {
                QMessageBox::warning(this, tr("Permissões"), tr("Este computador não é conhecido; nenhuma permissão foi alterada."));
                return;
            }
            DevicePermissionsDialog dialog(m_DeviceRegistry, device.uuid, this);
            dialog.exec();
            updateProtectionFacts();
        });
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::detailsRequested, this,
                [this](const DiscoveredDeviceView& device) {
            const auto registered = m_DeviceRegistry.find(device.uuid);
            const QString alias = registered && !registered->localAlias().isEmpty() ? registered->localAlias() : tr("Nenhum");
            QMessageBox::information(this, tr("Detalhes do computador"),
                tr("Apelido: %1\nNome técnico: %2\nVersão: %3\nEndereços: %4")
                    .arg(alias, device.technicalName, device.version, QStringList(device.addresses.values()).join(", ")));
        });
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::renameRequested, this,
                [this](const DiscoveredDeviceView& device) {
            const auto registered = m_DeviceRegistry.find(device.uuid); if (!registered) return;
            bool accepted = false;
            const QString value = QInputDialog::getText(this, tr("Renomear computador"),
                tr("Apelido local (deixe vazio para remover):"), QLineEdit::Normal,
                registered->localAlias().isEmpty() ? device.displayName : registered->localAlias(), &accepted);
            if (!accepted) return;
            const auto result = m_DiscoveredDevicesModel->setLocalAlias(device.uuid, value);
            if (result == DeviceRegistry::AliasResult::InvalidAlias)
                QMessageBox::warning(this, tr("Apelido inválido"), tr("Use até 96 caracteres e 192 bytes, sem quebras de linha ou caracteres de controle."));
            else if (result == DeviceRegistry::AliasResult::PersistenceError)
                QMessageBox::warning(this, tr("Não foi possível renomear"), tr("O apelido anterior foi preservado."));
        });
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::sendFileRequested, this,
                [this](const DiscoveredDeviceView& device) {
            const auto current=m_DiscoveredDevicesModel->find(device.uuid);
            if(!current || !current->negotiation.capabilityAllowed(CapabilityId::FileTransfer)) {
                QMessageBox::information(this,tr("Atualização necessária"), current ?
                    current->negotiation.capability(CapabilityId::FileTransfer).reason : tr("O computador não está mais disponível."));
                return;
            }
            setDashboardDevice(device.uuid);
            sendFilesCrossPlatform();
        });
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::filesDropped, this, &MainWindow::sendDroppedFiles);
        connect(m_DeviceDiscoveryPanel, &DeviceDiscoveryPanel::manualAddressRequested, this, [this] {
            setServerMode(false); ui_->m_pGroupClient->show(); ui_->m_pComboServerList->setFocus();
        });
        devices->addWidget(localCard, 0);
        devices->addWidget(linkLabel, 0, Qt::AlignCenter);
        devices->addWidget(m_DeviceDiscoveryPanel, 1);
        dashboardLayout->addLayout(devices);

        auto* transferPanel = new QFrame(dashboard);
        transferPanel->setObjectName("transferPanel");
        auto* transferLayout = new QHBoxLayout(transferPanel);
        transferLayout->setContentsMargins(12, 10, 12, 10);
        m_pDashboardTransfer = new QLabel(tr("Nenhuma transferência ativa"), transferPanel);
        m_pDashboardTransferProgress = new QProgressBar(transferPanel);
        m_pDashboardTransferProgress->setRange(0, 100);
        m_pDashboardTransferProgress->setValue(0);
        m_pDashboardTransferProgress->setTextVisible(false);
        m_pDashboardTransferProgress->setFixedWidth(150);
        auto* transfersButton = new QPushButton(tr("Ver transferências"), transferPanel);
        transferLayout->addWidget(m_pDashboardTransfer, 1);
        transferLayout->addWidget(m_pDashboardTransferProgress);
        transferLayout->addWidget(transfersButton);
        connect(transfersButton, &QPushButton::clicked, this, &MainWindow::showTransferQueue);
        dashboardLayout->addWidget(transferPanel);

        root_layout->insertWidget(0, dashboard);

        auto* modeSelector = new QFrame(ui_->centralwidget);
        modeSelector->setObjectName("modeSelector");
        auto* modeLayout = new QHBoxLayout(modeSelector);
        modeLayout->setContentsMargins(6, 6, 6, 6);
        modeLayout->setSpacing(6);
        m_pServerModeButton = new QPushButton(tr("Controlar outros computadores"), modeSelector);
        m_pServerModeButton->setObjectName("modeButton");
        m_pServerModeButton->setCheckable(true);
        m_pClientModeButton = new QPushButton(tr("Ser controlado por outro computador"), modeSelector);
        m_pClientModeButton->setObjectName("modeButton");
        m_pClientModeButton->setCheckable(true);
        modeLayout->addWidget(m_pServerModeButton, 1);
        modeLayout->addWidget(m_pClientModeButton, 1);
        root_layout->insertWidget(1, modeSelector);

        ui_->m_pGroupServer->setTitle(tr("Configurações do servidor"));
        ui_->m_pGroupClient->setTitle(tr("Configurações do cliente"));
        connect(m_pServerModeButton, &QPushButton::clicked, this, [this]() {
            setServerMode(true);
        });
        connect(m_pClientModeButton, &QPushButton::clicked, this, [this]() {
            setServerMode(false);
        });
        connect(ui_->m_pGroupServer, &QGroupBox::toggled, this, [this](bool enabled) {
            if (enabled) {
                ui_->m_pGroupServer->show();
                ui_->m_pGroupClient->hide();
                m_pServerModeButton->setChecked(true);
                m_pClientModeButton->setChecked(false);
            }
        });
        connect(ui_->m_pGroupClient, &QGroupBox::toggled, this, [this](bool enabled) {
            if (enabled) {
                ui_->m_pGroupClient->show();
                ui_->m_pGroupServer->hide();
                m_pClientModeButton->setChecked(true);
                m_pServerModeButton->setChecked(false);
            }
        });
    }

    setStyleSheet(
        "QMainWindow, QWidget#centralwidget { background: #f5f7fa; }"
        "QWidget#mainHeader { background: transparent; }"
        "QFrame#dashboardCard { background: #0f172a; border-radius: 14px; }"
        "QLabel#dashboardState { color: #f8fafc; font-size: 18px; font-weight: 700; }"
        "QLabel#dashboardDetail { color: #94a3b8; font-size: 10pt; }"
        "QLabel#securityBadge { color: #86efac; background: #173c2b; border: 1px solid #296647; border-radius: 12px; padding: 6px 10px; font-weight: 600; }"
        "QFrame#localDeviceCard, QFrame#remoteDeviceCard { background: #172033; border: 1px solid #334155; border-radius: 10px; }"
        "QFrame#localDeviceCard { border-color: #3b82f6; }"
        "QLabel#deviceIcon { color: #60a5fa; font-size: 20px; }"
        "QLabel#deviceTitle { color: #f8fafc; font-size: 9pt; font-weight: 700; }"
        "QLabel#deviceDetail { color: #94a3b8; font-size: 8pt; }"
        "QLabel#deviceLink { color: #60a5fa; font-size: 20px; font-weight: 700; padding: 0 2px; }"
        "QFrame#transferPanel { background: #111c30; border: 1px solid #334155; border-radius: 8px; }"
        "QFrame#transferPanel QLabel { color: #cbd5e1; font-weight: 600; }"
        "QFrame#transferPanel QPushButton { color: #dbeafe; background: #1e3a5f; border-color: #315b8c; }"
        "QProgressBar { background: #263449; border: none; border-radius: 3px; height: 6px; }"
        "QProgressBar::chunk { background: #3b82f6; border-radius: 3px; }"
        "QFrame#modeSelector { background: #e8edf5; border: 1px solid #d1d9e6; border-radius: 10px; }"
        "QPushButton#modeButton { background: transparent; border: none; border-radius: 7px; padding: 9px 14px; color: #475569; font-weight: 600; }"
        "QPushButton#modeButton:hover { background: #f8fafc; color: #1e3a8a; }"
        "QPushButton#modeButton:checked { background: #ffffff; color: #1d4ed8; border: 1px solid #c7d2fe; font-weight: 700; }"
        "QLabel#mainTitle {"
        "  color: #1f2937;"
        "  font-size: 18px;"
        "  font-weight: 700;"
        "}"
        "QLabel#mainSubtitle {"
        "  color: #5f6b7a;"
        "  font-size: 10pt;"
        "}"
        "QGroupBox {"
        "  background: #ffffff;"
        "  border: 1px solid #d8dee8;"
        "  border-radius: 8px;"
        "  margin-top: 11px;"
        "  padding: 16px 12px 12px 12px;"
        "}"
        "QGroupBox::title {"
        "  subcontrol-origin: margin;"
        "  left: 10px;"
        "  padding: 0 6px;"
        "  color: #172033;"
        "  font-weight: 700;"
        "}"
        "QGroupBox::indicator {"
        "  width: 14px;"
        "  height: 14px;"
        "}"
        "QLineEdit, QComboBox {"
        "  background: #ffffff;"
        "  border: 1px solid #b9c2d0;"
        "  border-radius: 4px;"
        "  padding: 4px 6px;"
        "  min-height: 22px;"
        "}"
        "QLineEdit:focus, QComboBox:focus { border: 1px solid #2563eb; }"
        "QPushButton {"
        "  background: #ffffff;"
        "  border: 1px solid #b9c2d0;"
        "  color: #111827;"
        "  border-radius: 4px;"
        "  padding: 5px 14px;"
        "  min-height: 24px;"
        "}"
        "QPushButton:hover { color: #111827; background: #eef4ff; border-color: #7aa2f7; }"
        "QPushButton:disabled { color: #7a8491; background: #e7ebf0; }"
        "QPushButton#m_pButtonToggleStart {"
        "  background: #2563eb;"
        "  border-color: #2563eb;"
        "  color: white;"
        "  font-weight: 600;"
        "}"
        "QPushButton#m_pButtonToggleStart:hover { background: #1d4ed8; }"
        "QPushButton#m_pButtonReload { font-weight: 600; }"
        "QLabel { color: #1f2937; }"
        "QRadioButton, QCheckBox { color: #1f2937; }"
        "QLabel#m_pStatusLabel {"
        "  color: #0f5132;"
        "  background: #dff7ea;"
        "  border: 1px solid #9be7ba;"
        "  border-radius: 6px;"
        "  padding: 5px 8px;"
        "  font-weight: 700;"
        "}"
    );

    auto addDescription = [](QGroupBox* group, const QString& text) {
        auto* layout = qobject_cast<QVBoxLayout*>(group->layout());
        if (layout == nullptr) {
            return;
        }

        auto* label = new QLabel(text, group);
        label->setWordWrap(true);
        label->setTextInteractionFlags(Qt::NoTextInteraction);
        label->setStyleSheet("color: #64748b; margin-bottom: 6px;");
        layout->insertWidget(0, label);
    };

    addDescription(
        ui_->m_pGroupServer,
        tr("Use this mode on the computer where your main mouse and keyboard are connected.")
    );
    addDescription(
        ui_->m_pGroupClient,
        tr("Use this mode on each extra computer you want to control from the server.")
    );
}

void MainWindow::open()
{
    createTrayIcon();

    if (!m_RuntimeConsumersEnabled) {
        showNormal();
        raise();
        activateWindow();
        if (centralWidget()) centralWidget()->setEnabled(false);
        ui_->m_pActionStartCmdApp->setEnabled(false);
        ui_->m_pActionStopCmdApp->setEnabled(false);
        ui_->m_pActionReload->setEnabled(false);
        ui_->m_pActionSave->setEnabled(false);
        ui_->m_pActionSettings->setEnabled(false);
        return;
    }

    if (appConfig().getAutoHide()) {
        hide();
    } else {
        showNormal();
        if (!property("initialPlacementApplied").toBool()) {
            setProperty("initialPlacementApplied", true);
            QTimer::singleShot(0, this, [this] {
                const QScreen* targetScreen = screen();
                if (targetScreen == nullptr)
                    targetScreen = QGuiApplication::primaryScreen();
                if (targetScreen == nullptr)
                    return;
                const QRect available = targetScreen->availableGeometry().adjusted(16, 16, -16, -16);
                const QSize targetSize(std::min(880, available.width()),
                                       std::min(760, available.height()));
                showNormal();
                resize(targetSize);
                move(available.center() - QPoint(width() / 2, height() / 2));
            });
        }
    }

    if (!appConfig().autoConfigPrompted()) {
        promptAutoConfig();
    }

    // only start if user has previously started. this stops the gui from
    // auto hiding before the user has configured InputLeap (which of course
    // confuses first time users, who think InputLeap has crashed).
    if (!m_SuppressAutomaticStartOnce &&
        appConfig().startedBefore() && appConfig().getAutoStart()) {
        m_SuppressEmptyServerWarning = true;
        start_cmd_app();
        m_SuppressEmptyServerWarning = false;
    }
}

void MainWindow::setStatus(const QString &status)
{
    ui_->m_pStatusLabel->setText(status);
    ui_->m_pStatusLabel->setAccessibleName(status);
    if (m_pDashboardDetail != nullptr) {
        m_pDashboardDetail->setText(status);
        m_pDashboardDetail->setAccessibleName(status);
    }
}

void MainWindow::updateDashboardState(AppConnectionState state)
{
    if (!m_DashboardDeviceUuid.isNull()) {
        const auto device = m_DeviceConnectionModel.snapshot(m_DashboardDeviceUuid);
        if (device.has_value()) {
            updateDashboardState(device->state);
            return;
        }
    }

    // Temporary fallback until discovery/core IPC supplies a real device UUID.
    // Never synthesize identity from a hostname, address or log line.
    updateDashboardState(dashboardState(state));
}

void MainWindow::updateDashboardState(DeviceConnectionModel::State state)
{
    if (m_pDashboardState == nullptr) {
        return;
    }
    if (!m_RuntimeConsumersEnabled && !m_RuntimeBlockMessage.isEmpty()) {
        const QString title = tr("Startup blocked");
        m_pDashboardState->setText(title);
        m_pDashboardState->setAccessibleName(title);
        m_pDashboardState->setStyleSheet(QStringLiteral("color: #f87171;"));
        if (m_pDashboardDetail != nullptr) {
            m_pDashboardDetail->setText(m_RuntimeBlockMessage);
            m_pDashboardDetail->setAccessibleName(m_RuntimeBlockMessage);
        }
        return;
    }

    QString title;
    QString color;
    switch (state) {
    case DeviceConnectionModel::State::Connected:
        title = tr("Conectado e pronto"); color = "#4ade80"; break;
    case DeviceConnectionModel::State::Connecting:
        title = tr("Conectando..."); color = "#60a5fa"; break;
    case DeviceConnectionModel::State::Transferring:
        title = tr("Transferindo arquivos"); color = "#c084fc"; break;
    case DeviceConnectionModel::State::Available:
        title = tr("Disponível para conectar"); color = "#60a5fa"; break;
    case DeviceConnectionModel::State::Incompatible:
        title = tr("Versão incompatível"); color = "#fbbf24"; break;
    case DeviceConnectionModel::State::Error:
        title = tr("Erro de conexão"); color = "#f87171"; break;
    case DeviceConnectionModel::State::Offline:
    default:
        title = tr("Pronto para conectar"); color = "#f8fafc"; break;
    }
    m_pDashboardState->setText(title);
    m_pDashboardState->setStyleSheet(QString("color: %1;").arg(color));
    if (m_pDashboardRemote != nullptr) {
        const bool connected = state == DeviceConnectionModel::State::Connected ||
                               state == DeviceConnectionModel::State::Transferring;
        for (auto* card : m_DashboardRemoteCards) {
            card->hide();
        }
        if (connected && !m_DashboardRemoteCards.isEmpty()) {
            m_DashboardRemoteCards.first()->show();
        }
        m_pDashboardRemote->setText(
            connected
                ? (m_LastConnectedClientHost.isEmpty()
                       ? tr("Conectado sem proteção confirmada")
                       : m_LastConnectedClientHost)
                : tr("Aguardando conexão"));
    }
}

bool MainWindow::environmentProfileBusy() const
{
    return m_EnvironmentProfileIntegrationPolicy.busy(
        m_ExpectedRunningState == kStarted, m_FileTransferReceiveBusy);
}

void MainWindow::refreshEnvironmentProfileUi()
{
    if (m_EnvironmentProfileUiBinding) {
        m_EnvironmentProfileUiBinding->refresh(
            m_EnvironmentProfilesInitialized, environmentProfileBusy(),
            ui_ && ui_->m_pRadioExternalConfig->isChecked());
    }
}

bool MainWindow::deviceAllows(const QUuid& uuid, DevicePermissions::Permission permission, const QString& action)
{
    if (m_DeviceAllowsOverride) return m_DeviceAllowsOverride(uuid, permission);
    const bool allowed = EnvironmentProfileIntegrationPolicy::deviceAllows(
        permission,
        [this, uuid, permission] {
            return m_EnvironmentProfileController.effectiveAllows(uuid, permission);
        },
        [this, uuid, permission] {
            return !uuid.isNull() && m_DeviceRegistry.allows(uuid, permission);
        });
    if (!allowed) {
        setStatus(tr("Ação bloqueada: permissão '%1' não concedida ou dispositivo não identificado.").arg(action));
        return false;
    }
    return true;
}

bool MainWindow::revalidateFileTransferEndpoint(const QUuid& uuid, const QString& host, quint16* transferPort)
{
    const auto device = m_DiscoveredDevicesModel->find(uuid);
    const QString normalizedHost = normalizeFileTransferHost(host);
    const bool endpointMatches = device &&
        (device->addresses.contains(normalizedHost) ||
         normalizeFileTransferHost(device->technicalName).compare(normalizedHost, Qt::CaseInsensitive) == 0);
    if (!device || !device->discoveryAvailable || !endpointMatches || !device->transferPort ||
        !device->negotiation.capabilityAllowed(CapabilityId::FileTransfer) ||
        !deviceAllows(uuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) {
        QMessageBox::information(this, tr("Computador indisponível"),
                                 tr("O computador selecionado não está mais disponível para envio."));
        return false;
    }
    if (transferPort) *transferPort = device->transferPort;
    return true;
}

void MainWindow::setDashboardDevice(const QUuid& uuid)
{
    m_DashboardDeviceUuid = uuid;
    updateProtectionFacts();
    if (uuid.isNull()) {
        updateDashboardState(connection_state_);
        return;
    }
    updateDashboardFromDevice(uuid);
}

void MainWindow::handleCoreConnectionState(IpcConnectionState state, IpcConnectionRole role,
                                           const QString& technicalName, const QString& detail,
                                           IpcIdentityPresence identityPresence)
{
    if (!m_RuntimeConsumersEnabled) return;
    if (m_ServiceStopPending) return;
    if (m_ServiceStartPending && !m_ServiceStartCommandApplied) return;
    if (m_ServiceStartPending) {
        ++m_ServiceStartGeneration;
        m_ServiceStartPending = false;
        m_ServiceStartCommandApplied = false;
        if (state == IpcConnectionState::Disconnected) {
            m_LastStartSucceeded = false;
            m_ExpectedRunningState = kStopped;
            if (!m_InternalReconnect && m_ReconnectionPolicy)
                m_ReconnectionPolicy->cancel();
            m_ReconnectTargetUuid = {};
            m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
            refreshEnvironmentProfileUi();
            set_connection_state(AppConnectionState::DISCONNECTED);
        } else {
            m_LastStartSucceeded = true;
            recordSuccessfulStart();
        }
    }
    // Service commands have no direct acknowledgement. The next core state is
    // their definitive asynchronous completion, including a failed start that
    // remains disconnected.
    if (m_EnvironmentProfileIntegrationPolicy.processTransitionBusy()) {
        const bool expectedStateReached =
            (m_ExpectedRunningState == kStopped && state == IpcConnectionState::Disconnected) ||
            (m_ExpectedRunningState == kStarted && state != IpcConnectionState::Disconnected);
        const bool definitiveStartFailure =
            m_ExpectedRunningState == kStarted && state == IpcConnectionState::Disconnected;
        if (expectedStateReached || definitiveStartFailure) {
            m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
            refreshEnvironmentProfileUi();
        }
    }
    if (app_role() == AppRole::Client && appConfig().processMode() == Service &&
        m_ExpectedRunningState == kStarted && m_ReconnectionPolicy) {
        if (state == IpcConnectionState::Connected) {
            m_ReconnectionPolicy->connected();
            m_ReconnectStableTimer->start(ReconnectionPolicy::StableWindowMs);
        } else if (state == IpcConnectionState::Disconnected) {
            m_ReconnectStableTimer->stop();
            m_ReconnectionPolicy->attemptFinished();
            scheduleReconnectFailure(ReconnectionPolicy::Failure::Unknown);
        }
    }
    if (identityPresence == IpcIdentityPresence::LegacyUnavailable) {
        m_CoreConnectionStateController.applyLegacy(state, detail);
        switch (state) {
        case IpcConnectionState::Connected:
            m_LegacyPeerState = DeviceConnectionModel::State::Connected;
            break;
        case IpcConnectionState::Available:
            m_LegacyPeerState = DeviceConnectionModel::State::Available;
            break;
        case IpcConnectionState::Disconnected:
            m_LegacyPeerState = DeviceConnectionModel::State::Offline;
            break;
        }
        applyDashboardPeerPolicy();
        setStatus(tr("Identidade remota não anunciada por esta versão"));
        return;
    }
    const auto result = m_CoreConnectionStateController.apply(state, role, technicalName, detail);
    if (result.status == CoreConnectionStateController::Status::RegistryError) {
        setStatus(tr("Não foi possível salvar a identidade do dispositivo remoto"));
        appendLogError(QString("device registry failed to resolve technical name '%1'").arg(technicalName));
        return;
    }
    applyDashboardPeerPolicy(result.uuid);
    setStatus(detail.isEmpty() ? tr("Estado remoto atualizado pelo núcleo") : detail);
}

void MainWindow::handleServiceStartTimeout(quint64 generation)
{
    if (!m_ServiceStartPending || generation != m_ServiceStartGeneration)
        return;
    m_ServiceStartPending = false;
    m_ServiceStartCommandApplied = false;
    ++m_ServiceStartGeneration;
    m_IpcClient.cancelPendingCommand();
    m_ServiceStopUnconfirmed = false;
    m_ServiceStopPending = true;
    const quint64 stopGeneration = ++m_ServiceStopGeneration;
    requestServiceStopAndDisconnect();
    QTimer::singleShot(kServiceStopConfirmationTimeoutMs, this, [this, stopGeneration] {
        handleServiceStopTimeout(stopGeneration);
    });
    m_LastStartSucceeded = false;
    m_ExpectedRunningState = kStopped;
    if (!m_InternalReconnect && m_ReconnectionPolicy)
        m_ReconnectionPolicy->cancel();
    m_ReconnectTargetUuid = {};
    setStatus(tr("The service did not confirm startup. A core stop was requested; "
                 "confirmation is pending."));
}

void MainWindow::handleServiceReconnectReady()
{
    if (!m_ServiceRestartAwaitingReconnect) return;
    m_ServiceRestartAwaitingReconnect = false;
    start_cmd_app();
    m_InternalReconnect = false;
}

void MainWindow::recordSuccessfulStart()
{
    if (appConfig().startedBefore()) return;
    appConfig().setStartedBefore(true);
    if (!appConfig().saveSettings()) {
        appConfig().setStartedBefore(false);
        appendLogError(tr("Could not remember that InputLeap started successfully."));
    }
}

void MainWindow::handleRuntimeInvalidation()
{
    if (!m_RuntimeConsumersEnabled) return;

    m_RuntimeConsumersEnabled = false;
    m_EnvironmentProfilesInitialized = false;
    m_ServerConfig.setPersistenceEnabled(false);
    m_DeviceRegistry.disablePersistence();
    m_TransferQueueShuttingDown = true;
    if (m_TransferQueue) m_TransferQueue->disablePersistence();
    if (m_ActivePairingWizard) {
        PairingWizard* wizard = m_ActivePairingWizard.data();
        QObject::disconnect(wizard, nullptr, this, nullptr);
        wizard->reject();
        delete wizard;
        m_ActivePairingWizard = nullptr;
    }
    if (m_ActiveSettingsDialog) {
        SettingsDialog* dialog = m_ActiveSettingsDialog.data();
        dialog->invalidateRuntimeOperations();
        QObject::disconnect(dialog, nullptr, this, nullptr);
        m_ActiveSettingsDialog = nullptr;
    }
    if (m_ReconnectTimer) m_ReconnectTimer->stop();
    if (m_ReconnectCountdownTimer) m_ReconnectCountdownTimer->stop();
    if (m_ReconnectStableTimer) m_ReconnectStableTimer->stop();
    if (m_ReconnectionPolicy) m_ReconnectionPolicy->cancel();
    m_ReconnectTargetUuid = {};
    m_ReconnectEndpointOverride.clear();
    m_NetworkRecoveryCoordinator.reset();
    m_PendingPublicationOutcomes.clear();
    appConfig().clearRuntimePairingSecret();
    if (m_pFileTransferService) m_pFileTransferService->clearPreSharedKeys();
    for (auto it = m_PairedSessions.begin(); it != m_PairedSessions.end(); ++it) {
        if (!it->key.isEmpty()) {
            it->key.detach();
            OPENSSL_cleanse(it->key.data(), size_t(it->key.size()));
        }
    }
    m_PairedSessions.clear();
    for (auto it = m_TransferControllers.begin(); it != m_TransferControllers.end(); ++it) {
        m_TransferCancelIntents[it.key()] = TransferCancelIntent::Shutdown;
        if (it.value()) {
            it.value()->cancel();
            it.value()->cancelAndWait();
        }
    }
    if (m_pFileTransferService) m_pFileTransferService->stopListening();
    delete m_pZeroconfService;
    m_pZeroconfService = nullptr;

    m_ServiceStartPending = false;
    m_ServiceRestartPending = false;
    m_ServiceRestartAwaitingReconnect = false;
    m_InternalReconnect = false;
    ++m_ServiceStartGeneration;
    if (appConfig().processMode() == Desktop) {
        stopDesktop();
    }
    if (!m_ServiceStopPending && !m_ServiceStopUnconfirmed) {
        m_ServiceStopPending = true;
        const quint64 stopGeneration = ++m_ServiceStopGeneration;
        requestServiceStopAndDisconnect();
        QTimer::singleShot(kServiceStopConfirmationTimeoutMs, this, [this, stopGeneration] {
            handleServiceStopTimeout(stopGeneration);
        });
    }
    m_ExpectedRunningState = kStopped;
    m_LastStartSucceeded = false;
    set_connection_state(AppConnectionState::DISCONNECTED);

    m_RuntimeBlockMessage = m_ServiceStopUnconfirmed
        ? tr("Startup blocked: persistent configuration became unavailable. "
             "The core state is unknown because stop was not confirmed.")
        : tr("Startup blocked: persistent configuration became unavailable. "
             "A core stop was requested; confirmation is pending.");
    setStatus(m_RuntimeBlockMessage);
    if (centralWidget()) centralWidget()->setEnabled(false);
    ui_->m_pActionStartCmdApp->setEnabled(false);
    ui_->m_pActionStopCmdApp->setEnabled(false);
    ui_->m_pActionReload->setEnabled(false);
    ui_->m_pActionSave->setEnabled(false);
    ui_->m_pActionSettings->setEnabled(false);
    if (m_pActionTransferQueue) m_pActionTransferQueue->setEnabled(false);
    if (m_pTransferQueueDialog) m_pTransferQueueDialog->hide();
    rebuildTrayMenu();
}

void MainWindow::applyDashboardPeerPolicy(const QUuid& eventPeer)
{
    const auto policy = DashboardPeerStatePolicy::evaluate(
        m_DeviceConnectionModel.snapshots(), m_DashboardDeviceUuid, eventPeer,
        m_LegacyPeerState);
    m_DashboardDeviceUuid = policy.selected;

    switch (policy.aggregate) {
    case DeviceConnectionModel::State::Transferring:
    case DeviceConnectionModel::State::Connected:
        set_connection_state(AppConnectionState::CONNECTED);
        break;
    case DeviceConnectionModel::State::Connecting:
    case DeviceConnectionModel::State::Available:
        set_connection_state(AppConnectionState::CONNECTING);
        break;
    default:
        set_connection_state(AppConnectionState::DISCONNECTED);
        break;
    }

    if (m_DashboardDeviceUuid.isNull()) {
        updateDashboardState(policy.aggregate);
    } else {
        updateDashboardFromDevice(m_DashboardDeviceUuid);
    }
}

DeviceConnectionModel::TransitionResult MainWindow::updateDeviceConnectionState(
    const QUuid& uuid, DeviceConnectionModel::State state,
    const QString& friendlyDetail, const QString& technicalDetail)
{
    return m_DeviceConnectionModel.setState(uuid, state, friendlyDetail, technicalDetail);
}

void MainWindow::updateDashboardFromDevice(const QUuid& uuid)
{
    const auto device = m_DeviceConnectionModel.snapshot(uuid);
    if (uuid == m_ReconnectTargetUuid && device && device->state == DeviceConnectionModel::State::Incompatible) {
        scheduleReconnectFailure(ReconnectionPolicy::Failure::Incompatible);
    }
    if (uuid != m_DashboardDeviceUuid) {
        return;
    }
    if (!device.has_value()) {
        return;
    }
    updateDashboardState(device->state);
    if (m_pDashboardDetail != nullptr && !device->friendlyDetail.isEmpty()) {
        m_pDashboardDetail->setText(device->friendlyDetail);
        m_pDashboardDetail->setToolTip(device->technicalDetail);
    }
}

void MainWindow::createTrayIcon()
{
    m_pTrayIconMenu = new QMenu(this);
    rebuildTrayMenu();

    m_pTrayIcon = new QSystemTrayIcon(this);
    m_pTrayIcon->setContextMenu(m_pTrayIconMenu);
    m_pTrayIcon->setToolTip("InputLeap");

    connect(m_pTrayIcon, &QSystemTrayIcon::activated, this, &MainWindow::trayActivated);
    connect(m_pTrayIcon, &QSystemTrayIcon::messageClicked, this, &MainWindow::openLastReceivedFilesFolder);

    set_icon(AppConnectionState::DISCONNECTED);

    m_pTrayIcon->setVisible(
        TrayMenuPolicy::visibility(isVisible()).trayIconVisible);
}

void MainWindow::rebuildTrayMenu()
{
    if (m_pTrayIconMenu == nullptr || m_DiscoveredDevicesModel == nullptr)
        return;

    const auto description = TrayMenuPolicy::build(m_DiscoveredDevicesModel->devices());
    m_pTrayIconMenu->clear();

    auto* openAction = m_pTrayIconMenu->addAction(description.openText);
    openAction->setStatusTip(tr("Mostrar a janela principal do InputLeap."));
    connect(openAction, &QAction::triggered, this, [this]() {
        showNormal();
        activateWindow();
    });

    if (!m_RuntimeConsumersEnabled) {
        m_pTrayIconMenu->addSeparator();
        auto* quitAction = m_pTrayIconMenu->addAction(description.quitText);
        quitAction->setStatusTip(tr("Encerrar o InputLeap."));
        connect(quitAction, &QAction::triggered,
                qApp, &QCoreApplication::quit);
        return;
    }

    m_pTrayIconMenu->addSeparator();
    m_pTrayIconMenu->addAction(ui_->m_pActionStartCmdApp);
    m_pTrayIconMenu->addAction(ui_->m_pActionStopCmdApp);
    m_pTrayIconMenu->addAction(ui_->m_pActionReload);

    if (!description.peers.isEmpty()) {
        auto* peersMenu = m_pTrayIconMenu->addMenu(description.peersText);
        peersMenu->menuAction()->setStatusTip(tr("Ações para computadores conectados."));
        for (const auto& peer : description.peers) {
            auto* peerMenu = peersMenu->addMenu(peer.displayName);
            auto* sendAction = peerMenu->addAction(description.sendText);
            sendAction->setEnabled(peer.sendEnabled);
            sendAction->setStatusTip(tr("Escolher um arquivo para enviar a %1.").arg(peer.displayName));
            sendAction->setData(peer.target.uuid);
            const auto target = peer.target;
            connect(sendAction, &QAction::triggered, this, [this, target]() {
                sendFileFromTray(target);
            });
        }
    }

    m_pTrayIconMenu->addSeparator();
    auto* transfersAction = m_pTrayIconMenu->addAction(description.transfersText);
    transfersAction->setStatusTip(tr("Mostrar transferências ativas e recentes."));
    connect(transfersAction, &QAction::triggered, this, &MainWindow::showTransferQueue);
    m_pTrayIconMenu->addSeparator();
    m_pTrayIconMenu->addAction(ui_->m_pActionShowLog);
    m_pTrayIconMenu->addAction(ui_->m_pActionSettings);
    if (m_pActionCheckUpdates != nullptr)
        m_pTrayIconMenu->addAction(m_pActionCheckUpdates);
    m_pTrayIconMenu->addSeparator();
    auto* quitAction = m_pTrayIconMenu->addAction(description.quitText);
    quitAction->setStatusTip(tr("Encerrar o InputLeap."));
    connect(quitAction, &QAction::triggered, qApp, &QCoreApplication::quit);
}

void MainWindow::retranslateMenuBar()
{
#ifndef Q_OS_DARWIN
    main_menu_->setTitle(tr("&InputLeap"));
    m_pMenuHelp->setTitle(tr("A&juda"));
#else
    m_pMenuHelp->setTitle(tr("&File"));
    main_menu_->setTitle(tr("&Window"));
#endif

    if (m_pActionSendFiles != nullptr) {
        m_pActionSendFiles->setText(tr("Enviar &arquivos..."));
        m_pActionSendFiles->setStatusTip(tr("Enviar arquivos para outro computador conectado."));
    }
    if (m_pActionSendFolder != nullptr) {
        m_pActionSendFolder->setText(tr("Enviar &pasta..."));
        m_pActionSendFolder->setStatusTip(tr("Enviar uma pasta para outro computador conectado."));
    }
    if (m_pActionSendClipboardImage != nullptr) {
        m_pActionSendClipboardImage->setText(tr("Enviar &imagem copiada..."));
        m_pActionSendClipboardImage->setStatusTip(tr("Enviar a imagem copiada para a área de transferência."));
    }
    if (m_pActionSendQuickText != nullptr) {
        m_pActionSendQuickText->setText(tr("Enviar &texto..."));
        m_pActionSendQuickText->setStatusTip(tr("Enviar um texto curto para outro computador."));
    }
    if (m_pActionSendTestFile != nullptr) {
        m_pActionSendTestFile->setText(tr("Enviar arquivo de &teste"));
        m_pActionSendTestFile->setStatusTip(tr("Enviar um pequeno arquivo para testar a transferência."));
    }
    if (m_pActionTransferHistory != nullptr) {
        m_pActionTransferHistory->setText(tr("&Histórico de transferências..."));
        m_pActionTransferHistory->setStatusTip(tr("Mostrar as transferências recentes."));
    }
    if (m_pActionRecentReceivedFiles != nullptr) {
        m_pActionRecentReceivedFiles->setText(tr("&Recebimentos recentes..."));
        m_pActionRecentReceivedFiles->setStatusTip(tr("Mostrar arquivos recebidos de outros computadores."));
    }
    if (m_pActionTransferQueue != nullptr) {
        m_pActionTransferQueue->setText(tr("&Fila de transferências..."));
        m_pActionTransferQueue->setStatusTip(tr("Mostrar transferências ativas e recentes."));
    }
    if (m_pActionOpenReceiveFolder != nullptr) {
        m_pActionOpenReceiveFolder->setText(tr("Abrir pasta de &recebimento"));
        m_pActionOpenReceiveFolder->setStatusTip(tr("Abrir a pasta onde os arquivos recebidos são salvos."));
    }
    if (m_pActionDiagnostics != nullptr) {
        m_pActionDiagnostics->setText(tr("&Diagnóstico..."));
        m_pActionDiagnostics->setStatusTip(tr("Verificar a conexão e a disponibilidade das transferências."));
    }
    if (m_pActionClipboardHistory != nullptr) {
        m_pActionClipboardHistory->setText(m_ClipboardHistoryModel && m_ClipboardHistoryModel->isEnabled()
            ? tr("Histórico da área de transferência (ativo)...")
            : tr("Histórico da área de transferência..."));
        m_pActionClipboardHistory->setStatusTip(
            tr("Histórico opcional, temporário e somente na memória."));
    }
    if (m_pActionReleaseNotes != nullptr) {
        const QString releaseVersion = QStringLiteral(INPUTLEAP_VERSION).section(QLatin1Char('-'), 0, 0);
        m_pActionReleaseNotes->setText(
            tr("&Novidades da versão %1...").arg(releaseVersion));
        m_pActionReleaseNotes->setStatusTip(
            tr("Mostrar as novidades da versão %1.").arg(releaseVersion));
    }
    if (m_pActionCheckUpdates != nullptr) {
        m_pActionCheckUpdates->setText(tr("Verificar atualizações..."));
        m_pActionCheckUpdates->setStatusTip(
            tr("Verificar manualmente se há uma versão estável mais recente."));
    }
    ui_->m_pActionStartCmdApp->setText(tr("Iniciar"));
    ui_->m_pActionStartCmdApp->setStatusTip(tr("Iniciar o compartilhamento do InputLeap."));
    ui_->m_pActionStopCmdApp->setText(tr("Parar"));
    ui_->m_pActionStopCmdApp->setStatusTip(tr("Parar o compartilhamento do InputLeap."));
    ui_->m_pActionReload->setText(tr("Recarregar"));
    ui_->m_pActionReload->setStatusTip(tr("Reiniciar o compartilhamento do InputLeap."));
    ui_->m_pActionShowLog->setText(tr("Mostrar log"));
    ui_->m_pActionSettings->setText(tr("Configurações..."));
    ui_->m_pActionMinimize->setText(tr("Ocultar"));
    ui_->m_pActionSave->setText(tr("Salvar configuração"));
    ui_->m_pActionQuit->setText(tr("Sair"));
    ui_->m_pActionAbout->setText(tr("Sobre o InputLeap..."));
}

void MainWindow::createMenuBar()
{
    m_pMenuBar = new QMenuBar(this);
    main_menu_ = new QMenu("", m_pMenuBar);
    m_pMenuHelp = new QMenu("", m_pMenuBar);
    m_pActionSendFiles = new QAction(tr("Send &Files..."), this);
    m_pActionSendFiles->setStatusTip(tr("Enviar arquivos para outro computador conectado."));
    m_pActionSendFiles->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_F));
    connect(m_pActionSendFiles, &QAction::triggered, this, &MainWindow::sendFilesCrossPlatform);
    m_pActionSendFolder = new QAction(tr("Send F&older..."), this);
    m_pActionSendFolder->setStatusTip(tr("Enviar uma pasta para outro computador conectado."));
    connect(m_pActionSendFolder, &QAction::triggered, this, &MainWindow::sendFolderCrossPlatform);
    m_pActionSendClipboardImage = new QAction(tr("Send Clipboard &Image..."), this);
    m_pActionSendClipboardImage->setStatusTip(tr("Enviar a imagem copiada para a área de transferência."));
    connect(m_pActionSendClipboardImage, &QAction::triggered, this, &MainWindow::sendClipboardImageCrossPlatform);
    m_pActionSendQuickText = new QAction(tr("Send &Text..."), this);
    m_pActionSendQuickText->setStatusTip(tr("Enviar um texto curto para outro computador."));
    connect(m_pActionSendQuickText, &QAction::triggered, this, &MainWindow::sendQuickTextCrossPlatform);
    m_pActionSendTestFile = new QAction(tr("Send &Test File"), this);
    m_pActionSendTestFile->setStatusTip(tr("Enviar um pequeno arquivo para testar a transferência."));
    connect(m_pActionSendTestFile, &QAction::triggered, this, &MainWindow::sendTestFileCrossPlatform);
    m_pActionTransferHistory = new QAction(tr("Transfer &History..."), this);
    m_pActionTransferHistory->setStatusTip(tr("Mostrar as transferências recentes."));
    connect(m_pActionTransferHistory, &QAction::triggered, this, &MainWindow::showTransferHistory);
    m_pActionRecentReceivedFiles = new QAction(tr("Recent &Received Files..."), this);
    m_pActionRecentReceivedFiles->setStatusTip(tr("Mostrar arquivos recebidos de outros computadores."));
    connect(m_pActionRecentReceivedFiles, &QAction::triggered, this, &MainWindow::showRecentReceivedFiles);
    m_pActionTransferQueue = new QAction(tr("Transfer &Queue..."), this);
    m_pActionTransferQueue->setStatusTip(tr("Mostrar transferências ativas e recentes."));
    m_pActionTransferQueue->setEnabled(m_RuntimeConsumersEnabled);
    connect(m_pActionTransferQueue, &QAction::triggered, this, &MainWindow::showTransferQueue);
    m_pActionOpenReceiveFolder = new QAction(tr("Open Receive &Folder"), this);
    m_pActionOpenReceiveFolder->setStatusTip(tr("Abrir a pasta onde os arquivos recebidos são salvos."));
    connect(m_pActionOpenReceiveFolder, &QAction::triggered, this, &MainWindow::openReceiveFilesFolder);
    m_pActionDiagnostics = new QAction(tr("&Diagnostics..."), this);
    m_pActionDiagnostics->setStatusTip(tr("Verificar a conexão e a disponibilidade das transferências."));
    connect(m_pActionDiagnostics, &QAction::triggered, this, &MainWindow::showDiagnostics);
    m_pActionClipboardHistory = new QAction(tr("Histórico da área de transferência..."), this);
    m_pActionClipboardHistory->setCheckable(true);
    connect(m_pActionClipboardHistory, &QAction::triggered, this, &MainWindow::showClipboardHistory);
    connect(m_ClipboardHistoryModel.get(), &ClipboardHistoryModel::enabledChanged, this, [this](bool enabled) {
        m_pActionClipboardHistory->setChecked(enabled);
        retranslateMenuBar();
    });
    m_pActionReleaseNotes = new QAction(tr("What's &New..."), this);
    m_pActionReleaseNotes->setStatusTip(tr("Mostrar as novidades desta versão."));
    connect(m_pActionReleaseNotes, &QAction::triggered, this, &MainWindow::showReleaseNotes);
    m_pActionCheckUpdates = new QAction(this);
    m_pActionCheckUpdates->setObjectName(QStringLiteral("checkForUpdatesAction"));
    connect(m_pActionCheckUpdates, &QAction::triggered,
            this, &MainWindow::checkForUpdates);
    retranslateMenuBar();

    ui_->m_pActionShowLog->setText(tr("Mostrar log"));
    ui_->m_pActionSettings->setText(tr("Configurações..."));
    ui_->m_pActionMinimize->setText(tr("Ocultar"));
    ui_->m_pActionSave->setText(tr("Salvar configuração"));
    ui_->m_pActionQuit->setText(tr("Sair"));
    ui_->m_pActionAbout->setText(tr("Sobre o InputLeap..."));

    m_pMenuBar->setStyleSheet(
        "QMenuBar { background: #f5f7fa; color: #334155; padding: 3px 8px; spacing: 4px; }"
        "QMenuBar::item { padding: 6px 10px; border-radius: 6px; }"
        "QMenuBar::item:selected, QMenuBar::item:pressed { background: #e0e7ff; color: #1d4ed8; }"
        "QMenu { background: #ffffff; color: #1f2937; border: 1px solid #cbd5e1; border-radius: 8px; padding: 7px; }"
        "QMenu::item { padding: 8px 34px 8px 12px; border-radius: 6px; margin: 1px 0; }"
        "QMenu::item:selected { background: #e8efff; color: #1d4ed8; }"
        "QMenu::separator { height: 1px; background: #e2e8f0; margin: 6px 8px; }"
    );

#ifndef Q_OS_DARWIN
    m_pMenuBar->addAction(main_menu_->menuAction());
    m_pMenuBar->addAction(m_pMenuHelp->menuAction());
#else
    m_pMenuBar->addAction(m_pMenuHelp->menuAction());
    m_pMenuBar->addAction(main_menu_->menuAction());
#endif

    auto* sendMenu = main_menu_->addMenu(tr("Enviar"));
    sendMenu->addAction(m_pActionSendFiles);
    sendMenu->addAction(m_pActionSendFolder);
    sendMenu->addSeparator();
    sendMenu->addAction(m_pActionSendClipboardImage);
    sendMenu->addAction(m_pActionSendQuickText);
    sendMenu->addAction(m_pActionSendTestFile);

    auto* transfersMenu = main_menu_->addMenu(tr("Transferências"));
    transfersMenu->addAction(m_pActionTransferQueue);
    transfersMenu->addAction(m_pActionRecentReceivedFiles);
    transfersMenu->addAction(m_pActionTransferHistory);
    transfersMenu->addSeparator();
    transfersMenu->addAction(m_pActionOpenReceiveFolder);

    main_menu_->addAction(ui_->m_pActionShowLog);
    main_menu_->addAction(m_pActionClipboardHistory);
    main_menu_->addAction(m_pActionDiagnostics);
    main_menu_->addSeparator();
    main_menu_->addAction(ui_->m_pActionSettings);
    main_menu_->addAction(ui_->m_pActionMinimize);
    main_menu_->addSeparator();

#ifndef Q_OS_DARWIN
    main_menu_->addAction(ui_->m_pActionSave);
#endif
    main_menu_->addSeparator();
    main_menu_->addAction(ui_->m_pActionQuit);
    m_pMenuHelp->addAction(m_pActionCheckUpdates);
    m_pMenuHelp->addAction(m_pActionReleaseNotes);
    m_pMenuHelp->addAction(ui_->m_pActionAbout);

#ifdef Q_OS_DARWIN
    m_pMenuHelp->addAction(ui_->m_pActionSave);
#endif

    setMenuBar(m_pMenuBar);
}

void MainWindow::loadSettings()
{
    // the next two must come BEFORE loading groupServerChecked and groupClientChecked or
    // disabling and/or enabling the right widgets won't automatically work
    ui_->m_pRadioExternalConfig->setChecked(settings().value("useExternalConfig", false).toBool());
    ui_->m_pRadioInternalConfig->setChecked(settings().value("useInternalConfig", true).toBool());

    ui_->m_pGroupServer->setChecked(settings().value("groupServerChecked", false).toBool());
    ui_->m_pLineEditConfigFile->setText(settings().value("configFile",
                                                    QDir::homePath() + "/" + APP_CONFIG_NAME).toString());
    ui_->m_pGroupClient->setChecked(settings().value("groupClientChecked", true).toBool());
    ui_->m_pLineEditHostname->setText(settings().value("serverHostname").toString());
    const bool serverMode = ui_->m_pGroupServer->isChecked();
    ui_->m_pGroupServer->setVisible(serverMode);
    ui_->m_pGroupClient->setVisible(!serverMode);
    if (m_pServerModeButton != nullptr && m_pClientModeButton != nullptr) {
        m_pServerModeButton->setChecked(serverMode);
        m_pClientModeButton->setChecked(!serverMode);
    }
    loadTransferHistory();
}

void MainWindow::initConnections()
{
    connect(ui_->m_pActionMinimize, &QAction::triggered, this, &MainWindow::hide);
    connect(ui_->m_pComboServerList, &QComboBox::currentTextChanged, this, &MainWindow::comboServerList_currentIndexChanged);
    connect(ui_->m_pLineEditHostname, &QLineEdit::textChanged, this, [this](const QString& hostname) {
        if (!m_RuntimeConsumersEnabled) return;
        settings().setValue("serverHostname", hostname.trimmed());
        settings().sync();
    });
    connect(ui_->m_pLineEditHostname, &QLineEdit::returnPressed,
            ui_->m_pButtonReload, &QPushButton::click);
    connect(ui_->m_pActionRestore, &QAction::triggered, this, &MainWindow::showNormal);
    connect(ui_->m_pActionStartCmdApp, &QAction::triggered, this, &MainWindow::start_cmd_app);
    connect(ui_->m_pActionStopCmdApp, &QAction::triggered, this, &MainWindow::stop_cmd_app);
    connect(ui_->m_pActionShowLog, &QAction::triggered, this, &MainWindow::showLogWindow);
    connect(ui_->m_pActionReload, &QAction::triggered, this, &MainWindow::restart_cmd_app);
    connect(ui_->m_pActionQuit, &QAction::triggered, qApp, &QCoreApplication::quit);
}

void MainWindow::saveSettings()
{
    if (!m_RuntimeConsumersEnabled) return;
    // program settings
    settings().setValue("groupServerChecked", ui_->m_pGroupServer->isChecked());
    settings().setValue("useExternalConfig", ui_->m_pRadioExternalConfig->isChecked());
    settings().setValue("configFile", ui_->m_pLineEditConfigFile->text());
    settings().setValue("useInternalConfig", ui_->m_pRadioInternalConfig->isChecked());
    settings().setValue("groupClientChecked", ui_->m_pGroupClient->isChecked());
    settings().setValue("serverHostname", ui_->m_pLineEditHostname->text());

    settings().sync();
}

void MainWindow::loadTransferHistory()
{
    m_TransferHistory.clear();
    const int count = settings().beginReadArray("transferHistory");
    for (int i = 0; i < count; ++i) {
        settings().setArrayIndex(i);
        QStringList entry{
            settings().value("time").toString(),
            settings().value("direction").toString(),
            settings().value("file").toString(),
            settings().value("peer").toString(),
            settings().value("status").toString(),
            settings().value("folder").toString()
        };
        if (entry.at(0).isEmpty() || entry.at(2).isEmpty()) {
            continue;
        }
        m_TransferHistory.append(entry);
    }
    settings().endArray();
}

void MainWindow::saveTransferHistory()
{
    if (!m_RuntimeConsumersEnabled) return;
    settings().remove("transferHistory");
    settings().beginWriteArray("transferHistory");
    for (int i = 0; i < m_TransferHistory.size(); ++i) {
        const QStringList& entry = m_TransferHistory.at(i);
        settings().setArrayIndex(i);
        settings().setValue("time", entry.value(0));
        settings().setValue("direction", entry.value(1));
        settings().setValue("file", entry.value(2));
        settings().setValue("peer", entry.value(3));
        settings().setValue("status", entry.value(4));
        settings().setValue("folder", entry.value(5));
    }
    settings().endArray();
    settings().sync();
}

void MainWindow::set_icon(AppConnectionState state)
{
    if (m_pTrayIcon) {
        QIcon icon = QIcon::fromTheme(icon_name_for_connection_state(state),
                                      QIcon(icon_file_for_connection_state(state)));
#if defined(Q_OS_MAC)
        icon.setIsMask(true);
#endif
        m_pTrayIcon->setIcon(icon);
    }
}

void MainWindow::trayActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick)
    {
        if (isVisible())
        {
            hide();
        }
        else
        {
            showNormal();
            activateWindow();
        }
    }
}

void MainWindow::logOutput()
{
    if (cmd_app_process_)
    {
        QString text(cmd_app_process_->readAllStandardOutput());
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        const auto results = text.split(QRegularExpression("\r|\n|\r\n"));
#else
        const auto results = text.split(QRegExp("\r|\n|\r\n"));
#endif
        for (const auto& line : results) {
            if (!line.isEmpty())
            {
                appendLogRaw(line);
            }
        }
    }
}

void MainWindow::logError()
{
    if (cmd_app_process_)
    {
        appendLogRaw(cmd_app_process_->readAllStandardError());
    }
}

void MainWindow::appendLogInfo(const QString& text)
{
    if (appConfig().logLevel() >= 3) {
        m_pLogWindow->appendInfo(text);
    }
}

void MainWindow::appendLogDebug(const QString& text) {
    if (appConfig().logLevel() >= 4) {
        m_pLogWindow->appendDebug(text);
    }
}

void MainWindow::appendLogError(const QString& text)
{
    m_pLogWindow->appendError(text);
}

void MainWindow::appendLogRaw(const QString& text)
{
    if (!m_RuntimeConsumersEnabled || m_ServiceStopPending) return;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const auto lines = text.split(QRegularExpression("\r|\n|\r\n"));
#else
    const auto lines = text.split(QRegExp("\r|\n|\r\n"));
#endif
    for (const auto& line : lines) {
        if (!line.isEmpty()) {
            m_pLogWindow->appendRaw(line);
            updateFromLogLine(line);
        }
    }
}

void MainWindow::updateFromLogLine(const QString &line)
{
    // TODO: this code makes Andrew cry
    updateFileTransferPeerFromLogLine(line);
    checkFingerprint(line);
}

void MainWindow::updateFileTransferPeerFromLogLine(const QString& line)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    static const QRegularExpression acceptedClientRegex("accepted client connection from ([0-9a-fA-F:\\.]+)");
    const QRegularExpressionMatch match = acceptedClientRegex.match(line);
    if (!match.hasMatch()) {
        return;
    }

    m_LastConnectedClientHost = normalizeFileTransferHost(match.captured(1));
#else
    QRegExp acceptedClientRegex(".*accepted client connection from ([0-9a-fA-F:\\.]+).*");
    if (!acceptedClientRegex.exactMatch(line)) {
        return;
    }

    m_LastConnectedClientHost = normalizeFileTransferHost(acceptedClientRegex.cap(1));
#endif

    rememberFileTransferDestinationHost(m_LastConnectedClientHost);
    appendLogInfo(tr("file transfer destination updated to connected client %1").arg(m_LastConnectedClientHost));
}

void MainWindow::checkFingerprint(const QString& line)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    QRegularExpression fingerprintRegex("peer fingerprint \\(SHA1\\): ([A-F0-9:]+) \\(SHA256\\): ([A-F0-9:]+)$");
    QRegularExpressionMatch match = fingerprintRegex.match(line);
    if (!match.hasMatch()) {
        return;
    }

    auto match1 = match.captured(1).toStdString();
    auto match2 = match.captured(2).toStdString();
#else
    QRegExp fingerprintRegex(".*peer fingerprint \\(SHA1\\): ([A-F0-9:]+) \\(SHA256\\): ([A-F0-9:]+)");
    if (!fingerprintRegex.exactMatch(line)) {
        return;
    }

    auto match1 = fingerprintRegex.cap(1).toStdString();
    auto match2 = fingerprintRegex.cap(2).toStdString();
#endif

    inputleap::FingerprintData fingerprint_sha1 = {
        inputleap::fingerprint_type_to_string(inputleap::FingerprintType::SHA1),
        inputleap::string::from_hex(match1)
    };

    inputleap::FingerprintData fingerprint_sha256 = {
        inputleap::fingerprint_type_to_string(inputleap::FingerprintType::SHA256),
        inputleap::string::from_hex(match2)
    };

    bool is_client = app_role() == AppRole::Client;

    auto db_path = is_client
            ? inputleap::DataDirectories::trusted_servers_ssl_fingerprints_path()
            : inputleap::DataDirectories::trusted_clients_ssl_fingerprints_path();

    // We compare only SHA256 fingerprints, but show both SHA1 and SHA256 so that the users can
    // still verify fingerprints on old InputLeap servers. This way the only time when we are
    // exposed to SHA1 vulnerabilities is when the user is reconnecting again.
    inputleap::FingerprintDatabase db;
    if (m_FingerprintTrustOverride) {
        if (m_FingerprintTrustOverride(false)) return;
    }
    else {
        auto db_dir = db_path.parent_path();
        if (!inputleap::fs::exists(db_dir)) {
            inputleap::fs::create_directories(db_dir);
        }
        db.read(db_path);
        if (db.is_trusted(fingerprint_sha256)) return;
    }

    static bool messageBoxAlreadyShown = false;

    if (!messageBoxAlreadyShown) {
        if (is_client) {
            if (m_ReconnectionPolicy && m_ReconnectionPolicy->active())
                m_ReconnectionPolicy->failed(ReconnectionPolicy::Failure::Certificate);
            stop_cmd_app();
        }
        const quint64 fingerprintStopGeneration = m_ServiceStartGeneration;

        messageBoxAlreadyShown = true;
        int dialogResult = QDialog::Rejected;
        if (m_FingerprintDialogExecOverride) {
            dialogResult = m_FingerprintDialogExecOverride();
        }
        else {
            FingerprintAcceptDialog dialog{this, app_role(), fingerprint_sha1, fingerprint_sha256};
            dialogResult = dialog.exec();
        }
        if (dialogResult == QDialog::Accepted && m_RuntimeConsumersEnabled) {
            // restart core process after trusting fingerprint.
            if (m_FingerprintTrustOverride) m_FingerprintTrustOverride(true);
            else {
                db.add_trusted(fingerprint_sha256);
                db.write(db_path);
            }
            if (is_client && m_ServiceStartGeneration == fingerprintStopGeneration) {
                restartAfterFingerprintAcceptance();
            }
        }

        messageBoxAlreadyShown = false;
    }
}

void MainWindow::restartAfterFingerprintAcceptance()
{
    if (appConfig().processMode() != Service) {
        start_cmd_app();
        return;
    }

    if (!m_RuntimeConsumersEnabled) return;

    if (m_ServiceStopPending) {
        m_ServiceRestartPending = true;
        return;
    }

    m_ServiceRestartAwaitingReconnect = true;
    set_connection_state(AppConnectionState::DISCONNECTED);
    if (m_ServiceReconnectOverride) m_ServiceReconnectOverride();
    else m_IpcClient.connectToHost();
}

void MainWindow::beginReconnectionIntent()
{
    if (!m_ReconnectionPolicy || app_role() != AppRole::Client || appConfig().processMode() != Service) return;
    if (!m_ReconnectTargetUuid.isNull()) m_ReconnectionPolicy->beginUuid(m_ReconnectTargetUuid);
    else {
        QString exactHost = ui_->m_pLineEditHostname->text().trimmed();
        if (exactHost.isEmpty() && ui_->m_pCheckBoxAutoConfig->isChecked() && ui_->m_pComboServerList->count() > 0)
            exactHost = ui_->m_pComboServerList->currentText().trimmed();
        if (!exactHost.isEmpty()) m_ReconnectionPolicy->beginManual(exactHost);
    }
}

void MainWindow::scheduleReconnectFailure(ReconnectionPolicy::Failure failure)
{
    if (!m_ReconnectionPolicy || app_role() != AppRole::Client || appConfig().processMode() != Service || m_ExpectedRunningState != kStarted) return;
    m_ReconnectionPolicy->failed(failure);
}

bool MainWindow::performReconnectAttempt(const QString& endpoint)
{
    if (m_ReconnectTargetUuid.isNull() || !deviceAllows(m_ReconnectTargetUuid, DevicePermissions::AutoConnect, tr("conexão automática")))
        return false;
    if (app_role() != AppRole::Client || appConfig().processMode() != Service || m_ExpectedRunningState != kStarted || m_InternalReconnect) return false;
    m_InternalReconnect = true;
    m_ReconnectEndpointOverride = endpoint;
    stop_cmd_app();
    m_ExpectedRunningState = kStarted;
    m_ServiceRestartPending = true;
    if (!m_ServiceStopPending) {
        m_ServiceRestartPending = false;
        if (m_RuntimeConsumersEnabled) {
            m_ServiceRestartAwaitingReconnect = true;
            set_connection_state(AppConnectionState::DISCONNECTED);
            if (m_ServiceReconnectOverride) m_ServiceReconnectOverride();
            else m_IpcClient.connectToHost();
        }
    }
    refreshEnvironmentProfileUi();
    return true;
}

void MainWindow::updateReconnectCountdown()
{
    const qint64 remaining = (std::max)(qint64(0), m_ReconnectDeadlineMs - QDateTime::currentMSecsSinceEpoch());
    const int seconds = int((remaining + 999) / 1000);
    const QString text = tr("Reconectando em %1 s").arg(seconds);
    setStatus(text);
    if (m_pDashboardDetail) { m_pDashboardDetail->setText(text); m_pDashboardDetail->setAccessibleName(text); }
}

void MainWindow::restart_cmd_app()
{
    m_EnvironmentProfileIntegrationPolicy.beginProcessTransition();
    refreshEnvironmentProfileUi();
    if (m_ReconnectionPolicy) m_ReconnectionPolicy->cancel();
    m_ReconnectTargetUuid = {};
    if (appConfig().processMode() == Service) {
        if (!m_ServiceStopPending)
            stop_cmd_app();
        m_ServiceRestartPending = true;
        if (!m_ServiceStopPending) {
            m_ServiceRestartPending = false;
            if (m_RuntimeConsumersEnabled) {
                m_ServiceRestartAwaitingReconnect = true;
                set_connection_state(AppConnectionState::DISCONNECTED);
                if (m_ServiceReconnectOverride) m_ServiceReconnectOverride();
                else m_IpcClient.connectToHost();
            }
        }
        return;
    }
    stop_cmd_app();
    start_cmd_app();
}

void MainWindow::proofreadInfo()
{
    AppConnectionState old = connection_state_;
    connection_state_ = AppConnectionState::DISCONNECTED;
    set_connection_state(old);
}

void MainWindow::start_cmd_app()
{
    if (m_ServiceStopPending) {
        m_LastStartSucceeded = false;
        setStatus(!m_RuntimeConsumersEnabled && !m_RuntimeBlockMessage.isEmpty()
            ? m_RuntimeBlockMessage
            : tr("InputLeap stop was requested; confirmation is pending."));
        return;
    }
    if (m_ServiceStopUnconfirmed) {
        m_LastStartSucceeded = false;
        m_ExpectedRunningState = kStopped;
        set_connection_state(AppConnectionState::DISCONNECTED);
        setStatus(tr("InputLeap stop was not confirmed; the core state is unknown."));
        return;
    }
    if (m_ServiceRestartAwaitingReconnect) return;
    if (!m_RuntimeConsumersEnabled) {
        m_LastStartSucceeded = false;
        m_ExpectedRunningState = kStopped;
        setStatus(m_RuntimeBlockMessage);
        showNormal();
        return;
    }

    m_EnvironmentProfileIntegrationPolicy.beginProcessTransition();
    refreshEnvironmentProfileUi();
    bool desktopMode = appConfig().processMode() == Desktop;
    bool serviceMode = appConfig().processMode() == Service;

    m_LastStartSucceeded = false;
    m_ServiceStartPending = false;
    ++m_ServiceStartGeneration;
    appendLogDebug("starting process");
    m_ExpectedRunningState = kStarted;
    refreshEnvironmentProfileUi();
    if (!m_InternalReconnect) beginReconnectionIntent();
    set_connection_state(AppConnectionState::CONNECTING);
    if (desktopMode) {
        setStatus(tr("Estado remoto detalhado indisponível no modo Desktop"));
    }

    QString app;
    QStringList args;

    args << "-f" << "--no-tray" << "--debug" << appConfig().logLevelText();
    // The GUI owns retries so the core cannot run a concurrent reconnect loop.
    if (app_role() == AppRole::Client && serviceMode) args << "--no-restart";


    args << "--name" << getScreenName();

    if (desktopMode)
    {
        cmd_app_process_ = new QProcess(this);
    }
    else
    {
        // tell client/server to talk to daemon through ipc.
        args << "--ipc";

#if defined(Q_OS_WIN)
        // tell the client/server to shut down when a ms windows desk
        // is switched; this is because we may need to elevate or not
        // based on which desk the user is in (login always needs
        // elevation, where as default desk does not).
        // Note that this is only enabled when InputLeap is set to elevate
        // 'as needed' (e.g. on a UAC dialog popup) in order to prevent
        // unnecessary restarts when InputLeap was started elevated or
        // when it is not allowed to elevate. In these cases restarting
        // the server is fruitless.
        if (appConfig().elevateMode() == ElevateAsNeeded) {
                args << "--stop-on-desk-switch";
        }
#endif
    }

#ifndef Q_OS_LINUX

    if (m_ServerConfig.enableDragAndDrop()) {
        args << "--enable-drag-drop";
    }

#endif

    if (!m_AppConfig->getCryptoEnabled()) {
        args << "--disable-crypto";
    }

#if defined(Q_OS_WIN)
    // on windows, the profile directory changes depending on the user that
    // launched the process (e.g. when launched with elevation). setting the
    // profile dir on launch ensures it uses the same profile dir is used
    // no matter how its relaunched.
    args << "--profile-dir" << QString::fromStdString("\"" + inputleap::path_to_utf8(inputleap::DataDirectories::profile()) + "\"");
#endif

    if ((app_role() == AppRole::Client && !clientArgs(args, app))
        || (app_role() == AppRole::Server && !serverArgs(args, app)))
    {
        m_ExpectedRunningState = kStopped;
        if (desktopMode) {
            stopDesktop();
        }
        else {
            m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
            refreshEnvironmentProfileUi();
        }
        if (!m_InternalReconnect && m_ReconnectionPolicy)
            m_ReconnectionPolicy->cancel();
        set_connection_state(AppConnectionState::DISCONNECTED);
        return;
    }

    if (m_AppArgumentsOverride) args = m_AppArgumentsOverride(args);

    if (desktopMode)
    {
        connect(cmd_app_process_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWindow::cmd_app_finished);
        connect(cmd_app_process_, &QProcess::readyReadStandardOutput, this, &MainWindow::logOutput);
        connect(cmd_app_process_, &QProcess::readyReadStandardError, this, &MainWindow::logError);
    }

    m_pLogWindow->startNewInstance();

    appendLogInfo("starting " + QString(app_role() == AppRole::Server ? "server" : "client"));

    qDebug() << args;

    appendLogDebug(QString("command: %1 %2").arg(app, args.join(" ")));

    appendLogInfo("config file: " + configFilename());
    appendLogInfo("log level: " + appConfig().logLevelText());

    if (appConfig().logToFile())
        appendLogInfo("log file: " + appConfig().logFilename());

    if (desktopMode)
    {
        cmd_app_process_->start(app, args);
        if (!cmd_app_process_->waitForStarted())
        {
            m_ExpectedRunningState = kStopped;
            stopDesktop();
            if (!m_InternalReconnect && m_ReconnectionPolicy)
                m_ReconnectionPolicy->cancel();
            m_ReconnectTargetUuid = {};
            set_connection_state(AppConnectionState::DISCONNECTED);
            show();
            QMessageBox::warning(this, tr("Program can not be started"), QString(tr("The executable<br><br>%1<br><br>could not be successfully started, although it does exist. Please check if you have sufficient permissions to run this program.").arg(app)));
            return;
        }
        m_LastStartSucceeded = true;
        recordSuccessfulStart();
        m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
        refreshEnvironmentProfileUi();
#if defined(Q_OS_WIN)
        if (setLowLatencyPriority(cmd_app_process_)) {
            appendLogInfo(tr("low latency process priority enabled"));
        }
        else {
            appendLogDebug(tr("could not enable low latency process priority"));
        }
#endif
    }

    if (serviceMode)
    {
        QString command(app + " " + args.join(" "));
        const quint64 generation = ++m_ServiceStartGeneration;
        m_ServiceStartPending = true;
        m_ServiceStartCommandApplied = false;
        m_IpcClient.sendCommand(command, appConfig().elevateMode());
        QTimer::singleShot(kServiceStartConfirmationTimeoutMs, this, [this, generation] {
            handleServiceStartTimeout(generation);
        });
    }
}

void MainWindow::setServerMode(bool isServerMode)
{
    if (m_ReconnectionPolicy) m_ReconnectionPolicy->cancel();
    m_ReconnectStableTimer->stop();
    m_ReconnectTargetUuid = {};
    ui_->m_pGroupServer->setChecked(isServerMode);
    ui_->m_pGroupClient->setChecked(!isServerMode);
    if(m_DeviceDiscoveryPanel)m_DeviceDiscoveryPanel->setConnectionInitiationAllowed(!isServerMode);
}

bool MainWindow::clientArgs(QStringList& args, QString& app)
{
    app = appPath(appConfig().client_name());

    if (!QFile::exists(app))
    {
        show();
        QMessageBox::warning(this, tr("InputLeap client not found"),
                             tr("The executable for the InputLeap client does not exist."));
        return false;
    }

#if defined(Q_OS_WIN)
    // wrap in quotes so a malicious user can't start \Program.exe as admin.
    app = QString("\"%1\"").arg(app);
#endif

    if (appConfig().logToFile())
    {
        appConfig().persistLogDir();
        args << "--log" << appConfig().logFilenameCmd();
    }

    if (!m_ReconnectEndpointOverride.isEmpty()) {
        args << "[" + m_ReconnectEndpointOverride + "]:" + QString::number(appConfig().port());
        m_ReconnectEndpointOverride.clear();
        return true;
    }

    // check auto config first, if it is disabled or no server detected,
    // use line edit host name if it is not empty
    if (ui_->m_pCheckBoxAutoConfig->isChecked()) {
        if (ui_->m_pComboServerList->count() != 0) {
            QString serverIp = ui_->m_pComboServerList->currentText();
            args << "[" + serverIp + "]:" + QString::number(appConfig().port());
            return true;
        }
    } else if (ui_->m_pLineEditHostname->text().isEmpty()) {
        show();
        if (!m_SuppressEmptyServerWarning) {
            QMessageBox::warning(this, tr("Hostname is empty"),
                             tr("Please fill in a hostname for the InputLeap client to connect to."));
        }
        return false;
    }

    args << "[" + ui_->m_pLineEditHostname->text() + "]:" + QString::number(appConfig().port());

    return true;
}

QString MainWindow::configFilename()
{
    QString filename;
    if (ui_->m_pRadioInternalConfig->isChecked())
    {
        // TODO: no need to use a temporary file, since we need it to
        // be permanent (since it'll be used for Windows services, etc).
        m_pTempConfigFile = m_TempConfigFileFactory
            ? m_TempConfigFileFactory() : nullptr;
        if (m_pTempConfigFile == nullptr || !m_pTempConfigFile->open())
        {
            QMessageBox::critical(this, tr("Cannot write configuration file"),
                                  tr("The temporary configuration file required to start InputLeap can not be written."));
            return "";
        }

        serverConfig().save(*m_pTempConfigFile);
        filename = m_pTempConfigFile->fileName();

        m_pTempConfigFile->close();
    }
    else
    {
        if (!QFile::exists(ui_->m_pLineEditConfigFile->text()))
        {
            if (QMessageBox::warning(this, tr("Configuration filename invalid"),
                tr("You have not filled in a valid configuration file for the InputLeap server. "
                        "Do you want to browse for the configuration file now?"), QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes
                    || !on_m_pButtonBrowseConfigFile_clicked())
                return "";
        }

        filename = ui_->m_pLineEditConfigFile->text();
    }
    return filename;
}

AppRole MainWindow::app_role() const
{
    return ui_->m_pGroupClient->isChecked() ? AppRole::Client : AppRole::Server;
}

QString MainWindow::hostname() const
{
    return ui_->m_pLineEditHostname->text();
}

QString MainWindow::address()
{
    QString address = appConfig().networkInterface();
    if (!address.isEmpty())
        address = "[" + address + "]";
    return address + ":" + QString::number(appConfig().port());
}

QString MainWindow::appPath(const QString& name)
{
    if (m_AppPathResolver) return m_AppPathResolver(name);
    return appConfig().program_dir() + name;
}

bool MainWindow::serverArgs(QStringList& args, QString& app)
{
    app = appPath(appConfig().server_name());

    if (!QFile::exists(app))
    {
        QMessageBox::warning(this, tr("InputLeap server not found"),
                             tr("The executable for the InputLeap server does not exist."));
        return false;
    }

#if defined(Q_OS_WIN)
    // wrap in quotes so a malicious user can't start \Program.exe as admin.
    app = QString("\"%1\"").arg(app);
#endif

    if (appConfig().logToFile())
    {
        appConfig().persistLogDir();

        args << "--log" << appConfig().logFilenameCmd();
    }

    if (!appConfig().getRequireClientCertificate()) {
        args << "--disable-client-cert-checking";
    }

    QString configFilename = this->configFilename();
    if (configFilename.isEmpty())
        return false;
#if defined(Q_OS_WIN)
    // wrap in quotes in case username contains spaces.
    configFilename = QString("\"%1\"").arg(configFilename);
#endif
    args << "-c" << configFilename << "--address" << address();

    return true;
}

void MainWindow::stop_cmd_app()
{
    if (!m_InternalReconnect || m_ServiceRestartPending ||
        m_ServiceRestartAwaitingReconnect) {
        m_ServiceRestartPending = false;
        m_ServiceRestartAwaitingReconnect = false;
        m_InternalReconnect = false;
        m_ReconnectEndpointOverride.clear();
    }
    m_EnvironmentProfileIntegrationPolicy.beginProcessTransition();
    refreshEnvironmentProfileUi();
    appendLogDebug("stopping process");

    m_ExpectedRunningState = kStopped;
    m_ServiceStartPending = false;
    ++m_ServiceStartGeneration;
    refreshEnvironmentProfileUi();
    if (!m_InternalReconnect && m_ReconnectionPolicy) m_ReconnectionPolicy->cancel();

    if (appConfig().processMode() == Service)
    {
        if (!m_ServiceStopPending && !m_ServiceStopUnconfirmed) {
            m_ServiceStopPending = true;
            const quint64 stopGeneration = ++m_ServiceStopGeneration;
            stopService();
            QTimer::singleShot(kServiceStopConfirmationTimeoutMs, this, [this, stopGeneration] {
                handleServiceStopTimeout(stopGeneration);
            });
        }
        setStatus(m_ServiceStopUnconfirmed
            ? tr("InputLeap stop was not confirmed; the core state is unknown.")
            : tr("InputLeap stop was requested; confirmation is pending."));
    }
    else if (appConfig().processMode() == Desktop)
    {
        stopDesktop();
    }

    if (!m_ServiceStopPending)
        set_connection_state(AppConnectionState::DISCONNECTED);

    // HACK: deleting the object deletes the physical file, which is
    // bad, since it could be in use by the Windows service!
#if !defined(Q_OS_WIN)
    delete m_pTempConfigFile;
#endif
    m_pTempConfigFile = nullptr;

    // reset so that new connects cause auto-hide.
    m_AlreadyHidden = false;
}

void MainWindow::stopService()
{
    requestServiceStopAndDisconnect();
}

void MainWindow::requestServiceStopAndDisconnect()
{
    if (m_ServiceStopOverride) {
        m_ServiceStopOverride();
        return;
    }
    if (!m_SystemIpcEnabled) return;
    m_IpcClient.requestServiceStopAndDisconnect(appConfig().elevateMode());
}

void MainWindow::handleServiceStopTimeout(quint64 generation)
{
    if (!m_ServiceStopPending || generation != m_ServiceStopGeneration) return;

    ++m_ServiceStopGeneration;
    m_ServiceStopPending = false;
    m_ServiceStopUnconfirmed = true;
    m_ServiceRestartPending = false;
    m_ServiceRestartAwaitingReconnect = false;
    m_InternalReconnect = false;
    m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
    refreshEnvironmentProfileUi();
    set_connection_state(AppConnectionState::DISCONNECTED);
    setStatus(tr("InputLeap stop was not confirmed; the core state is unknown."));
    if (m_UpdateInstallAwaitingStop) {
        updateInstallationFailed(
            tr("A instalação não começou porque a parada do InputLeap não foi confirmada."));
    }
}

void MainWindow::stopDesktop()
{
    QMutexLocker locker(&m_StopDesktopMutex);
    m_DesktopStopConfirmed = false;
    if (!cmd_app_process_) {
        m_DesktopStopConfirmed = true;
        m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
        refreshEnvironmentProfileUi();
        return;
    }

    appendLogInfo("stopping InputLeap desktop process");

    QProcess* const process = cmd_app_process_;
    if (process->state() != QProcess::NotRunning) {
        process->terminate();
        if (!process->waitForFinished(5000)) {
            process->kill();
            process->waitForFinished(5000);
        }
    }
    m_DesktopStopConfirmed = process->state() == QProcess::NotRunning;
    if (m_DesktopStopPostWaitHook) m_DesktopStopPostWaitHook();
    if (cmd_app_process_ == process && m_DesktopStopConfirmed) process->close();

    if (cmd_app_process_ == process && m_DesktopStopConfirmed) {
        delete process;
        cmd_app_process_ = nullptr;
    }
    m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
    refreshEnvironmentProfileUi();
}

void MainWindow::cmd_app_finished(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_UNUSED(exitStatus);
    const bool unexpectedExit = m_ExpectedRunningState == kStarted;
    m_ExpectedRunningState = kStopped;
    m_LastStartSucceeded = false;
    if (unexpectedExit) {
        if (m_ReconnectionPolicy)
            m_ReconnectionPolicy->cancel();
        m_ReconnectTargetUuid = {};
    }
    m_EnvironmentProfileIntegrationPolicy.completeProcessTransition();
    refreshEnvironmentProfileUi();
    if (exitCode == 0) {
        appendLogInfo(QString("process exited normally"));
    }
    else {
        appendLogError(QString("process exited with error code: %1").arg(exitCode));
    }

    if (cmd_app_process_ && sender() == cmd_app_process_) {
        cmd_app_process_->deleteLater();
        cmd_app_process_ = nullptr;
    }
    set_connection_state(AppConnectionState::DISCONNECTED);
}

void MainWindow::set_connection_state(AppConnectionState state)
{
    if (connection_state() == state &&
        !(state == AppConnectionState::DISCONNECTED && m_ServiceRestartAwaitingReconnect))
        return;

    if (m_DashboardDeviceUuid.isNull()) {
        updateDashboardState(state);
    }

    const bool restartAwaitingReconnect =
        state == AppConnectionState::DISCONNECTED && m_ServiceRestartAwaitingReconnect;
    if (state == AppConnectionState::CONNECTED || state == AppConnectionState::CONNECTING ||
        restartAwaitingReconnect)
    {
        disconnect(ui_->m_pButtonToggleStart, &QPushButton::clicked, ui_->m_pActionStartCmdApp, &QAction::trigger);
        connect(ui_->m_pButtonToggleStart, &QPushButton::clicked, ui_->m_pActionStopCmdApp, &QAction::trigger);
        ui_->m_pButtonToggleStart->setText(tr("&Stop"));
        ui_->m_pButtonReload->setEnabled(true);
    }
    else if (state == AppConnectionState::DISCONNECTED)
    {
        disconnect(ui_->m_pButtonToggleStart, &QPushButton::clicked, ui_->m_pActionStopCmdApp, &QAction::trigger);
        connect(ui_->m_pButtonToggleStart, &QPushButton::clicked, ui_->m_pActionStartCmdApp, &QAction::trigger);
        ui_->m_pButtonToggleStart->setText(tr("&Start"));
        ui_->m_pButtonReload->setEnabled(false);
    }

    const bool canStop = state == AppConnectionState::CONNECTED ||
        state == AppConnectionState::TRANSFERRING ||
        state == AppConnectionState::CONNECTING || restartAwaitingReconnect;
    ui_->m_pActionStartCmdApp->setEnabled(!canStop);
    ui_->m_pActionStopCmdApp->setEnabled(canStop);

    switch (state)
    {
    case AppConnectionState::CONNECTED: {
        ProtectionFacts facts;
        facts.pairedUuid = m_DashboardDeviceUuid;
        const auto session = m_PairedSessions.constFind(facts.pairedUuid);
        facts.pairedSessionKey = !facts.pairedUuid.isNull() &&
            session != m_PairedSessions.cend() && session->key.size() == 32;
        facts.tlsActive = facts.pairedSessionKey && m_AppConfig &&
            m_AppConfig->getCryptoEnabled();
        facts.receiverGate = !facts.pairedUuid.isNull() &&
            m_DeviceRegistry.allows(facts.pairedUuid, DevicePermissions::ReceiveFiles);
        facts.permissions = m_DeviceRegistry.permissions(facts.pairedUuid);
        if (ProtectionPanel::stateFor(facts) == ProtectionPanel::State::Complete) {
            ui_->m_pLabelPadlock->show();
        }
        else {
            ui_->m_pLabelPadlock->hide();
        }

        setStatus(tr("InputLeap is running."));

        break;
    }
    case AppConnectionState::CONNECTING:
        ui_->m_pLabelPadlock->hide();
        setStatus(tr("InputLeap is starting."));
        break;
    case AppConnectionState::DISCONNECTED:
        ui_->m_pLabelPadlock->hide();
        setStatus(tr("InputLeap is not running."));
        break;
    case AppConnectionState::TRANSFERRING:
        break;
    default:
        break;
    }

    set_icon(state);

    connection_state_ = state;
    updateProtectionFacts();
}

void MainWindow::updateProtectionFacts()
{
    if (!m_ProtectionPanel && !m_pSecurityBadge) return;
    ProtectionFacts facts;
    facts.pairedUuid = m_DashboardDeviceUuid;
    const auto session = m_PairedSessions.constFind(facts.pairedUuid);
    facts.pairedSessionKey = !facts.pairedUuid.isNull() && session != m_PairedSessions.cend() && session->key.size() == 32;
    facts.tlsActive = facts.pairedSessionKey && m_AppConfig && m_AppConfig->getCryptoEnabled() &&
        (connection_state_ == AppConnectionState::CONNECTED || connection_state_ == AppConnectionState::TRANSFERRING);
    facts.receiverGate = !facts.pairedUuid.isNull() && m_DeviceRegistry.allows(facts.pairedUuid, DevicePermissions::ReceiveFiles);
    facts.permissions = m_DeviceRegistry.permissions(facts.pairedUuid);
    if (m_ProtectionPanel) m_ProtectionPanel->setFacts(facts);
    if (m_pSecurityBadge) {
        const QString label = ProtectionPanel::badgeLabel(facts);
        m_pSecurityBadge->setText(label);
        m_pSecurityBadge->setAccessibleName(label);
    }
}

void MainWindow::setVisible(bool visible)
{
    const auto visibility = TrayMenuPolicy::visibility(visible);
    QMainWindow::setVisible(visibility.mainWindowVisible);
    if (m_pTrayIcon != nullptr)
        m_pTrayIcon->setVisible(visibility.trayIconVisible);
    ui_->m_pActionMinimize->setEnabled(visibility.mainWindowVisible);
    ui_->m_pActionRestore->setEnabled(!visibility.mainWindowVisible);

#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070 // lion
    // dock hide only supported on lion :(
    ProcessSerialNumber psn = { 0, kCurrentProcess };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    GetCurrentProcess(&psn);
#pragma GCC diagnostic pop
    if (visible)
        TransformProcessType(&psn, kProcessTransformToForegroundApplication);
    else
        TransformProcessType(&psn, kProcessTransformToBackgroundApplication);
#endif
}

QString MainWindow::getIPAddresses()
{
    QList<QHostAddress> addresses = QNetworkInterface::allAddresses();

    bool hinted = false;
    QString result;
    for (int i = 0; i < addresses.size(); i++) {
        if (addresses[i].protocol() == QAbstractSocket::IPv4Protocol &&
            addresses[i] != QHostAddress(QHostAddress::LocalHost)) {

            QString address = addresses[i].toString();
            QString format = "%1, ";

            // usually 192.168.x.x is a useful ip for the user, so indicate
            // this by making it bold.
            if (!hinted && address.startsWith("192.168")) {
                hinted = true;
                format = "<b>%1</b>, ";
            }

            result += format.arg(address);
        }
    }

    if (result == "") {
        return tr("Unknown");
    }

    // remove trailing comma.
    result.chop(2);

    return result;
}

QString MainWindow::getScreenName()
{
    if (appConfig().screenName() == "") {
        return QHostInfo::localHostName();
    }
    else {
        return appConfig().screenName();
    }
}

void MainWindow::changeEvent(QEvent* event)
{
    if (event != nullptr)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
        {
            ui_->retranslateUi(this);
            retranslateMenuBar();

            proofreadInfo();

            break;
        }
        case QEvent::WindowStateChange:
        {
            windowStateChanged();
            break;
        }
        default:
        {
            break;
        }
        }
    }
    // all that do not return are allowing the event to propagate
    QMainWindow::changeEvent(event);
}

void MainWindow::updateZeroconfService()
{
    QMutexLocker locker(&m_UpdateZeroconfMutex);

    if (!m_RuntimeConsumersEnabled) {
        if (m_pZeroconfService) {
            m_DiscoveredDevicesModel->clearDiscovery();
            delete m_pZeroconfService;
            m_pZeroconfService = nullptr;
        }
        return;
    }

    if (isBonjourRunning()) {
        if (!m_AppConfig->wizardShouldRun()) {
            if (m_pZeroconfService) {
                m_DiscoveredDevicesModel->clearDiscovery();
                delete m_pZeroconfService;
                m_pZeroconfService = nullptr;
            }

            if (m_AppConfig->autoConfig() || app_role() == AppRole::Server) {
                m_pZeroconfService = new ZeroconfService(this);
                connect(m_pZeroconfService, &ZeroconfService::advertisementFound,
                        m_DiscoveredDevicesModel.get(), &DiscoveredDevicesModel::upsert);
                connect(m_pZeroconfService, &ZeroconfService::advertisementUpdated,
                        m_DiscoveredDevicesModel.get(), &DiscoveredDevicesModel::upsert);
                connect(m_pZeroconfService, &ZeroconfService::advertisementLost,
                        m_DiscoveredDevicesModel.get(),
                        static_cast<void (DiscoveredDevicesModel::*)(const DiscoveredDeviceAdvertisement&)>(
                            &DiscoveredDevicesModel::remove));
            }
        }
    }
}

void MainWindow::serverDetected(const QString name)
{
    if (ui_->m_pComboServerList->findText(name) == -1) {
        // Note: the first added item triggers startInputLeap
        ui_->m_pComboServerList->addItem(name);
    }

    if (ui_->m_pComboServerList->count() > 1) {
        ui_->m_pComboServerList->show();
    }
}

void MainWindow::updateSSLFingerprint()
{
    ui_->toolbutton_show_fingerprint->setEnabled(false);
    ui_->m_pLabelLocalFingerprint->setText("Disabled");
    if (!m_RuntimeConsumersEnabled)
        return;

    if (m_AppConfig->getCryptoEnabled() && m_pSslCertificate == nullptr) {
        m_pSslCertificate = new SslCertificate(this);
        connect(m_pSslCertificate, &SslCertificate::info, this, &MainWindow::appendLogInfo);
        m_pSslCertificate->generateCertificate();
    }

    if (!m_AppConfig->getCryptoEnabled()) {
        return;
    }

    auto local_path = inputleap::DataDirectories::local_ssl_fingerprints_path();
    if (!inputleap::fs::exists(local_path)) {
        return;
    }

    inputleap::FingerprintDatabase db;
    db.read(local_path);
    if (db.fingerprints().size() != 2) {
        return;
    }

    for (const auto& fingerprint : db.fingerprints()) {
        if (fingerprint.algorithm == "sha1") {
            auto fingerprint_str = inputleap::format_ssl_fingerprint(fingerprint.data);
            ui_->label_sha1_fingerprint_full->setText(QString::fromStdString(fingerprint_str));
            continue;
        }

        if (fingerprint.algorithm == "sha256") {
            auto fingerprint_str = inputleap::format_ssl_fingerprint(fingerprint.data);
            fingerprint_str.resize(40);
            fingerprint_str += " ...";

            auto fingerprint_str_cols = inputleap::format_ssl_fingerprint_columns(fingerprint.data);
            auto fingerprint_randomart = inputleap::create_fingerprint_randomart(fingerprint.data);

            ui_->m_pLabelLocalFingerprint->setText(QString::fromStdString(fingerprint_str));
            ui_->label_sha256_fingerprint_full->setText(QString::fromStdString(fingerprint_str_cols));
            ui_->label_sha256_randomart->setText(QString::fromStdString(fingerprint_randomart));
        }
    }

    ui_->toolbutton_show_fingerprint->setEnabled(true);
}

void MainWindow::on_m_pGroupClient_toggled(bool on)
{
    ui_->m_pGroupServer->setChecked(!on);
    if (on) {
        updateZeroconfService();
    }
}

void MainWindow::on_m_pGroupServer_toggled(bool on)
{
    ui_->m_pGroupClient->setChecked(!on);
    if (on) {
        updateZeroconfService();
    }
}

bool MainWindow::on_m_pButtonBrowseConfigFile_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Browse for a InputLeap config file"), QString(), APP_CONFIG_OPEN_FILTER);

    if (!fileName.isEmpty())
    {
        ui_->m_pLineEditConfigFile->setText(fileName);
        return true;
    }

    return false;
}

bool MainWindow::on_m_pActionSave_triggered()
{
    if (!m_RuntimeConsumersEnabled) return true;
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save configuration as..."), QString(), APP_CONFIG_SAVE_FILTER);

    if (!fileName.isEmpty() && !serverConfig().save(fileName))
    {
        QMessageBox::warning(this, tr("Save failed"), tr("Could not save configuration to file."));
        return true;
    }

    return false;
}

void MainWindow::on_m_pActionAbout_triggered()
{
    AboutDialog(this, appPath(appConfig().client_name())).exec();
}

void MainWindow::on_m_pActionSettings_triggered()
{
    if (!m_RuntimeConsumersEnabled) return;
    if (m_ActiveSettingsDialog) {
        m_ActiveSettingsDialog->raise();
        m_ActiveSettingsDialog->activateWindow();
        return;
    }
    auto dialog = std::make_unique<SettingsDialog>(
        this, appConfig(), &m_EnvironmentProfileController,
        m_EnvironmentProfilesInitialized, environmentProfileBusy(),
        ui_->m_pRadioExternalConfig->isChecked());
    m_ActiveSettingsDialog = dialog.get();
    auto* profileAvailabilityTimer = new QTimer(dialog.get());
    profileAvailabilityTimer->setInterval(250);
    connect(profileAvailabilityTimer, &QTimer::timeout, dialog.get(),
            [this, dialogPointer = dialog.get()] {
        dialogPointer->setEnvironmentProfileAvailability(
            m_EnvironmentProfilesInitialized, environmentProfileBusy(),
            ui_->m_pRadioExternalConfig->isChecked());
    });
    profileAvailabilityTimer->start();
    connect(dialog.get(), &SettingsDialog::requestLanguageChange, this, &MainWindow::requestLanguageChange);
    connect(dialog.get(), &SettingsDialog::configurationImported, this, [this] {
        if (!m_RuntimeConsumersEnabled) return;
        m_pFileTransferService->setReceiveDirectory(appConfig().receiveDirectory());
        m_pFileTransferService->setPairingCode(appConfig().fileTransferPairingCode());
        updateSSLFingerprint();
    });
    connect(dialog.get(), &SettingsDialog::requestCoreRestart,
            this, &MainWindow::restart_cmd_app);
    connect(dialog.get(), &SettingsDialog::configurationSaveFailed,
            this, &MainWindow::handleRuntimeInvalidation);
    if (dialog.get()->exec() == QDialog::Accepted && m_RuntimeConsumersEnabled)
    {
        m_pFileTransferService->setReceiveDirectory(appConfig().receiveDirectory());
        m_pFileTransferService->setPairingCode(appConfig().fileTransferPairingCode());
        updateSSLFingerprint();
    }
    m_ActiveSettingsDialog = nullptr;
    disconnect(dialog.get(), &SettingsDialog::requestLanguageChange, this, &MainWindow::requestLanguageChange);
}

void MainWindow::sendFilesCrossPlatform()
{
    const QUuid targetUuid = m_DashboardDeviceUuid;
    if (!deviceAllows(targetUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    const QString host = promptFileTransferDestinationHost(tr("Send files"));
    if (host.isEmpty()) {
        return;
    }
    if (!confirmFileTransferDestinationReachable(host)) {
        return;
    }

    const QStringList files = QFileDialog::getOpenFileNames(
        this,
        tr("Choose files to send"),
        QDir::homePath(),
        tr("All files (*.*)")
    );

    if (files.isEmpty()) {
        return;
    }

    quint64 totalSize = 0;
    for (const QString& file : files) {
        const QFileInfo info(file);
        if (info.exists() && info.isFile()) {
            totalSize += static_cast<quint64>(info.size());
        }
    }

    const quint16 transferPort = FILE_TRANSFER_PORT;
    const QString startMessage = tr("Sending %1 file(s), %2 MB total, to %3:%4")
        .arg(files.size())
        .arg(QString::number(totalSize / 1024.0 / 1024.0, 'f', 2))
        .arg(host)
        .arg(transferPort);
    setStatus(startMessage);
    m_ReceivedFileNotificationOpenable = false;
    appendLogInfo(startMessage);
    if (m_pTrayIcon != nullptr && m_pTrayIcon->isVisible()) {
        m_pTrayIcon->showMessage(tr("InputLeap file transfer"), startMessage, QSystemTrayIcon::Information, 4000);
    }

    const QString doneMessage = tr("%1 file(s) sent to %2. Received files are saved in Downloads/InputLeap on the destination computer.")
        .arg(files.size())
        .arg(host);

    QList<FileTransferService::TransferItem> items;
    for (const QString& path : files) {
        items.append({path, QFileInfo(path).fileName()});
    }

    QUuid discoveredUuid = targetUuid;
    quint16 discoveredPort=0;
    const auto dashboardDevice=m_DiscoveredDevicesModel->find(m_DashboardDeviceUuid);
    const QString normalizedDestination=normalizeFileTransferHost(host);
    if(dashboardDevice && (dashboardDevice->addresses.contains(normalizedDestination) ||
       normalizeFileTransferHost(dashboardDevice->technicalName).compare(normalizedDestination,Qt::CaseInsensitive)==0)) {
        discoveredUuid=dashboardDevice->uuid;
        discoveredPort=dashboardDevice->transferPort;
    }

    if (discoveredUuid != targetUuid || !deviceAllows(discoveredUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    startFileTransfer(
        host,
        items,
        tr("File transfer"),
        doneMessage,
        tr("File transfer failed"),
        tr("File transfer cancelled"),
        tr("%1 file(s)").arg(files.size()),
        QFileInfo(files.first()).absolutePath(), discoveredUuid, discoveredPort);
}

void MainWindow::sendFileFromTray(const TrayMenuPolicy::Target& target)
{
    if (!deviceAllows(target.uuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    auto current = m_DiscoveredDevicesModel->find(target.uuid);
    if (!current || !TrayMenuPolicy::resolveTarget(target, *current)) {
        QMessageBox::information(this,tr("Computador indisponível"),tr("Este computador não está mais disponível para envio."));
        return;
    }

    const QString path = QFileDialog::getOpenFileName(
        this, tr("Escolha um arquivo para enviar"), QDir::homePath(), tr("Todos os arquivos (*.*)"));
    if (path.isEmpty())
        return;

    const QFileInfo info(path);
    if (!info.exists() || !info.isFile() || !info.isReadable() || info.isSymLink()) {
        QMessageBox::warning(this, tr("Enviar arquivo"),
                             tr("O arquivo não existe, é um link ou não pode ser lido."));
        return;
    }
    if (!FileTransferService::isSafeToOpenAutomatically(info.fileName()) &&
        QMessageBox::warning(
            this, tr("Confirmar envio seguro"),
            tr("Este arquivo pode executar comandos. Ele será enviado, mas nunca aberto automaticamente no destino. Deseja continuar?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        return;

    // Discovery can change while the file picker is open. Fail closed unless the
    // captured UUID still owns the exact same transfer endpoint.
    current = m_DiscoveredDevicesModel->find(target.uuid);
    const auto resolved = current ? TrayMenuPolicy::resolveTarget(target, *current) : std::nullopt;
    if (!resolved) {
        QMessageBox::information(this, tr("Computador desconectado"),
                                 tr("Este computador não está mais disponível para envio."));
        return;
    }

    QList<FileTransferService::TransferItem> items{{info.absoluteFilePath(), info.fileName()}};
    startFileTransfer(
        target.address, items, tr("Transferência de arquivos"),
        tr("Arquivo enviado para %1.").arg(resolved->displayName),
        tr("Falha na transferência"), tr("Transferência cancelada"),
        info.fileName(), info.absolutePath(), target.uuid, target.transferPort);
}

void MainWindow::sendDroppedFiles(const QUuid& deviceUuid, const QStringList& paths)
{
    if (!deviceAllows(deviceUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    const auto device=m_DiscoveredDevicesModel->find(deviceUuid);
    if(!device || !device->negotiation.capabilityAllowed(CapabilityId::FileTransfer) || !(device->state==DeviceConnectionModel::State::Connected||device->state==DeviceConnectionModel::State::Controlling) || !device->capabilities.contains(ZeroconfCapability::FileTransfer) || !device->transferPort || paths.isEmpty()) return;
    QString host; for(const QString& candidate:device->addresses) if(!QHostAddress(candidate).isNull()){host=candidate;break;} if(host.isEmpty())return;
    bool hasDirectory=false,hasDangerous=false;
    for(const QString& path:paths){const QFileInfo info(path);if(!info.exists()||!info.isReadable()||info.isSymLink())return;hasDirectory|=info.isDir();hasDangerous|=info.isFile()&&!FileTransferService::isSafeToOpenAutomatically(info.fileName());}
    if(hasDangerous && QMessageBox::warning(this,tr("Confirmar envio seguro"),tr("Um ou mais itens podem executar comandos. Eles serão enviados, mas nunca abertos automaticamente no destino. Deseja continuar?"),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    if(hasDirectory && QMessageBox::question(this,tr("Enviar pasta"),tr("Pastas serão enumeradas de forma limitada antes do envio. Deseja continuar?"),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    QList<FileTransferService::TransferItem> items; constexpr int maximumFolderFiles=1000;bool nestedDangerous=false;
    for(const QString& path:paths){const QFileInfo info(path);if(info.isFile())items.append({info.absoluteFilePath(),info.fileName()});else{QDir root(info.absoluteFilePath());QDirIterator it(info.absoluteFilePath(),QDir::Files|QDir::Readable|QDir::NoSymLinks,QDirIterator::Subdirectories);while(it.hasNext()&&items.size()<maximumFolderFiles){const QString file=it.next();const QFileInfo nested(file);nestedDangerous|=!FileTransferService::isSafeToOpenAutomatically(nested.fileName());items.append({file,info.fileName()+"/"+root.relativeFilePath(file)});}if(it.hasNext()){QMessageBox::warning(this,tr("Pasta muito grande"),tr("A pasta excede o limite seguro de %1 arquivos.").arg(maximumFolderFiles));return;}}}
    if(nestedDangerous&&!hasDangerous&&QMessageBox::warning(this,tr("Confirmar envio seguro"),tr("A pasta contém itens que podem executar comandos. Eles serão enviados, mas nunca abertos automaticamente no destino. Deseja continuar?"),QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    if(items.isEmpty()){QMessageBox::information(this,tr("Enviar arquivos"),tr("Nenhum arquivo legível foi encontrado."));return;}
    const QString label=items.size()==1?QFileInfo(items.first().sourcePath).fileName():tr("%1 itens arrastados").arg(items.size());
    startFileTransfer(host,items,tr("Transferência de arquivos"),tr("Arquivos enviados para %1.").arg(device->displayName),tr("Falha na transferência"),tr("Transferência cancelada"),label,QFileInfo(paths.first()).absolutePath(),deviceUuid,device->transferPort);
}

void MainWindow::sendFolderCrossPlatform()
{
    const QUuid targetUuid = m_DashboardDeviceUuid;
    if (!deviceAllows(targetUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    const QString host = promptFileTransferDestinationHost(tr("Send folder"));
    if (host.isEmpty()) {
        return;
    }
    if (!confirmFileTransferDestinationReachable(host)) {
        return;
    }

    const QString folderPath = QFileDialog::getExistingDirectory(this, tr("Choose folder to send"), QDir::homePath());
    if (folderPath.isEmpty()) {
        return;
    }

    // Re-resolve by UUID after the dialogs. A hostname is not an identity and
    // discovery may have changed while the folder picker was open.
    const auto current = m_DiscoveredDevicesModel->find(targetUuid);
    const QString normalizedHost = normalizeFileTransferHost(host);
    if (!current || !current->discoveryAvailable ||
        (!current->addresses.contains(normalizedHost) &&
         normalizeFileTransferHost(current->technicalName).compare(normalizedHost, Qt::CaseInsensitive) != 0) ||
        !current->transferPort ||
        !current->negotiation.capabilityAllowed(CapabilityId::FileTransfer) ||
        !deviceAllows(targetUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) {
        QMessageBox::information(this, tr("Computador indisponível"),
                                 tr("O computador selecionado não está mais disponível para envio."));
        return;
    }
    const quint16 transferPort = current->transferPort;

    const QFileInfo folderInfo(folderPath);
    const QDir rootDir(folderInfo.absoluteFilePath());
    QList<FileTransferService::TransferItem> items;
    quint64 totalSize = 0;

    QDirIterator iterator(folderInfo.absoluteFilePath(), QDir::Files, QDirIterator::Subdirectories);
    while (iterator.hasNext()) {
        const QString filePath = iterator.next();
        const QFileInfo fileInfo(filePath);
        const QString relativePath = QDir(folderInfo.absoluteDir().absolutePath()).relativeFilePath(filePath);
        items.append({filePath, relativePath});
        totalSize += static_cast<quint64>(fileInfo.size());
    }

    if (items.isEmpty()) {
        QMessageBox::information(this, tr("Send folder"), tr("The selected folder does not contain files."));
        return;
    }

    const QString startMessage = tr("Sending folder %1 (%2 file(s), %3 MB) to %4:%5")
        .arg(folderInfo.fileName())
        .arg(items.size())
        .arg(QString::number(totalSize / 1024.0 / 1024.0, 'f', 2))
        .arg(host)
        .arg(transferPort);
    setStatus(startMessage);
    m_ReceivedFileNotificationOpenable = false;
    appendLogInfo(startMessage);
    if (m_pTrayIcon != nullptr && m_pTrayIcon->isVisible()) {
        m_pTrayIcon->showMessage(tr("InputLeap file transfer"), startMessage, QSystemTrayIcon::Information, 4000);
    }

    const QString doneMessage = tr("Folder %1 sent to %2. Received files are saved in the destination receive folder.")
        .arg(folderInfo.fileName())
        .arg(host);

    startFileTransfer(
        host,
        items,
        tr("Folder transfer"),
        doneMessage,
        tr("Folder transfer failed"),
        tr("Folder transfer cancelled"),
        folderInfo.fileName(),
        folderInfo.absoluteFilePath(),
        targetUuid, transferPort);
}

void MainWindow::sendClipboardImageCrossPlatform()
{
    const QUuid targetUuid = m_DashboardDeviceUuid;
    if (!deviceAllows(targetUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    const QString host = promptFileTransferDestinationHost(tr("Send clipboard image"));
    if (host.isEmpty()) {
        return;
    }
    if (!confirmFileTransferDestinationReachable(host)) {
        return;
    }

    quint16 transferPort = 0;
    if (!revalidateFileTransferEndpoint(targetUuid, host, &transferPort)) return;

    const QImage image = QApplication::clipboard()->image();
    if (image.isNull()) {
        QMessageBox::information(
            this,
            tr("Send clipboard image"),
            tr("There is no image copied to the clipboard."));
        return;
    }

    const QString transferDirectory = QDir::temp().filePath("InputLeap");
    QDir().mkpath(transferDirectory);
    const QString fileName = QString("clipboard-image-%1.png")
        .arg(QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss"));
    const QString filePath = QDir(transferDirectory).filePath(fileName);

    if (!image.save(filePath, "PNG")) {
        QMessageBox::warning(
            this,
            tr("Send clipboard image"),
            tr("Could not prepare the clipboard image for transfer."));
        return;
    }

    const QFileInfo fileInfo(filePath);
    const QString startMessage = tr("Sending clipboard image %1 (%2 MB) to %3:%4")
        .arg(fileInfo.fileName())
        .arg(QString::number(fileInfo.size() / 1024.0 / 1024.0, 'f', 2))
        .arg(host)
        .arg(FILE_TRANSFER_PORT);
    setStatus(startMessage);
    appendLogInfo(startMessage);

    QList<FileTransferService::TransferItem> items;
    items.append({filePath, fileInfo.fileName()});

    startFileTransfer(
        host,
        items,
        tr("Clipboard image transfer"),
        tr("Clipboard image sent to %1. Received files are saved in the destination receive folder.").arg(host),
        tr("Clipboard image transfer failed"),
        tr("Clipboard image transfer cancelled"),
        fileInfo.fileName(),
        fileInfo.absolutePath(), targetUuid, transferPort);
}

void MainWindow::sendQuickTextCrossPlatform()
{
    const QUuid targetUuid = m_DashboardDeviceUuid;
    if (!deviceAllows(targetUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    const QString host = promptFileTransferDestinationHost(tr("Send text"));
    if (host.isEmpty()) {
        return;
    }
    if (!confirmFileTransferDestinationReachable(host)) {
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Send text"));
    dialog.resize(520, 320);

    auto* layout = new QVBoxLayout(&dialog);
    auto* label = new QLabel(tr("Text to send:"), &dialog);
    auto* textEdit = new QPlainTextEdit(&dialog);
    textEdit->setPlaceholderText(tr("Type or paste text here."));
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(label);
    layout->addWidget(textEdit);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    quint16 transferPort = 0;
    if (!revalidateFileTransferEndpoint(targetUuid, host, &transferPort)) return;

    const QString text = textEdit->toPlainText();
    if (text.trimmed().isEmpty()) {
        QMessageBox::information(this, tr("Send text"), tr("Enter text before sending."));
        return;
    }

    const QString transferDirectory = QDir::temp().filePath("InputLeap");
    QDir().mkpath(transferDirectory);
    const QString fileName = QString("inputleap-text-%1.txt")
        .arg(QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss"));
    const QString filePath = QDir(transferDirectory).filePath(fileName);

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Send text"), tr("Could not prepare the text file for transfer."));
        return;
    }
    QTextStream out(&file);
    out << text;
    file.close();

    const QFileInfo fileInfo(filePath);
    QList<FileTransferService::TransferItem> items;
    items.append({filePath, fileInfo.fileName()});
    startFileTransfer(
        host,
        items,
        tr("Text transfer"),
        tr("Text sent to %1.").arg(host),
        tr("Text transfer failed"),
        tr("Text transfer cancelled"),
        fileInfo.fileName(),
        fileInfo.absolutePath(), targetUuid, transferPort);
}

void MainWindow::sendTestFileCrossPlatform()
{
    const QUuid targetUuid = m_DashboardDeviceUuid;
    if (!deviceAllows(targetUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) return;
    const QString host = promptFileTransferDestinationHost(tr("Send test file"));
    if (host.isEmpty()) {
        return;
    }
    if (!confirmFileTransferDestinationReachable(host)) {
        return;
    }

    quint16 transferPort = 0;
    if (!revalidateFileTransferEndpoint(targetUuid, host, &transferPort)) return;

    const QString transferDirectory = QDir::temp().filePath("InputLeap");
    QDir().mkpath(transferDirectory);
    const QString fileName = QString("inputleap-transfer-test-%1.txt")
        .arg(QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss"));
    const QString filePath = QDir(transferDirectory).filePath(fileName);

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Send test file"), tr("Could not prepare the test file."));
        return;
    }

    QTextStream out(&file);
    out << "InputLeap transfer test\n";
    out << "Created: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    out << "From: " << getScreenName() << "\n";
    out << "Local IP addresses: " << getIPAddresses() << "\n";
    out << "Destination: " << host << ":" << FILE_TRANSFER_PORT << "\n";
    file.close();

    const QFileInfo fileInfo(filePath);
    QList<FileTransferService::TransferItem> items;
    items.append({filePath, fileInfo.fileName()});
    startFileTransfer(
        host,
        items,
        tr("Test file transfer"),
        tr("Test file sent to %1.").arg(host),
        tr("Test file transfer failed"),
        tr("Test file transfer cancelled"),
        fileInfo.fileName(),
        fileInfo.absolutePath(), targetUuid, transferPort);
}

QString MainWindow::fileTransferDestinationHost()
{
    const QString savedDestination = normalizeFileTransferHost(m_Settings.value("lastFileTransferDestinationHost").toString());
    if (!savedDestination.isEmpty()) {
        return savedDestination;
    }

    if (app_role() == AppRole::Client) {
        const QString hostname = normalizeFileTransferHost(ui_->m_pLineEditHostname->text());
        if (!hostname.isEmpty()) {
            return hostname;
        }

        const QString autoConfigHost = normalizeFileTransferHost(ui_->m_pComboServerList->currentText());
        if (ui_->m_pComboServerList->isVisible() && !autoConfigHost.isEmpty()) {
            return autoConfigHost;
        }
    }

    if (app_role() == AppRole::Server && !m_LastConnectedClientHost.isEmpty()) {
        return m_LastConnectedClientHost;
    }

    return QString();
}

QString MainWindow::normalizeFileTransferHost(const QString& host)
{
    QString normalizedHost = host.trimmed();
    if (normalizedHost.startsWith("::ffff:", Qt::CaseInsensitive)) {
        normalizedHost = normalizedHost.mid(7);
    }

    return normalizedHost;
}

QString MainWindow::promptFileTransferDestinationHost(const QString& title)
{
    const QString suggestedHost = fileTransferDestinationHost();
    if (!suggestedHost.isEmpty()) {
        rememberFileTransferDestinationHost(suggestedHost);
    }

    QDialog dialog(this);
    dialog.setWindowTitle(title);

    auto* layout = new QVBoxLayout(&dialog);
    modernizeUtilityDialog(dialog, *layout, tr("Escolha o destino"),
                           tr("Selecione o computador que receberá esta transferência."));
    auto* label = new QLabel(tr("Computador de destino:"), &dialog);
    label->setWordWrap(true);

    auto* destinationCombo = new QComboBox(&dialog);
    destinationCombo->setEditable(true);
    destinationCombo->setInsertPolicy(QComboBox::NoInsert);
    if (m_DiscoveredDevicesModel) {
        for (const auto& device : m_DiscoveredDevicesModel->devices()) {
            if (device.addresses.isEmpty()) continue;
            QStringList endpoints=device.addresses.values(); endpoints.sort();
            destinationCombo->addItem(device.displayName, endpoints.first());
        }
    }
    for (const QString& host : m_FileTransferDestinationHosts)
        if (destinationCombo->findData(host) < 0) destinationCombo->addItem(host, host);
    const int suggestedIndex=destinationCombo->findData(suggestedHost);
    if (suggestedIndex >= 0) destinationCombo->setCurrentIndex(suggestedIndex); else destinationCombo->setEditText(suggestedHost);
    destinationCombo->setAccessibleName(tr("Computador de destino"));
    destinationCombo->lineEdit()->setPlaceholderText(tr("Endereço IP ou nome do computador"));

    auto* hintLabel = new QLabel(tr("Use o endereço IP ou o nome do computador que receberá os arquivos."), &dialog);
    hintLabel->setWordWrap(true);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Continuar"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancelar"));
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    layout->addWidget(label);
    layout->addWidget(destinationCombo);
    layout->addWidget(hintLabel);
    layout->addWidget(buttons);

    if (dialog.exec() != QDialog::Accepted) {
        return QString();
    }

    QString selectedEndpoint = destinationCombo->currentText();
    if (destinationCombo->currentIndex() >= 0 && destinationCombo->currentText() == destinationCombo->itemText(destinationCombo->currentIndex()))
        selectedEndpoint = destinationCombo->currentData().toString();
    const QString host = normalizeFileTransferHost(selectedEndpoint);
    if (host.isEmpty()) {
        QMessageBox::information(this, title, tr("Informe o endereço IP ou o nome do computador de destino."));
        return QString();
    }

    rememberFileTransferDestinationHost(host);
    return host;
}

void MainWindow::rememberFileTransferDestinationHost(const QString& host)
{
    if (!m_RuntimeConsumersEnabled) return;
    const QString normalizedHost = normalizeFileTransferHost(host);
    if (normalizedHost.isEmpty()) {
        return;
    }

    m_FileTransferDestinationHosts.removeAll(normalizedHost);
    m_FileTransferDestinationHosts.prepend(normalizedHost);
    while (m_FileTransferDestinationHosts.size() > 10) {
        m_FileTransferDestinationHosts.removeLast();
    }

    m_Settings.setValue("lastFileTransferDestinationHost", normalizedHost);
    m_Settings.setValue("fileTransferDestinationHosts", m_FileTransferDestinationHosts);
}

bool MainWindow::confirmFileTransferDestinationReachable(const QString& host)
{
    const QString normalizedHost = normalizeFileTransferHost(host);
    setStatus(tr("Testing file transfer connection to %1:%2...").arg(normalizedHost).arg(FILE_TRANSFER_PORT));

    QTcpSocket socket;
    socket.connectToHost(normalizedHost, FILE_TRANSFER_PORT);
    const bool connected = socket.waitForConnected(2500);
    if (connected) {
        socket.disconnectFromHost();
        appendLogInfo(tr("file transfer destination %1:%2 is reachable").arg(normalizedHost).arg(FILE_TRANSFER_PORT));
        return true;
    }

    const QString errorMessage = tr(
        "The computer %1 is not accepting file transfers on port %2.\n\n"
        "Mouse and keyboard can still work on port 24800, but file transfer needs the InputLeap GUI open on the destination and listening on port %2."
    ).arg(normalizedHost).arg(FILE_TRANSFER_PORT);

    appendLogError(tr("file transfer preflight failed for %1:%2 - %3")
        .arg(normalizedHost)
        .arg(FILE_TRANSFER_PORT)
        .arg(socket.errorString()));
    setStatus(tr("File transfer destination is not reachable."));
    QMessageBox::warning(this, tr("File transfer unavailable"), errorMessage);
    return false;
}

void MainWindow::openLastReceivedFilesFolder()
{
    if (!m_ReceivedFileNotificationOpenable || m_LastReceivedFilesFolder.isEmpty()) {
        return;
    }

    QDesktopServices::openUrl(QUrl::fromLocalFile(m_LastReceivedFilesFolder));
}

void MainWindow::openReceiveFilesFolder()
{
    const QString receiveDirectory = m_pFileTransferService != nullptr
        ? m_pFileTransferService->receiveDirectory()
        : QDir::homePath();
    QDir dir(receiveDirectory);
    if (!dir.exists()) {
        dir.mkpath(".");
    }

    if (!QDesktopServices::openUrl(QUrl::fromLocalFile(dir.absolutePath()))) {
        QMessageBox::warning(this, tr("Open receive folder"), tr("Could not open receive folder: %1").arg(dir.absolutePath()));
    }
}

void MainWindow::showReceivedFileNotification(const QString& fileName,
                                              const QString& destinationPath,
                                              const QString& message,
                                              bool verified,
                                              const QUuid& peerUuid)
{
    const bool openAutomatically = verified &&
        deviceAllows(peerUuid, DevicePermissions::OpenSafeFiles, tr("abrir arquivos recebidos")) &&
        FileTransferService::isSafeToOpenAutomatically(fileName);
    if (m_pTrayIcon != nullptr && m_pTrayIcon->isVisible()) {
        m_pTrayIcon->showMessage(
            tr("File received"),
            !verified
                ? tr("%1\\nVerification failed. The file was not opened automatically.").arg(message)
                : openAutomatically
                    ? tr("%1\\nOpening automatically.").arg(message)
                    : tr("%1\\nAutomatic opening is disabled for this file type.").arg(message),
            QSystemTrayIcon::Information,
            10000);
    }

    if (openAutomatically) {
        if (!QDesktopServices::openUrl(QUrl::fromLocalFile(destinationPath))) {
            appendLogError(tr("could not open received file automatically: %1").arg(destinationPath));
        }
    }
    else if (verified) {
        appendLogInfo(tr("received file was not opened automatically because its type is blocked: %1").arg(destinationPath));
    }
    (void)fileName;
}

QByteArray MainWindow::trackTransferController(FileTransferController* controller,
                                               const QByteArray& queueId)
{
    const QByteArray key = queueId.isEmpty()
        ? QUuid::createUuid().toRfc4122() : queueId;
    m_TransferControllers.insert(key, controller);
    return key;
}

void MainWindow::startFileTransfer(const QString& host,
                                   const QList<FileTransferService::TransferItem>& items,
                                   const QString& title,
                                   const QString& successMessage,
                                   const QString& failureTitle,
                                   const QString& cancelledTitle,
                                   const QString& historyName,
                                   const QString& historyPath,
                                   const QUuid& deviceUuid,
                                   quint16 transferPort,
                                   const QByteArray& queueId,
                                   quint64 queueGeneration)
{
    if (m_UpdateTransferBarrierActive || m_TransferQueueShuttingDown) {
        if (!queueId.isEmpty() && m_TransferQueue)
            m_TransferQueue->finish(
                queueId, queueGeneration, TransferQueue::State::FailedRetryable);
        setStatus(tr("Transferências pausadas enquanto a atualização é preparada."));
        return;
    }
    if (!deviceAllows(deviceUuid, DevicePermissions::SendFiles, tr("enviar arquivos"))) {
        if (!queueId.isEmpty() && m_TransferQueue)
            m_TransferQueue->finish(queueId, queueGeneration, TransferQueue::State::FailedRetryable);
        return;
    }
    if (transferPort == 0) transferPort = FILE_TRANSFER_PORT;
    QString effectiveHost = host;
    QString destinationLabel = host;
    QList<DeviceInfo> endpointMatches;
    const QString normalizedHost = normalizeFileTransferHost(host);
    for (const auto& device : m_DeviceRegistry.devices()) {
        if (normalizeFileTransferHost(device.technicalName()).compare(normalizedHost, Qt::CaseInsensitive) == 0 ||
            device.ipAddresses().contains(normalizedHost, Qt::CaseInsensitive))
            endpointMatches.append(device);
    }
    if (endpointMatches.size() == 1)
        destinationLabel = DeviceDisplayNameResolver(m_DeviceRegistry).resolve(endpointMatches.first().uuid(), host);
    QUuid peerUuid=deviceUuid;
    bool resumeEnabled=false;
    bool conflictProtocolEnabled=false;
    if(peerUuid.isNull()&&endpointMatches.size()==1) {
        const auto discovered=m_DiscoveredDevicesModel->find(endpointMatches.first().uuid());
        if(discovered && (discovered->addresses.contains(normalizedHost) ||
           normalizeFileTransferHost(discovered->technicalName).compare(normalizedHost,Qt::CaseInsensitive)==0))
            peerUuid=endpointMatches.first().uuid();
    }
    if(!peerUuid.isNull()) {
        const auto current=m_DiscoveredDevicesModel->find(peerUuid);
        if(!current || !current->discoveryAvailable ||
           !(current->state==DeviceConnectionModel::State::Connected||current->state==DeviceConnectionModel::State::Controlling) ||
           !current->capabilities.contains(ZeroconfCapability::FileTransfer) || !current->transferPort ||
           !current->negotiation.capabilityAllowed(CapabilityId::FileTransfer)) {
            QMessageBox::information(this,tr("Atualização necessária"), current ?
                current->negotiation.capability(CapabilityId::FileTransfer).reason : tr("O computador não está mais disponível."));
            return;
        }
        effectiveHost=EndpointPolicy::firstUsable(current->addresses.values());
        if(effectiveHost.isEmpty()) { QMessageBox::information(this,tr("Computador indisponível"),tr("Nenhum endereço seguro está disponível.")); return; }
        transferPort=current->transferPort;
        const auto negotiated=current->negotiation.capability(CapabilityId::FileTransfer).negotiatedVersion;
        resumeEnabled=negotiated && negotiated->major==1 && negotiated->minor>=1;
        conflictProtocolEnabled=negotiated && negotiated->major==1 && negotiated->minor>=2;
    }
    const auto activeTransferUuids = m_EnvironmentProfileIntegrationPolicy.activeTransferUuids();
    const bool transferSlotUnavailable=queueId.isEmpty()?m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers():
        !transferPerformancePolicy().canStartQueuedPeer(peerUuid,activeTransferUuids);
    if(transferSlotUnavailable){
        QMessageBox::information(this,tr("Transferência em andamento"),tr("Aguarde a transferência atual para este computador terminar."));
        return;
    }
    if(queueId.isEmpty()&&!peerUuid.isNull()&&resumeEnabled&&m_TransferQueue){
        QList<TransferQueue::Item> queuedItems;const QDateTime now=QDateTime::currentDateTimeUtc();
        const QByteArray batchId=QUuid::createUuid().toRfc4122();quint32 batchIndex=0;
        for(const auto& source:items){
            TransferQueue::Item queued;queued.transferId=TransferQueue::newTransferId();queued.peerUuid=peerUuid;
            queued.batchId=batchId;queued.batchIndex=batchIndex++;queued.batchCount=quint32(items.size());
            queued.displayName=QFileInfo(source.relativePath).fileName();queued.sources={{QFileInfo(source.sourcePath).absoluteFilePath(),source.relativePath}};
            queued.state=TransferQueue::State::Pending;queued.userEnqueued=true;queued.createdAtUtc=queued.updatedAtUtc=now;queuedItems.append(queued);
        }
        QString queueError;if(!m_TransferQueue->enqueueMany(queuedItems,&queueError)){
            QMessageBox::warning(this,tr("Fila de transferências"),tr("Não foi possível salvar a transferência antes do envio: %1").arg(queueError));return;
        }
        refreshTransferQueueDialog();dispatchNextTransfer();return;
    }

    auto* progress = new QProgressDialog(tr("Preparing transfer..."), tr("Cancel"), 0, 100, this);
    progress->setWindowTitle(title);
    progress->setWindowModality(Qt::WindowModal);
    progress->setMinimumDuration(queueId.isEmpty()?0:std::numeric_limits<int>::max());
    progress->setAttribute(Qt::WA_DeleteOnClose, false);
    if(queueId.isEmpty())progress->show();
    ensureTransferQueueDialog();
    if(queueId.isEmpty())addOrUpdateTransferQueueRow(historyName,destinationLabel,tr("Em andamento"),"0%",tr("Preparando transferência..."),historyPath);

    auto* controller = new FileTransferController(this);
    const QByteArray controllerKey = trackTransferController(controller, queueId);
    auto timer = std::make_shared<QElapsedTimer>();
    timer->start();
    auto currentProgressFile = std::make_shared<QString>();
    auto estimator=std::make_shared<TransferEstimator>();

    if(queueId.isEmpty())connect(progress,&QProgressDialog::canceled,controller,&FileTransferController::cancel);
    else connect(progress,&QProgressDialog::canceled,this,[this,queueId]{cancelQueuedTransfer(queueId,false);});

    connect(controller,&FileTransferController::progress,this,[this,progress,timer,currentProgressFile,estimator,historyName,historyPath,destinationLabel,peerUuid,queueId](const QString& fileName,quint64 bytesDone,quint64 bytesTotal) {
        if (!m_RuntimeConsumersEnabled) return;
        if (m_DeviceDiscoveryPanel != nullptr && !peerUuid.isNull()) m_DeviceDiscoveryPanel->setTransferProgress(peerUuid,fileName,bytesDone,bytesTotal);
        if (*currentProgressFile != fileName || bytesDone == 0) {
            *currentProgressFile = fileName;
            timer->restart();
            *estimator=TransferEstimator();
        }
        const auto estimate=estimator->sample(timer->elapsed(),bytesDone,bytesTotal);
        const QString speed=estimate.bytesPerSecond?tr("%1 MB/s").arg(QString::number(*estimate.bytesPerSecond/1024.0/1024.0,'f',2)):tr("calculando velocidade");
        const QString remaining=estimate.remainingSeconds?formatDuration(qint64(*estimate.remainingSeconds)):tr("calculando tempo restante");
        const QString details=tr("Velocidade: %1 — Tempo restante: %2").arg(speed,remaining);
        const QString message = formatTransferProgress(tr("Sending"), fileName, bytesDone, bytesTotal, details);
        const QString percent = QString::number(bytesTotal == 0 ? 100 : static_cast<int>((bytesDone * 100) / bytesTotal)) + "%";
        setStatus(message);
        appendLogInfo(message);
        progress->setLabelText(message);
        progress->setValue(bytesTotal == 0 ? 100 : static_cast<int>((bytesDone * 100) / bytesTotal));
        if(queueId.isEmpty())addOrUpdateTransferQueueRow(historyName,destinationLabel,tr("Em andamento"),percent,tr("%1\n%2").arg(fileName,details),historyPath);
    });

    connect(controller, &FileTransferController::finished, this,
            [this, progress, controller, host, destinationLabel, successMessage, failureTitle, cancelledTitle, historyName, historyPath, peerUuid,queueId,queueGeneration,controllerKey]
            (bool success,const QString& errorMessage,bool cancelled,bool terminalFailure,
             quint32 transferred,quint32 deduplicated,quint32 skipped) {
        m_EnvironmentProfileIntegrationPolicy.transferFinished(peerUuid);
        m_TransferControllers.remove(controllerKey);
        const auto intent=m_TransferCancelIntents.take(controllerKey);
        if (m_RuntimeConsumersEnabled) refreshEnvironmentProfileUi();
        progress->setValue(100);
        progress->hide();
        progress->deleteLater();
        if (!m_RuntimeConsumersEnabled) {
            controller->deleteLater();
            return;
        }
        if (m_DeviceDiscoveryPanel != nullptr && !peerUuid.isNull()) m_DeviceDiscoveryPanel->finishTransfer(peerUuid,success,errorMessage);

        if(!queueId.isEmpty()&&m_TransferQueue){
            if(success)m_TransferQueue->finish(queueId,queueGeneration,skipped>0?TransferQueue::State::Skipped:TransferQueue::State::Completed);
            else if(intent==TransferCancelIntent::None)m_TransferQueue->finish(queueId,queueGeneration,terminalFailure?TransferQueue::State::FailedTerminal:TransferQueue::State::FailedRetryable);
            if (m_NotificationService) {
                m_NotificationService->publish(
                    success ? QStringLiteral("transfer-completed") : QStringLiteral("transfer-failed"),
                    tr("Transferência"),
                    success ? tr("Transferência concluída.") : tr("A transferência não foi concluída."),
                    success ? NotificationService::Severity::Information
                            : NotificationService::Severity::Warning);
            }
            refreshTransferQueueDialog();controller->deleteLater();
            if(!m_TransferQueueShuttingDown)QTimer::singleShot(0,this,&MainWindow::dispatchNextTransfer);
            return;
        }

        if (success) {
            const QString resultMessage=skipped>0
                ? tr("Transferência encerrada: %1 enviado(s), %2 já confirmado(s) e %3 ignorado(s) pelo destinatário.").arg(transferred).arg(deduplicated).arg(skipped)
                : deduplicated>0&&transferred==0
                    ? tr("O destinatário confirmou que o arquivo já existia com o mesmo conteúdo.") : successMessage;
            const QString resultStatus=skipped>0?tr("Concluída parcialmente"):tr("Concluída");
            setStatus(resultMessage);
            if (m_NotificationService)
                m_NotificationService->publish(
                    QStringLiteral("transfer-completed"), tr("Transferência"), resultMessage);
            addOrUpdateTransferQueueRow(historyName,destinationLabel,resultStatus,"100%",resultMessage,historyPath);
            if (m_pTrayIcon != nullptr && m_pTrayIcon->isVisible()) {
                m_pTrayIcon->showMessage(tr("Transferência encerrada"),resultMessage,QSystemTrayIcon::Information,8000);
            }
            QMessageBox::information(this,tr("Transferência encerrada"),resultMessage);
            addTransferHistoryEntry(tr("Enviado"),historyName,destinationLabel,resultStatus,historyPath);
            appendLogInfo(tr("sent %1 to %2").arg(historyName).arg(host));
        }
        else {
            const QString status = cancelled ? tr("Cancelled") : tr("Failed");
            addOrUpdateTransferQueueRow(historyName, destinationLabel, status, status, errorMessage, historyPath);
            QMessageBox::warning(this, cancelled ? cancelledTitle : failureTitle, errorMessage);
            appendLogError(tr("file transfer failed: %1").arg(errorMessage));
            addTransferHistoryEntry(tr("Sent"), historyName, destinationLabel, status, historyPath);
            setStatus(cancelled ? tr("Transfer cancelled.") : tr("Transfer failed."));
            if (m_NotificationService)
                m_NotificationService->publish(
                    QStringLiteral("transfer-failed"), tr("Transferência"),
                    cancelled ? tr("Transferência cancelada.") : tr("A transferência falhou."),
                    NotificationService::Severity::Warning);
        }

        controller->deleteLater();
    });

    const auto paired=m_PairedSessions.constFind(peerUuid);
    const bool usePairKey=!peerUuid.isNull()&&paired!=m_PairedSessions.cend()&&paired->key.size()==32;
    if(!queueId.isEmpty()&&(!resumeEnabled||!usePairKey)){
        if(m_TransferQueue)m_TransferQueue->finish(queueId,queueGeneration,TransferQueue::State::FailedRetryable);
        m_TransferControllers.remove(controllerKey);
        progress->deleteLater();controller->deleteLater();refreshTransferQueueDialog();QTimer::singleShot(0,this,&MainWindow::dispatchNextTransfer);return;
    }
    m_EnvironmentProfileIntegrationPolicy.transferStarted(peerUuid);
    refreshEnvironmentProfileUi();
    if (!controller->start(effectiveHost,transferPort,items,appConfig().fileTransferPairingCode(),
                           usePairKey?m_LocalDeviceUuid:QUuid(),usePairKey?paired->key:QByteArray(),resumeEnabled&&usePairKey,
                           transferPerformancePolicy().bandwidthBytesPerSecond(),conflictProtocolEnabled&&usePairKey)) {
        m_EnvironmentProfileIntegrationPolicy.transferFinished(peerUuid);
        refreshEnvironmentProfileUi();
        m_TransferControllers.remove(controllerKey);
        if(!queueId.isEmpty()){if(m_TransferQueue)m_TransferQueue->finish(queueId,queueGeneration,TransferQueue::State::FailedRetryable);refreshTransferQueueDialog();}
        progress->deleteLater();
        controller->deleteLater();
        if(queueId.isEmpty())QMessageBox::warning(this, failureTitle, tr("Could not start file transfer."));
        else QTimer::singleShot(0,this,&MainWindow::dispatchNextTransfer);
    }
}

void MainWindow::addTransferHistoryEntry(const QString& direction,
                                         const QString& fileName,
                                         const QString& peer,
                                         const QString& status,
                                         const QString& path)
{
    m_TransferHistory.prepend(QStringList{
        QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"),
        direction,
        fileName,
        peer.isEmpty() ? tr("Local") : peer,
        status,
        path
    });

    while (m_TransferHistory.size() > 100) {
        m_TransferHistory.removeLast();
    }

    saveTransferHistory();
}

void MainWindow::showTransferHistory()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Histórico de transferências"));
    dialog.resize(780, 420);

    auto* layout = new QVBoxLayout(&dialog);
    modernizeUtilityDialog(dialog, *layout, tr("Histórico de transferências"),
                           tr("Consulte, exporte ou limpe as transferências realizadas."));
    auto* table = new QTableWidget(m_TransferHistory.size(), 6, &dialog);
    table->setHorizontalHeaderLabels({
        tr("Time"),
        tr("Direction"),
        tr("File"),
        tr("Peer"),
        tr("Status"),
        tr("Folder")
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->horizontalHeader()->setStretchLastSection(true);

    for (int row = 0; row < m_TransferHistory.size(); ++row) {
        const QStringList entry = m_TransferHistory.at(row);
        for (int column = 0; column < entry.size(); ++column) {
            table->setItem(row, column, new QTableWidgetItem(entry.at(column)));
        }
    }

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fechar"));
    auto* openFolderButton = buttons->addButton(tr("Abrir pasta"), QDialogButtonBox::ActionRole);
    auto* exportHistoryButton = buttons->addButton(tr("Exportar CSV"), QDialogButtonBox::ActionRole);
    auto* clearHistoryButton = buttons->addButton(tr("Limpar histórico"), QDialogButtonBox::ActionRole);
    openFolderButton->setEnabled(!m_TransferHistory.isEmpty());
    exportHistoryButton->setEnabled(!m_TransferHistory.isEmpty());
    clearHistoryButton->setEnabled(!m_TransferHistory.isEmpty());

    connect(openFolderButton, &QPushButton::clicked, &dialog, [table]() {
        const int row = table->currentRow() >= 0 ? table->currentRow() : 0;
        const auto* item = table->item(row, 5);
        if (item != nullptr && !item->text().isEmpty()) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(item->text()));
        }
    });
    connect(exportHistoryButton, &QPushButton::clicked, &dialog, [this]() {
        const QString fileName = QFileDialog::getSaveFileName(
            this,
            tr("Export transfer history"),
            QDir::home().filePath("inputleap-transfer-history.csv"),
            tr("CSV files (*.csv)"));
        if (fileName.isEmpty()) {
            return;
        }

        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, tr("Export transfer history"), tr("Could not write transfer history: %1").arg(fileName));
            return;
        }

        auto csvEscape = [](QString value) {
            value.replace("\"", "\"\"");
            if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
                value = QString("\"%1\"").arg(value);
            }
            return value;
        };

        QTextStream out(&file);
        out << csvEscape(tr("Time")) << ","
            << csvEscape(tr("Direction")) << ","
            << csvEscape(tr("File")) << ","
            << csvEscape(tr("Peer")) << ","
            << csvEscape(tr("Status")) << ","
            << csvEscape(tr("Folder")) << "\n";
        for (const QStringList& entry : m_TransferHistory) {
            out << csvEscape(entry.value(0)) << ","
                << csvEscape(entry.value(1)) << ","
                << csvEscape(entry.value(2)) << ","
                << csvEscape(entry.value(3)) << ","
                << csvEscape(entry.value(4)) << ","
                << csvEscape(entry.value(5)) << "\n";
        }
        QMessageBox::information(this, tr("Export transfer history"), tr("Transfer history exported to %1.").arg(fileName));
    });
    connect(clearHistoryButton, &QPushButton::clicked, &dialog, [this, table, openFolderButton, exportHistoryButton, clearHistoryButton]() {
        if (QMessageBox::question(
                this,
                tr("Clear transfer history"),
                tr("Clear all saved file transfer history?"),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes) {
            return;
        }

        m_TransferHistory.clear();
        saveTransferHistory();
        table->setRowCount(0);
        openFolderButton->setEnabled(false);
        exportHistoryButton->setEnabled(false);
        clearHistoryButton->setEnabled(false);
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    layout->addWidget(table);
    layout->addWidget(buttons);
    dialog.exec();
}

void MainWindow::showClipboardHistory()
{
    ClipboardHistoryDialog dialog(m_ClipboardHistoryModel.get(), QGuiApplication::clipboard(), this);
    dialog.exec();
    m_pActionClipboardHistory->setChecked(m_ClipboardHistoryModel->isEnabled());
}

void MainWindow::showRecentReceivedFiles()
{
    QList<QStringList> receivedEntries;
    for (const QStringList& entry : m_TransferHistory) {
        if (entry.value(1) == tr("Received")) {
            receivedEntries.append(entry);
        }
    }

    QDialog dialog(this);
    dialog.setWindowTitle(tr("Recebimentos recentes"));
    dialog.resize(820, 420);

    auto* layout = new QVBoxLayout(&dialog);
    modernizeUtilityDialog(dialog, *layout, tr("Arquivos recebidos recentemente"),
                           tr("Acesse rapidamente os últimos arquivos recebidos."));
    auto* table = new QTableWidget(receivedEntries.size(), 6, &dialog);
    table->setHorizontalHeaderLabels({
        tr("Time"),
        tr("File"),
        tr("From"),
        tr("Status"),
        tr("Folder"),
        tr("Path")
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setColumnHidden(5, true);
    table->horizontalHeader()->setStretchLastSection(true);

    for (int row = 0; row < receivedEntries.size(); ++row) {
        const QStringList entry = receivedEntries.at(row);
        const QString folder = entry.value(5);
        const QString filePath = folder.isEmpty() ? QString() : QDir(folder).filePath(entry.value(2));
        table->setItem(row, 0, new QTableWidgetItem(entry.value(0)));
        table->setItem(row, 1, new QTableWidgetItem(entry.value(2)));
        table->setItem(row, 2, new QTableWidgetItem(entry.value(3)));
        table->setItem(row, 3, new QTableWidgetItem(entry.value(4)));
        table->setItem(row, 4, new QTableWidgetItem(folder));
        table->setItem(row, 5, new QTableWidgetItem(filePath));
    }

    auto selectedPath = [table]() {
        const int row = table->currentRow() >= 0 ? table->currentRow() : 0;
        const auto* item = table->item(row, 5);
        return item != nullptr ? item->text() : QString();
    };

    auto selectedFolder = [table]() {
        const int row = table->currentRow() >= 0 ? table->currentRow() : 0;
        const auto* item = table->item(row, 4);
        return item != nullptr ? item->text() : QString();
    };

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fechar"));
    auto* openFileButton = buttons->addButton(tr("Abrir arquivo"), QDialogButtonBox::ActionRole);
    auto* openFolderButton = buttons->addButton(tr("Abrir pasta"), QDialogButtonBox::ActionRole);
    auto* copyPathButton = buttons->addButton(tr("Copiar caminho"), QDialogButtonBox::ActionRole);
    const bool hasReceivedFiles = !receivedEntries.isEmpty();
    openFileButton->setEnabled(hasReceivedFiles);
    openFolderButton->setEnabled(hasReceivedFiles);
    copyPathButton->setEnabled(hasReceivedFiles);

    connect(openFileButton, &QPushButton::clicked, &dialog, [this, selectedPath]() {
        const QString path = selectedPath();
        if (path.isEmpty() || !QFileInfo::exists(path)) {
            QMessageBox::information(this, tr("Abrir arquivo"), tr("The selected received file is no longer available."));
            return;
        }
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    connect(openFolderButton, &QPushButton::clicked, &dialog, [this, selectedFolder]() {
        const QString folder = selectedFolder();
        if (folder.isEmpty() || !QDir(folder).exists()) {
            QMessageBox::information(this, tr("Abrir pasta"), tr("The selected receive folder is no longer available."));
            return;
        }
        QDesktopServices::openUrl(QUrl::fromLocalFile(folder));
    });
    connect(copyPathButton, &QPushButton::clicked, &dialog, [selectedPath]() {
        QApplication::clipboard()->setText(selectedPath());
    });
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    layout->addWidget(table);
    layout->addWidget(buttons);
    dialog.exec();
}

void MainWindow::showTransferQueue()
{
    if (!m_RuntimeConsumersEnabled) return;
    ensureTransferQueueDialog();
    m_pTransferQueueDialog->show();
    m_pTransferQueueDialog->raise();
    m_pTransferQueueDialog->activateWindow();
}

void MainWindow::ensureTransferQueueDialog()
{
    if (m_pTransferQueueDialog != nullptr) {
        return;
    }

    m_pTransferQueueDialog = new QDialog(this);
    m_pTransferQueueDialog->setWindowTitle(tr("Fila de transferências"));
    m_pTransferQueueDialog->resize(920, 420);
    m_pTransferQueueDialog->setAttribute(Qt::WA_DeleteOnClose, false);

    auto* layout = new QVBoxLayout(m_pTransferQueueDialog);
    modernizeUtilityDialog(*m_pTransferQueueDialog, *layout, tr("Fila de transferências"),
                           tr("Acompanhe e controle os arquivos aguardando envio."));
    m_pTransferQueueTable = new QTableWidget(0, 6, m_pTransferQueueDialog);
    m_pTransferQueueTable->setHorizontalHeaderLabels({
        tr("Nome"),
        tr("Computador"),
        tr("Estado"),
        tr("Progresso"),
        tr("Detalhes"),
        tr("Pasta")
    });
    m_pTransferQueueTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pTransferQueueTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_pTransferQueueTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_pTransferQueueTable->setColumnHidden(5, true);
    m_pTransferQueueTable->horizontalHeader()->setStretchLastSection(true);

    auto* advancedToggle=new QCheckBox(tr("Mostrar opções avançadas de desempenho"),m_pTransferQueueDialog);
    auto* performanceGroup=new QGroupBox(tr("Desempenho da rede local"),m_pTransferQueueDialog);performanceGroup->setVisible(false);
    auto* performanceForm=new QFormLayout(performanceGroup);
    auto* concurrentSpin=new QSpinBox(performanceGroup);concurrentSpin->setRange(1,PerformancePolicy::MaximumConcurrentTransfers);concurrentSpin->setValue(transferPerformancePolicy().maxConcurrent());
    concurrentSpin->setAccessibleDescription(tr("Permite no máximo duas transferências simultâneas, sempre para computadores diferentes."));
    auto* bandwidthSpin=new QSpinBox(performanceGroup);bandwidthSpin->setRange(0,1024);bandwidthSpin->setValue(m_Settings.value(QStringLiteral("transfer/performance/bandwidthMiB"),0).toInt());
    bandwidthSpin->setSuffix(tr(" MB/s"));bandwidthSpin->setSpecialValueText(tr("Sem limite"));bandwidthSpin->setAccessibleDescription(tr("Zero mantém a velocidade sem limite artificial."));
    performanceForm->addRow(tr("Transferências simultâneas:"),concurrentSpin);performanceForm->addRow(tr("Limite de banda:"),bandwidthSpin);
    connect(advancedToggle,&QCheckBox::toggled,performanceGroup,&QWidget::setVisible);
    connect(concurrentSpin,qOverload<int>(&QSpinBox::valueChanged),this,[this](int value){if(!m_RuntimeConsumersEnabled)return;m_Settings.setValue(QStringLiteral("transfer/performance/maxConcurrent"),value);m_Settings.sync();dispatchNextTransfer();});
    connect(bandwidthSpin,qOverload<int>(&QSpinBox::valueChanged),this,[this](int value){if(!m_RuntimeConsumersEnabled)return;m_Settings.setValue(QStringLiteral("transfer/performance/bandwidthMiB"),value);m_Settings.sync();});

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, m_pTransferQueueDialog);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fechar"));
    auto* openFolderButton = buttons->addButton(tr("Abrir pasta"), QDialogButtonBox::ActionRole);
    auto* pauseButton = buttons->addButton(tr("Pausar"),QDialogButtonBox::ActionRole);
    auto* continueButton = buttons->addButton(tr("Continuar"),QDialogButtonBox::ActionRole);
    auto* repeatButton = buttons->addButton(tr("Repetir"),QDialogButtonBox::ActionRole);
    auto* cancelButton = buttons->addButton(tr("Cancelar"),QDialogButtonBox::ActionRole);
    auto selectedId=[this]{const int row=m_pTransferQueueTable?m_pTransferQueueTable->currentRow():-1;return row>=0?m_pTransferQueueTable->item(row,0)->data(Qt::UserRole).toByteArray():QByteArray();};
    connect(pauseButton,&QPushButton::clicked,m_pTransferQueueDialog,[this,selectedId]{cancelQueuedTransfer(selectedId(),true);});
    connect(cancelButton,&QPushButton::clicked,m_pTransferQueueDialog,[this,selectedId]{cancelQueuedTransfer(selectedId(),false);});
    connect(continueButton,&QPushButton::clicked,m_pTransferQueueDialog,[this,selectedId]{const QByteArray id=selectedId();m_TransferCancelIntents.remove(id);QString error;if(m_TransferQueue&&m_TransferQueue->continueItem(id,&error)){refreshTransferQueueDialog();dispatchNextTransfer();}else if(!error.isEmpty())setStatus(error);});
    connect(repeatButton,&QPushButton::clicked,m_pTransferQueueDialog,[this,selectedId]{QString error;if(m_TransferQueue&&m_TransferQueue->repeat(selectedId(),&error)){refreshTransferQueueDialog();dispatchNextTransfer();}else if(!error.isEmpty())setStatus(error);});
    auto updateActions=[this,pauseButton,continueButton,repeatButton,cancelButton,selectedId]{const auto queued=m_TransferQueue?m_TransferQueue->find(selectedId()):std::nullopt;
        pauseButton->setEnabled(queued&&(queued->state==TransferQueue::State::Running||queued->state==TransferQueue::State::Pending||queued->state==TransferQueue::State::FailedRetryable));
        continueButton->setEnabled(queued&&queued->state==TransferQueue::State::Paused);
        repeatButton->setEnabled(queued&&(queued->state==TransferQueue::State::FailedTerminal||queued->state==TransferQueue::State::FailedRetryable||queued->state==TransferQueue::State::Cancelled||queued->state==TransferQueue::State::Skipped));
        cancelButton->setEnabled(queued&&queued->state!=TransferQueue::State::Completed&&queued->state!=TransferQueue::State::Cancelled&&queued->state!=TransferQueue::State::Skipped);};
    connect(m_pTransferQueueTable,&QTableWidget::itemSelectionChanged,m_pTransferQueueDialog,updateActions);updateActions();
    connect(openFolderButton, &QPushButton::clicked, m_pTransferQueueDialog, [this]() {
        if (m_pTransferQueueTable == nullptr || m_pTransferQueueTable->rowCount() == 0) {
            return;
        }

        const int row = m_pTransferQueueTable->currentRow() >= 0 ? m_pTransferQueueTable->currentRow() : 0;
        const auto* folderItem = m_pTransferQueueTable->item(row, 5);
        if (folderItem == nullptr || folderItem->text().isEmpty()) {
            QMessageBox::information(this, tr("Abrir pasta"), tr("Nenhuma pasta está disponível para a transferência selecionada."));
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(folderItem->text()));
    });
    connect(buttons,&QDialogButtonBox::rejected,m_pTransferQueueDialog,&QDialog::hide);

    layout->addWidget(m_pTransferQueueTable);
    layout->addWidget(advancedToggle);
    layout->addWidget(performanceGroup);
    layout->addWidget(buttons);
    refreshTransferQueueDialog();
}

void MainWindow::refreshTransferQueueDialog()
{
    if(!m_TransferQueue||m_pTransferQueueTable==nullptr)return;
    m_pTransferQueueTable->setRowCount(0);DeviceDisplayNameResolver names(m_DeviceRegistry);
    const auto label=[](TransferQueue::State state){switch(state){
        case TransferQueue::State::Pending:return QObject::tr("Aguardando");case TransferQueue::State::Running:return QObject::tr("Enviando");
        case TransferQueue::State::Paused:return QObject::tr("Pausada");case TransferQueue::State::Completed:return QObject::tr("Concluída");
        case TransferQueue::State::FailedRetryable:return QObject::tr("Falha temporária");case TransferQueue::State::FailedTerminal:return QObject::tr("Precisa de atenção");
        case TransferQueue::State::Cancelled:return QObject::tr("Cancelada");case TransferQueue::State::Skipped:return QObject::tr("Ignorada pelo destinatário");}return QObject::tr("Desconhecida");};
    for(const auto& queued:m_TransferQueue->items()){
        const int row=m_pTransferQueueTable->rowCount();m_pTransferQueueTable->insertRow(row);
        for(int column=0;column<6;++column)m_pTransferQueueTable->setItem(row,column,new QTableWidgetItem());
        QString status=label(queued.state);QString detail;
        const auto session=m_PairedSessions.constFind(queued.peerUuid);const bool validSession=session!=m_PairedSessions.cend()&&session->key.size()==32;
        if((queued.state==TransferQueue::State::Pending||queued.state==TransferQueue::State::FailedRetryable)&&!validSession){
            status=tr("Aguardando pareamento nesta sessão");detail=tr("Pareie novamente este computador para continuar com segurança.");
        }
        m_pTransferQueueTable->item(row,0)->setText(queued.displayName);m_pTransferQueueTable->item(row,0)->setData(Qt::UserRole,queued.transferId);
        m_pTransferQueueTable->item(row,1)->setText(names.resolve(queued.peerUuid,tr("Outro computador")));
        m_pTransferQueueTable->item(row,2)->setText(status);m_pTransferQueueTable->item(row,3)->setText(queued.state==TransferQueue::State::Completed?QStringLiteral("100%") : QString());
        m_pTransferQueueTable->item(row,4)->setText(detail);m_pTransferQueueTable->item(row,5)->setText(QFileInfo(queued.sources.front().sourcePath).absolutePath());
    }
    m_pTransferQueueTable->resizeRowsToContents();
}

PerformancePolicy MainWindow::transferPerformancePolicy() const
{
    const int concurrent=m_Settings.value(QStringLiteral("transfer/performance/maxConcurrent"),1).toInt();
    const quint64 mib=m_Settings.value(QStringLiteral("transfer/performance/bandwidthMiB"),0).toULongLong();
    return PerformancePolicy(concurrent,mib==0?0:qMin<quint64>(mib,1024)*1024ull*1024ull);
}

void MainWindow::dispatchNextTransfer()
{
    if(!m_RuntimeConsumersEnabled||m_TransferQueueShuttingDown||
       !m_TransferQueue||!m_DiscoveredDevicesModel)return;
    const PerformancePolicy policy=transferPerformancePolicy();
    const auto activeTransferUuids = m_EnvironmentProfileIntegrationPolicy.activeTransferUuids();
    if(activeTransferUuids.contains(QUuid())||m_TransferControllers.size()>=policy.maxConcurrent())return;
    for(const auto& queued:m_TransferQueue->items()){
        if(!queued.userEnqueued||(queued.state!=TransferQueue::State::Pending&&queued.state!=TransferQueue::State::FailedRetryable))continue;
        const auto& source=queued.sources.front();QFileInfo info(source.sourcePath);
        if(!info.exists()||!info.isFile()||info.isSymLink()){
            quint64 generation=0;if(m_TransferQueue->markRunning(queued.transferId,&generation))m_TransferQueue->finish(queued.transferId,generation,TransferQueue::State::FailedTerminal);
        }
    }
    while(m_TransferControllers.size()<policy.maxConcurrent()){
        const auto next=m_TransferQueue->nextEligibleConcurrent([this,&policy](const TransferQueue::Item& queued){
            if(!policy.canStartQueuedPeer(queued.peerUuid,m_EnvironmentProfileIntegrationPolicy.activeTransferUuids()))return false;
            const auto session=m_PairedSessions.constFind(queued.peerUuid);if(queued.attempts>=3||session==m_PairedSessions.cend()||session->key.size()!=32)return false;
            const auto device=m_DiscoveredDevicesModel->find(queued.peerUuid);if(!device||!device->discoveryAvailable||
                !(device->state==DeviceConnectionModel::State::Connected||device->state==DeviceConnectionModel::State::Controlling)||
                !device->capabilities.contains(ZeroconfCapability::FileTransfer)||!device->transferPort)return false;
            const auto version=device->negotiation.capability(CapabilityId::FileTransfer).negotiatedVersion;
            return device->negotiation.capabilityAllowed(CapabilityId::FileTransfer)&&version&&version->major==1&&version->minor>=1&&
                !EndpointPolicy::firstUsable(device->addresses.values()).isEmpty();
        });
        if(!next)break;
        const auto device=m_DiscoveredDevicesModel->find(next->peerUuid);if(!device)break;
        quint64 generation=0;if(!m_TransferQueue->markRunning(next->transferId,&generation))break;
        const auto source=next->sources.front();QList<FileTransferService::TransferItem> transferItems{{source.sourcePath,source.relativePath,next->transferId,next->batchId,next->batchIndex,next->batchCount}};
        refreshTransferQueueDialog();
        startFileTransfer(EndpointPolicy::firstUsable(device->addresses.values()),transferItems,tr("Transferência em fila"),tr("Transferência concluída."),
            tr("Falha na transferência"),tr("Transferência cancelada"),next->displayName,QFileInfo(source.sourcePath).absolutePath(),next->peerUuid,device->transferPort,next->transferId,generation);
        if(!m_TransferControllers.contains(next->transferId))break;
    }
    refreshTransferQueueDialog();
}

void MainWindow::cancelQueuedTransfer(const QByteArray& transferId,bool pause)
{
    if(!m_RuntimeConsumersEnabled||!m_TransferQueue||transferId.isEmpty())return;QString error;
    const bool changed=pause?m_TransferQueue->pause(transferId,&error):m_TransferQueue->cancel(transferId,&error);
    if(!changed){if(!error.isEmpty())setStatus(error);return;}
    if(const auto controller=m_TransferControllers.value(transferId)){
        m_TransferCancelIntents[transferId]=pause?TransferCancelIntent::Pause:TransferCancelIntent::Cancel;controller->cancel();
    }else{
        m_TransferCancelIntents.remove(transferId);QTimer::singleShot(0,this,&MainWindow::dispatchNextTransfer);
    }
    refreshTransferQueueDialog();
}

void MainWindow::addOrUpdateTransferQueueRow(const QString& name,
                                             const QString& peer,
                                             const QString& status,
                                             const QString& progress,
                                             const QString& details,
                                             const QString& folder)
{
    ensureTransferQueueDialog();

    int row = -1;
    for (int i = 0; i < m_pTransferQueueTable->rowCount(); ++i) {
        const auto* nameItem = m_pTransferQueueTable->item(i, 0);
        const auto* peerItem = m_pTransferQueueTable->item(i, 1);
        if (nameItem != nullptr && peerItem != nullptr &&
            nameItem->text() == name && peerItem->text() == peer) {
            row = i;
            break;
        }
    }

    if (row == -1) {
        row = m_pTransferQueueTable->rowCount();
        m_pTransferQueueTable->insertRow(row);
        for (int column = 0; column < 6; ++column) {
            m_pTransferQueueTable->setItem(row, column, new QTableWidgetItem());
        }
    }

    m_pTransferQueueTable->item(row, 0)->setText(name);
    m_pTransferQueueTable->item(row, 1)->setText(peer);
    m_pTransferQueueTable->item(row, 2)->setText(status);
    m_pTransferQueueTable->item(row, 3)->setText(progress);
    m_pTransferQueueTable->item(row, 4)->setText(details);
    m_pTransferQueueTable->item(row, 5)->setText(folder);
    m_pTransferQueueTable->resizeRowsToContents();
}

void MainWindow::showDiagnostics()
{
    QDialog dialog(this);
    dialog.setWindowTitle(tr("Diagnóstico"));
    dialog.resize(760, 500);
    dialog.setStyleSheet(
        "QDialog { background: #f5f7fa; }"
        "QFrame#diagnosticsHeader { background: #0f172a; border-radius: 11px; }"
        "QLabel#diagnosticsTitle { color: #f8fafc; font-size: 16px; font-weight: 700; }"
        "QLabel#diagnosticsSubtitle { color: #94a3b8; }"
        "QTableWidget { background: #ffffff; alternate-background-color: #f8fafc; border: 1px solid #d5deea; border-radius: 8px; gridline-color: #e2e8f0; selection-background-color: #dbeafe; selection-color: #1e3a8a; }"
        "QHeaderView::section { background: #eef2f7; color: #334155; border: none; border-bottom: 1px solid #cbd5e1; padding: 8px; font-weight: 700; }"
        "QPushButton { background: #ffffff; color: #334155; border: 1px solid #aab4c3; border-radius: 6px; padding: 8px 16px; font-weight: 600; }"
        "QPushButton:hover { background: #eef4ff; border-color: #7aa2e3; }"
    );

    auto* layout = new QVBoxLayout(&dialog);
    auto* header = new QFrame(&dialog);
    header->setObjectName("diagnosticsHeader");
    auto* headerLayout = new QVBoxLayout(header);
    headerLayout->setContentsMargins(18, 13, 18, 13);
    headerLayout->setSpacing(2);
    auto* title = new QLabel(tr("Diagnóstico do sistema"), header);
    title->setObjectName("diagnosticsTitle");
    auto* subtitle = new QLabel(tr("Confira rapidamente o estado da conexão e das transferências."), header);
    subtitle->setObjectName("diagnosticsSubtitle");
    headerLayout->addWidget(title);
    headerLayout->addWidget(subtitle);
    layout->addWidget(header);
    auto* table = new QTableWidget(0, 4, &dialog);
    table->setHorizontalHeaderLabels({tr("Item"), tr("Status"), tr("Mensagem"), tr("Detalhe técnico")});
    table->setColumnHidden(3, true);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);

    auto* detailsToggle = new QCheckBox(tr("Mostrar detalhes técnicos"), &dialog);
    connect(detailsToggle, &QCheckBox::toggled, table, [table](bool visible) { table->setColumnHidden(3, !visible); });

    DiagnosticsInput diagnosticInput;
    const auto selected = m_DiscoveredDevicesModel && !m_DashboardDeviceUuid.isNull()
        ? m_DiscoveredDevicesModel->find(m_DashboardDeviceUuid) : std::nullopt;
    if (selected) {
        diagnosticInput.deviceSelected = true;
        diagnosticInput.deviceUuid = selected->uuid;
        diagnosticInput.endpoint = EndpointPolicy::firstUsable(selected->addresses.values());
        diagnosticInput.controlPort = selected->controlPort;
        diagnosticInput.transferPort = selected->transferPort;
        diagnosticInput.discovered = selected->discoveryAvailable;
        diagnosticInput.compatible = selected->compatible;
        diagnosticInput.version = selected->version;
        const bool transferNegotiated=selected->negotiation.capabilityAllowed(CapabilityId::FileTransfer);
        diagnosticInput.fileTransferCapability = transferNegotiated && selected->capabilities.contains(ZeroconfCapability::FileTransfer);
        diagnosticInput.tlsPskCapability = transferNegotiated && selected->features.contains(QStringLiteral("tls-psk"));
        diagnosticInput.hasPairSessionKey = m_PairedSessions.contains(selected->uuid);
    }
    else {
        // Sem dispositivo selecionado não atribuímos capacidades ou compatibilidade
        // com base em configuração local: isso não comprova o estado remoto.
        diagnosticInput.deviceSelected = false;
    }
    diagnosticInput.receiveFolder = appConfig().receiveDirectory().isEmpty()
        ? m_pFileTransferService->receiveDirectory() : appConfig().receiveDirectory();

    auto* privateMode = new QCheckBox(tr("Modo privado (recomendado)"), &dialog);
    privateMode->setChecked(true);
    privateMode->setAccessibleDescription(tr("Remove endereços, nomes de computadores e outros identificadores do relatório."));
    auto* reportPreview = new QPlainTextEdit(&dialog);
    reportPreview->setReadOnly(true);
    reportPreview->setMinimumHeight(170);
    reportPreview->setAccessibleName(tr("Pré-visualização do relatório de suporte"));
    auto* copyReport = new QPushButton(tr("Copiar relatório"), &dialog);
    copyReport->setAccessibleName(tr("Copiar relatório de suporte para a área de transferência"));
    auto* copyConfirmation = new QLabel(&dialog);
    copyConfirmation->setAccessibleName(tr("Estado da cópia do relatório"));
    auto reportSnapshot = std::make_shared<SupportReportSnapshot>();
    reportSnapshot->appVersion = QStringLiteral(INPUTLEAP_VERSION);
    reportSnapshot->osProductType = QSysInfo::productType();
    reportSnapshot->osProductVersion = QSysInfo::productVersion();
    reportSnapshot->cpuArchitecture = QSysInfo::currentCpuArchitecture();
    reportSnapshot->mode = ui_->m_pGroupServer->isChecked() ? SupportReportMode::Server : SupportReportMode::Client;
    reportSnapshot->coreState = m_ExpectedRunningState == kStarted ? tr("Em execução") : tr("Parado");
    if (selected) {
        reportSnapshot->endpoint = diagnosticInput.endpoint + (diagnosticInput.controlPort ? QStringLiteral(":%1").arg(diagnosticInput.controlPort) : QString());
        reportSnapshot->deviceDisplayName = selected->displayName;
        reportSnapshot->peerUuid = selected->uuid;
        const auto connection = m_DeviceConnectionModel.snapshot(selected->uuid);
        const auto stateText = [this](DeviceConnectionModel::State state) {
            switch (state) {
            case DeviceConnectionModel::State::Offline: return tr("Desconectado");
            case DeviceConnectionModel::State::Available: return tr("Disponível");
            case DeviceConnectionModel::State::Connecting: return tr("Conectando");
            case DeviceConnectionModel::State::Connected: return tr("Conectado");
            case DeviceConnectionModel::State::Controlling: return tr("Controle ativo");
            case DeviceConnectionModel::State::Transferring: return tr("Transferindo");
            case DeviceConnectionModel::State::Incompatible: return tr("Incompatível");
            case DeviceConnectionModel::State::Error: return tr("Erro");
            }
            return tr("Desconhecido");
        };
        reportSnapshot->peerState = stateText(connection ? connection->state : m_LegacyPeerState);
    }
    auto updateReport = [reportPreview, privateMode, reportSnapshot]() {
        reportPreview->setPlainText(SupportReportBuilder().build(*reportSnapshot, SupportReportPolicy{privateMode->isChecked()}));
    };
    connect(privateMode, &QCheckBox::toggled, &dialog, [updateReport](bool) { updateReport(); });
    connect(copyReport, &QPushButton::clicked, &dialog, [reportPreview, privateMode, reportSnapshot, copyConfirmation]() {
        const QString freshReport = SupportReportBuilder().build(*reportSnapshot, SupportReportPolicy{privateMode->isChecked()});
        reportPreview->setPlainText(freshReport);
        QGuiApplication::clipboard()->setText(freshReport);
        copyConfirmation->setText(QObject::tr("Relatório copiado. Atenção: os dados permanecerão na área de transferência até serem substituídos."));
        copyConfirmation->setFocus(Qt::OtherFocusReason);
    });

    auto* diagnostics = new DiagnosticsService(nullptr, &dialog);
    auto* remediation = new DiagnosticsRemediationService(nullptr, &dialog);
    auto* retest = new QPushButton(tr("Testar novamente"), &dialog);
    auto* fixFirewall = new QPushButton(tr("Corrigir firewall"), &dialog);
    auto* openFolder = new QPushButton(tr("Abrir pasta de recebimento"), &dialog);
    auto* openSettings = new QPushButton(tr("Abrir configurações"), &dialog);
    fixFirewall->setVisible(false);
    openFolder->setEnabled(QFileInfo(diagnosticInput.receiveFolder).isDir());
    const auto profiles = FirewallProfile::Domain | FirewallProfile::Private;
    FirewallRuleSetSpec firewallSpecs;
    const QString appDir = QCoreApplication::applicationDirPath();
    if (ui_->m_pGroupServer->isChecked() && controlPort()) {
        firewallSpecs.rules << FirewallRuleSpec{QDir(appDir).filePath(QStringLiteral("input-leaps.exe")), {controlPort()}, profiles};
    }
    if (m_pFileTransferService && m_pFileTransferService->port()) {
        firewallSpecs.rules << FirewallRuleSpec{QDir(appDir).filePath(QStringLiteral("input-leap.exe")), {m_pFileTransferService->port()}, profiles};
    }
    auto runDiagnostics = [diagnostics, table, diagnosticInput, retest, fixFirewall]() {
        retest->setEnabled(false); fixFirewall->setVisible(false);
        table->setRowCount(0);
        diagnostics->start(diagnosticInput);
    };
    connect(diagnostics, &DiagnosticsService::completed, &dialog,
            [table, retest, remediation, firewallSpecs, reportSnapshot, updateReport](quint64, const DiagnosticsReport& report) {
        reportSnapshot->diagnostics = report;
        reportSnapshot->recentErrors.clear();
        for (const auto& check : report.checks) {
            if (check.severity == DiagnosticSeverity::Error) {
                reportSnapshot->recentErrors << QStringLiteral("%1: %2%3")
                    .arg(check.id, check.simple,
                         check.technical.isEmpty() ? QString() : QStringLiteral(" — %1").arg(check.technical));
            }
        }
        updateReport();
        static const QHash<QString, QString> titles{{"discovery", QObject::tr("Descoberta")}, {"version", QObject::tr("Versão")}, {"dns-ip", QObject::tr("DNS / IP")},
            {"control-port", QObject::tr("Porta de controle")}, {"transfer-port", QObject::tr("Porta de transferência")},
            {"tls-psk", QObject::tr("TLS-PSK")}, {"receive-folder", QObject::tr("Pasta de recebimento")},
            {"folder-permissions", QObject::tr("Permissões da pasta")}};
        for (const auto& item : report.checks) {
            const int row = table->rowCount(); table->insertRow(row);
            const QString status = item.severity == DiagnosticSeverity::Ok ? QObject::tr("OK") :
                item.severity == DiagnosticSeverity::Warning ? QObject::tr("Atenção") : QObject::tr("Erro");
            table->setItem(row, 0, new QTableWidgetItem(titles.value(item.id, item.id)));
            table->setItem(row, 1, new QTableWidgetItem(status));
            table->setItem(row, 2, new QTableWidgetItem(item.simple));
            table->setItem(row, 3, new QTableWidgetItem(item.technical));
            table->item(row, 1)->setForeground(item.severity == DiagnosticSeverity::Ok ? QColor("#15803d") :
                item.severity == DiagnosticSeverity::Warning ? QColor("#b45309") : QColor("#b91c1c"));
        }
        table->resizeRowsToContents(); retest->setEnabled(true); remediation->inspect(firewallSpecs);
    });
    connect(remediation, &DiagnosticsRemediationService::firewallInspected, &dialog,
            [table, fixFirewall, reportSnapshot, updateReport](const FirewallDetection& result) {
        reportSnapshot->firewall = result;
        updateReport();
        const int old = table->findItems(QObject::tr("Firewall do Windows"), Qt::MatchExactly).value(0, nullptr)
            ? table->findItems(QObject::tr("Firewall do Windows"), Qt::MatchExactly).first()->row() : -1;
        const int row = old >= 0 ? old : table->rowCount(); if (old < 0) table->insertRow(row);
        const bool present=result.status==FirewallDetectionStatus::Present, missing=result.status==FirewallDetectionStatus::Missing;
        table->setItem(row,0,new QTableWidgetItem(QObject::tr("Firewall do Windows")));
        table->setItem(row,1,new QTableWidgetItem(present?QObject::tr("OK"):missing?QObject::tr("Atenção"):QObject::tr("Desconhecido")));
        table->setItem(row,2,new QTableWidgetItem(present?QObject::tr("Regra efetiva confirmada."):missing?QObject::tr("A regra necessária não foi encontrada."):QObject::tr("Não foi possível confirmar o estado do firewall.")));
        table->setItem(row,3,new QTableWidgetItem(result.technical)); fixFirewall->setVisible(missing);
    });
    connect(fixFirewall, &QPushButton::clicked, &dialog, [this, remediation, firewallSpecs]() {
        QStringList items;
        for (const auto& spec : firewallSpecs.rules) {
            QStringList ports; for (auto p : spec.ports) ports << QString::number(p);
            items << tr("%1 — porta(s) %2").arg(spec.executablePath, ports.join(", "));
        }
        const auto answer=QMessageBox::question(this,tr("Corrigir firewall"),
            tr("O InputLeap adicionará regras TCP de entrada somente para:\n%1\n\nPerfis: Domínio e Privado.\nO perfil Público não será alterado. Uma única confirmação do UAC será solicitada. Continuar?").arg(items.join("\n")),
            QMessageBox::Yes|QMessageBox::No,QMessageBox::No);
        remediation->remediateFirewall(answer==QMessageBox::Yes);
    });
    connect(remediation,&DiagnosticsRemediationService::firewallVerified,&dialog,runDiagnostics);
    connect(remediation,&DiagnosticsRemediationService::firewallRemediationFailed,&dialog,[this](const QString&m){QMessageBox::warning(this,tr("Firewall"),m);});
    connect(openFolder,&QPushButton::clicked,&dialog,[this,diagnosticInput](){if(QFileInfo(diagnosticInput.receiveFolder).isDir())QDesktopServices::openUrl(QUrl::fromLocalFile(diagnosticInput.receiveFolder));});
    connect(openSettings,&QPushButton::clicked,&dialog,[this](){on_m_pActionSettings_triggered();});
    connect(retest, &QPushButton::clicked, &dialog, runDiagnostics);
    connect(&dialog, &QDialog::finished, diagnostics, [diagnostics](int) { diagnostics->cancel(); });

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fechar"));
    if (auto* closeButton = buttons->button(QDialogButtonBox::Close)) {
        closeButton->setText(tr("Fechar"));
    }
    buttons->addButton(openFolder,QDialogButtonBox::ActionRole);
    buttons->addButton(openSettings,QDialogButtonBox::ActionRole);
    buttons->addButton(fixFirewall,QDialogButtonBox::ActionRole);
    buttons->addButton(retest, QDialogButtonBox::ActionRole);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    layout->addWidget(table);
    layout->addWidget(detailsToggle);
    layout->addWidget(privateMode);
    layout->addWidget(reportPreview);
    layout->addWidget(copyReport);
    layout->addWidget(copyConfirmation);
    layout->addWidget(buttons);
    updateReport();
    runDiagnostics();
    dialog.exec();
}

void MainWindow::checkForUpdates()
{
    if (m_pUpdateService == nullptr || m_pActionCheckUpdates == nullptr)
        return;
    m_pActionCheckUpdates->setEnabled(false);
    setStatus(tr("Verificando atualizações seguras..."));
    const QDateTime nowUtc = m_UpdateNowUtcOverride
        ? m_UpdateNowUtcOverride()
        : QDateTime::currentDateTimeUtc();
    m_pUpdateService->check(UpdateTrustConfig::production().manifestUrl, nowUtc);
}

void MainWindow::handleUpdateCheckFinished(const UpdateService::Result& result)
{
    if (m_pActionCheckUpdates != nullptr)
        m_pActionCheckUpdates->setEnabled(true);

    if (result.error != UpdateService::Error::None || !result.release) {
        if (m_DiscoveredDevicesModel)
            m_DiscoveredDevicesModel->setUpdateTargetVersion(QString());
        appendLogError(tr("Falha na verificação segura de atualização: %1")
                           .arg(result.detail));
        QString title = tr("Não foi possível verificar");
        QString text = tr("Não foi possível confirmar uma atualização segura agora. "
                          "Tente novamente mais tarde.");
        QString accessibleName = tr("Falha na verificação de atualização");
        QString status = tr("A verificação de atualização não foi concluída.");
        if (result.error == UpdateService::Error::HttpFailure) {
            title = tr("Serviço de atualização indisponível");
            text = tr("O serviço de atualizações ainda não está disponível. "
                      "Nenhuma atualização foi baixada ou instalada. "
                      "Tente novamente mais tarde.");
            accessibleName = tr("Serviço de atualização indisponível");
            status = tr("O serviço de atualização está indisponível.");
        }
        else if (result.error == UpdateService::Error::NetworkFailure) {
            title = tr("Sem conexão com o serviço de atualização");
            text = tr("Não foi possível acessar o serviço de atualizações. "
                      "Verifique sua conexão com a Internet e tente novamente.");
            accessibleName = tr("Falha de conexão com o serviço de atualização");
            status = tr("Não foi possível acessar o serviço de atualização.");
        }
        auto* message = new QMessageBox(
            QMessageBox::Warning, title, text, QMessageBox::Ok, this);
        message->setAttribute(Qt::WA_DeleteOnClose);
        message->setAccessibleName(accessibleName);
        message->show();
        setStatus(status);
        return;
    }

    if (!result.updateAvailable) {
        if (m_DiscoveredDevicesModel)
            m_DiscoveredDevicesModel->setUpdateTargetVersion(QString());
        auto* message = new QMessageBox(
            QMessageBox::Information, tr("InputLeap está atualizado"),
            tr("Você já está usando a versão estável mais recente."),
            QMessageBox::Ok, this);
        message->setAttribute(Qt::WA_DeleteOnClose);
        message->setAccessibleName(tr("Resultado da verificação de atualização"));
        message->show();
        setStatus(tr("Nenhuma atualização estável disponível."));
        return;
    }

    const UpdateService::Release& release = *result.release;
    if (m_DiscoveredDevicesModel)
        m_DiscoveredDevicesModel->setUpdateTargetVersion(release.version);
    if (m_NotificationService)
        m_NotificationService->publish(
            QStringLiteral("update-available"), tr("Atualização"),
            tr("A versão %1 está disponível para este computador.").arg(release.version));
    auto* dialog = new CompactUpdateDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModal(true);
    dialog->setWindowTitle(tr("Atualização disponível"));
    dialog->setAccessibleName(tr("Detalhes da atualização disponível"));
    const QRect available = screen() != nullptr
        ? screen()->availableGeometry() : QRect(0, 0, 500, 420);
    dialog->setMinimumSize(1, 1);
    dialog->resize(qMax(1, qMin(500, available.width() - 32)),
                   qMax(1, qMin(420, available.height() - 32)));
    auto* layout = new QVBoxLayout(dialog);
    layout->setSizeConstraint(QLayout::SetNoConstraint);
    layout->setContentsMargins(18, 18, 18, 18);
    layout->setSpacing(12);
    modernizeUtilityDialog(
        *dialog, *layout, tr("Atualização estável disponível"),
        tr("Confira os detalhes antes de decidir atualizar."));

    auto* version = new QLabel(tr("Versão %1").arg(release.version), dialog);
    version->setObjectName(QStringLiteral("updateVersionLabel"));
    version->setAccessibleName(version->text());
    auto* size = new QLabel(
        tr("Tamanho: %1").arg(QLocale().formattedDataSize(qint64(release.size))), dialog);
    size->setObjectName(QStringLiteral("updateSizeLabel"));
    size->setAccessibleName(size->text());
    auto* notesTitle = new QLabel(tr("Novidades"), dialog);
    notesTitle->setStyleSheet(QStringLiteral("font-weight: 700;"));
    auto* notes = new QLabel(release.notes, dialog);
    notes->setObjectName(QStringLiteral("updateNotesLabel"));
    notes->setAccessibleName(tr("Novidades da versão: %1").arg(release.notes));
    notes->setTextFormat(Qt::PlainText);
    notes->setWordWrap(true);
    notes->setTextInteractionFlags(Qt::TextSelectableByMouse);
    notes->setFocusPolicy(Qt::NoFocus);
    layout->addWidget(version);
    layout->addWidget(size);
    layout->addWidget(notesTitle);
    auto* notesScroll = new QScrollArea(dialog);
    notesScroll->setObjectName(QStringLiteral("updateNotesScrollArea"));
    notesScroll->setWidgetResizable(true);
    notesScroll->setFrameShape(QFrame::NoFrame);
    notesScroll->setFocusPolicy(Qt::StrongFocus);
    notesScroll->setWidget(notes);
    layout->addWidget(notesScroll, 1);
    auto* updateStatus = new QLabel(dialog);
    updateStatus->setObjectName(QStringLiteral("updateInstallStatusLabel"));
    updateStatus->setWordWrap(true);
    updateStatus->setAccessibleName(tr("Estado da atualização"));
    updateStatus->hide();
    layout->addWidget(updateStatus);
    auto* updateProgress = new QProgressBar(dialog);
    updateProgress->setObjectName(QStringLiteral("updateDownloadProgress"));
    updateProgress->setRange(0, 1000);
    updateProgress->setValue(0);
    updateProgress->setAccessibleName(tr("Progresso do download da atualização"));
    updateProgress->hide();
    layout->addWidget(updateProgress);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
    buttons->setObjectName(QStringLiteral("updateDialogButtons"));
    buttons->button(QDialogButtonBox::Close)->setText(tr("Fechar"));
    QPushButton* updateButton = nullptr;
    if (release.installable && UpdateInstallPolicy::platformSupportsInstallation() &&
        !result.signedEnvelope.isEmpty()) {
        updateButton = buttons->addButton(tr("Atualizar agora"),
                                          QDialogButtonBox::ActionRole);
        updateButton->setObjectName(QStringLiteral("updateNowButton"));
        updateButton->setAccessibleName(
            tr("Baixar, verificar e instalar a atualização somente neste computador"));
        updateButton->setToolTip(
            tr("A autorização vale somente para este computador; nenhum dispositivo remoto será atualizado."));
        const UpdateService::Result updateResult = result;
        connect(updateButton, &QPushButton::clicked, dialog,
                [this, updateResult, dialog, updateButton, updateProgress, updateStatus] {
            startUpdateDownload(updateResult, dialog, updateButton,
                                updateProgress, updateStatus);
        });
    }
    connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
    connect(dialog, &QDialog::rejected, this, [this, dialog] {
        if (m_UpdateDialog == dialog) cancelPendingUpdateInstallation();
    });
    layout->addWidget(buttons);
    dialog->show();
    notesScroll->setFocus(Qt::OtherFocusReason);
    setStatus(tr("Uma atualização estável foi confirmada."));
}

void MainWindow::startUpdateDownload(const UpdateService::Result& result,
                                     QDialog* dialog, QPushButton* updateButton,
                                     QProgressBar* progress, QLabel* status)
{
    if (!result.release || !result.release->installable ||
        !UpdateInstallPolicy::platformSupportsInstallation() ||
        result.release->packageType != UpdateService::PackageType::WindowsMsi ||
        result.signedEnvelope.isEmpty() || !m_UpdateDownloadService) {
        return;
    }
    m_PendingUpdateRelease = result.release;
    m_PendingUpdateEnvelope = result.signedEnvelope;
    m_StagedUpdatePath.clear();
    m_UpdateDialog = dialog;
    m_UpdateButton = updateButton;
    m_UpdateProgress = progress;
    m_UpdateStatus = status;
    m_UpdateInstallAwaitingStop = false;
    m_DesktopStopConfirmed = false;
    updateButton->setEnabled(false);
    progress->setValue(0);
    progress->show();
    status->setText(tr("Baixando e verificando a atualização…"));
    status->show();
    if (m_NotificationService)
        m_NotificationService->publish(
            QStringLiteral("update-started"), tr("Atualização"),
            tr("O download da atualização foi iniciado neste computador."));
    m_UpdateDownloadService->start(*result.release);
}

bool MainWindow::engageUpdateTransferBarrier(QString* error)
{
    const bool active = m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers() ||
        !m_TransferControllers.isEmpty() || m_FileTransferReceiveBusy;
    if (active) {
        if (error) *error = tr("Há transferências em andamento.");
        return false;
    }
    m_UpdateTransferBarrierActive = true;
    m_TransferQueueShuttingDown = true;
    m_UpdateTransferListenPort = m_pFileTransferService
        ? m_pFileTransferService->port() : 0;
    if (m_pFileTransferService) m_pFileTransferService->stopListening();
    for (auto it = m_TransferControllers.begin();
         it != m_TransferControllers.end(); ++it) {
        m_TransferCancelIntents[it.key()] = TransferCancelIntent::Shutdown;
        if (it.value()) {
            it.value()->cancel();
            it.value()->cancelAndWait();
        }
    }
    QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    if (m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers() ||
        !m_TransferControllers.isEmpty() || m_FileTransferReceiveBusy) {
        if (error) *error = tr("Uma transferência começou durante a preparação.");
        releaseUpdateTransferBarrier();
        return false;
    }
    if (m_TransferQueue && !m_TransferQueue->save(error)) {
        releaseUpdateTransferBarrier();
        return false;
    }
    return true;
}

void MainWindow::releaseUpdateTransferBarrier()
{
    if (!m_UpdateTransferBarrierActive) return;
    m_UpdateTransferBarrierActive = false;
    m_TransferQueueShuttingDown = false;
    if (m_RuntimeConsumersEnabled && m_pFileTransferService &&
        m_UpdateTransferListenPort != 0 && m_pFileTransferService->port() == 0) {
        QString listenError;
        if (!m_pFileTransferService->startListening(
                m_UpdateTransferListenPort, &listenError)) {
            appendLogError(tr("O receptor de arquivos não pôde ser reativado: %1")
                               .arg(listenError));
        }
    }
    m_UpdateTransferListenPort = 0;
    QTimer::singleShot(0, this, &MainWindow::dispatchNextTransfer);
    applyDashboardPeerPolicy();
    rebuildTrayMenu();
}

void MainWindow::cancelPendingUpdateInstallation()
{
    if (m_UpdateDownloadService && m_UpdateDownloadService->active()) {
        m_UpdateCancellationRequested = true;
        m_UpdateDownloadService->cancel();
    }
    cleanupStagedUpdateArtifacts(m_StagedUpdatePath);
    const bool stopWasRequested = m_UpdateStopRequested;
    m_UpdateInstallAwaitingStop = false;
    if (stopWasRequested && m_UpdateCoreWasRunning) {
        if (appConfig().processMode() == Service && m_ServiceStopPending) {
            m_ServiceRestartPending = true;
        }
        else if (m_UpdateCoreStoppedForInstall) {
            if (appConfig().processMode() == Service) {
                m_ServiceRestartPending = true;
                m_ServiceRestartAwaitingReconnect = true;
                if (m_ServiceReconnectOverride) m_ServiceReconnectOverride();
                else m_IpcClient.connectToHost();
            }
            else {
                start_cmd_app();
            }
        }
    }
    releaseUpdateTransferBarrier();
    releaseUpdateInstallMutex(m_UpdateInstallMutex);
    m_UpdateStopRequested = false;
    m_UpdateCoreStoppedForInstall = false;
    const QString message = tr("Atualização cancelada. Nenhuma instalação foi iniciada.");
    if (m_UpdateStatus) m_UpdateStatus->setText(message);
    setStatus(message);
}

void MainWindow::prepareUpdateInstallation()
{
    if (!m_PendingUpdateRelease || m_StagedUpdatePath.isEmpty()) {
        updateInstallationFailed(tr("O pacote verificado não está disponível."));
        return;
    }
    const bool transfersActive =
        m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers() ||
        !m_TransferControllers.isEmpty() || m_FileTransferReceiveBusy;
    if (transfersActive) {
        updateInstallationFailed(tr(
            "A atualização está pronta. Termine as transferências em andamento e tente novamente."));
        return;
    }
    if (!m_RuntimeConsumersEnabled) {
        updateInstallationFailed(tr(
            "A atualização não pode ser instalada enquanto a configuração persistente estiver inválida."));
        return;
    }
    QString barrierError;
    if (!engageUpdateTransferBarrier(&barrierError)) {
        updateInstallationFailed(tr(
            "A atualização está pronta, mas as transferências não puderam ser pausadas com segurança."));
        return;
    }
    if (!acquireUpdateInstallMutex(m_UpdateInstallMutex)) {
        updateInstallationFailed(tr(
            "Outra instalação do InputLeap já está em andamento."));
        return;
    }
    m_UpdateCoreWasRunning = m_ExpectedRunningState == kStarted ||
        connection_state_ != AppConnectionState::DISCONNECTED;
    m_UpdateStopRequested = false;
    m_UpdateCoreStoppedForInstall = false;
    saveSettings();
    if (!appConfig().saveSettings() || settings().status() != QSettings::NoError) {
        updateInstallationFailed(tr(
            "Não foi possível salvar as configurações. A instalação não começou."));
        return;
    }

    if (m_UpdateStatus) {
        m_UpdateStatus->setText(tr(
            "Pacote verificado. Aguardando a confirmação de parada do InputLeap…"));
        m_UpdateStatus->show();
    }
    m_UpdateInstallAwaitingStop = true;
    m_UpdateStopRequested = true;
    stop_cmd_app();
    if (appConfig().processMode() == Desktop) {
        if (!m_DesktopStopConfirmed) {
            updateInstallationFailed(tr(
                "A instalação não começou porque o processo do InputLeap não parou."));
            return;
        }
        m_UpdateCoreStoppedForInstall = true;
        continueUpdateInstallationAfterStop();
    }
}

void MainWindow::continueUpdateInstallationAfterStop()
{
    if (!m_UpdateInstallAwaitingStop || !m_PendingUpdateRelease)
        return;
    const bool transfersActive =
        m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers() ||
        !m_TransferControllers.isEmpty() || m_FileTransferReceiveBusy;
    const bool stopConfirmed = appConfig().processMode() == Service
        ? !m_ServiceStopPending && !m_ServiceStopUnconfirmed
        : m_DesktopStopConfirmed;
    const UpdateInstallPolicy::Input input{
        *m_PendingUpdateRelease,
        QStringLiteral(INPUTLEAP_VERSION),
        m_StagedUpdatePath,
        transfersActive,
        m_RuntimeConsumersEnabled,
        m_ServiceStopPending,
        stopConfirmed,
    };
    const auto policy = UpdateInstallPolicy::evaluate(input);
    if (policy != UpdateInstallPolicy::Decision::Allowed) {
        updateInstallationFailed(tr(
            "As condições de segurança mudaram. A instalação não começou."));
        return;
    }

    const QString appPath = QFileInfo(QCoreApplication::applicationFilePath())
                                .canonicalFilePath();
    const QByteArray appHash = updateFileSha256(appPath);
    if (appPath.isEmpty() || appHash.size() != 32) {
        updateInstallationFailed(tr(
            "Não foi possível verificar o executável atual. A instalação não começou."));
        return;
    }
    UpdateHelperInstruction instruction;
    instruction.parentPid = quint32(QCoreApplication::applicationPid());
    instruction.parentPath = appPath;
    instruction.parentSha256 = appHash;
    instruction.msiPath = QDir::cleanPath(m_StagedUpdatePath);
    instruction.msiSize = m_PendingUpdateRelease->size;
    instruction.msiSha256 = m_PendingUpdateRelease->sha256;
    instruction.appPath = appPath;
    instruction.appSha256 = appHash;
    instruction.resultPath = QDir(QFileInfo(instruction.msiPath).absolutePath())
                                 .filePath(QStringLiteral("install.result.json"));
    instruction.readyPath = QDir(QFileInfo(instruction.msiPath).absolutePath())
                                .filePath(QStringLiteral("install.ready.json"));
    instruction.readyNonce = QUuid::createUuid().toRfc4122();
    instruction.manifestEnvelope = m_PendingUpdateEnvelope;

    QString error;
    if (!launchUpdateHelper(instruction, &error)) {
        Q_UNUSED(error);
        updateInstallationFailed(tr(
            "Não foi possível iniciar o instalador verificado. O InputLeap permanecerá aberto."));
        return;
    }
    m_UpdateInstallAwaitingStop = false;
    const QString preparedMessage = tr(
        "Preparação concluída. O pacote será verificado pelo Windows antes da instalação. "
        "O InputLeap será fechado agora.");
    if (m_UpdateStatus)
        m_UpdateStatus->setText(preparedMessage);
    setStatus(preparedMessage);
    if (m_UpdateExitOverride)
        m_UpdateExitOverride();
    else
        QTimer::singleShot(0, qApp, &QCoreApplication::quit);
}

bool MainWindow::authenticatedStagedUpdateResultPresent()
{
    const QString resultPath = QDir(m_UpdateStagingDirectory).filePath(
        QStringLiteral("install.result.json"));
    QByteArray encoded;
    if (!readResultPayloadWithIdentity(resultPath, encoded)) {
        return false;
    }
    const auto parsed = UpdateHelperProtocol::parseResult(encoded);
    if (!parsed)
        return false;
    const auto key = RecoveryArtifactAuthenticator::loadKey(
        m_AppConfig->m_CredentialStore,
        UpdateHelperProtocol::resultAuthenticationAccount());
    return key && UpdateHelperProtocol::verifyResultAuthentication(
        *parsed, key->bytes());
}

bool MainWindow::cleanupStagedUpdateArtifacts(
    const QString& msiPath, bool preserveAuthenticatedResult,
    bool removeProtectedIfHelperInactive)
{
    if (pathContainsWindowsReparsePoint(m_UpdateStagingDirectory))
        return false;
    StagingDirectoryLock stagingLock(m_UpdateStagingDirectory);
    if (!stagingLock.valid())
        return false;
    void* cleanupMutex = nullptr;
    const bool acquiredCleanupMutex = !preserveAuthenticatedResult &&
        m_UpdateInstallMutex == nullptr &&
        acquireUpdateInstallMutex(cleanupMutex);
    if (!preserveAuthenticatedResult && m_UpdateInstallMutex == nullptr &&
        !acquiredCleanupMutex) {
        return false;
    }
    const auto releaseCleanupMutex = [this, &cleanupMutex, acquiredCleanupMutex] {
        if (acquiredCleanupMutex)
            releaseUpdateInstallMutex(cleanupMutex);
    };
    const auto failCleanup = [&releaseCleanupMutex] {
        releaseCleanupMutex();
        return false;
    };
    if (preserveAuthenticatedResult && authenticatedStagedUpdateResultPresent())
        return failCleanup();
    const QString resultPath = QDir(m_UpdateStagingDirectory).filePath(
        QStringLiteral("install.result.json"));
    const QString helperPath = QDir(m_UpdateStagingDirectory).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    const QFileInfo msiInfo(msiPath);
    const bool validMsiArtifact = msiInfo.isAbsolute() &&
        QDir::cleanPath(msiPath) == msiPath &&
        msiInfo.suffix().compare(QStringLiteral("msi"), Qt::CaseInsensitive) == 0 &&
        msiInfo.absolutePath().compare(
            QDir::cleanPath(m_UpdateStagingDirectory), Qt::CaseInsensitive) == 0;
    QStringList artifacts{
        QDir(m_UpdateStagingDirectory).filePath(
            QStringLiteral("install.instruction.json")),
        QDir(m_UpdateStagingDirectory).filePath(
            QStringLiteral("install.ready.json")),
        helperPath,
    };
    if (validMsiArtifact)
        artifacts.append(msiPath);
    artifacts.append(resultPath);
    bool removedAll = true;
    Q_UNUSED(removeProtectedIfHelperInactive);
    for (const QString& artifact : artifacts) {
        // Before the result has been authenticated and consumed, never unlink
        // any artifact that the helper can still publish or needs to complete
        // publication. A check followed by QFile::remove() has an unavoidable
        // race on Windows; retaining this small protected set closes it.
        const bool protectedArtifact = artifact == resultPath ||
            artifact == helperPath || (validMsiArtifact && artifact == msiPath);
        if (preserveAuthenticatedResult && protectedArtifact) {
            const QFileInfo retained(artifact);
            if (retained.exists() || retained.isSymLink())
                removedAll = false;
            continue;
        }
        if (preserveAuthenticatedResult && authenticatedStagedUpdateResultPresent())
            return failCleanup();
        const QFileInfo before(artifact);
        if (!before.exists() && !before.isSymLink())
            continue;
        if (pathContainsWindowsReparsePoint(artifact)) {
            removedAll = false;
            continue;
        }
        // Revalidate immediately before unlinking. The helper publishes via
        // an atomic result replacement, so a result observed in this final
        // window must stop cleanup rather than allowing a protected artifact
        // to be removed after authentication has been established.
        if (preserveAuthenticatedResult && authenticatedStagedUpdateResultPresent()) {
            removedAll = false;
            continue;
        }
        const bool removalReported = m_UpdateArtifactRemoveOverride
            ? m_UpdateArtifactRemoveOverride(artifact)
#if defined(Q_OS_WIN)
            : removeFileWithoutReparseRace(artifact);
#else
            : QFile::remove(artifact);
#endif
        if (preserveAuthenticatedResult && authenticatedStagedUpdateResultPresent()) {
            removedAll = false;
            continue;
        }
        const QFileInfo after(artifact);
        if (!removalReported || after.exists() || after.isSymLink())
            removedAll = false;
    }
    releaseCleanupMutex();
    return removedAll;
}

void MainWindow::updateInstallationFailed(const QString& message)
{
    if (m_NotificationService)
        m_NotificationService->publish(
            QStringLiteral("update-failed"), tr("Atualização"), message,
            NotificationService::Severity::Error);
    const QString pendingGroup = QStringLiteral("SecureUpdate/PendingResult");
    if (cleanupStagedUpdateArtifacts(m_StagedUpdatePath)) {
        m_Settings.remove(pendingGroup);
    }
    else {
        m_Settings.setValue(pendingGroup + QStringLiteral("/schema"), 2);
        m_Settings.setValue(pendingGroup + QStringLiteral("/cleanupOnly"), true);
        m_Settings.setValue(pendingGroup + QStringLiteral("/msiPath"),
                            m_StagedUpdatePath);
    }
    m_Settings.sync();
    if (m_Settings.contains(pendingGroup + QStringLiteral("/schema")))
        schedulePendingUpdateResultRetry(1000);
    const bool stopWasRequested = m_UpdateStopRequested;
    m_UpdateInstallAwaitingStop = false;
    if (stopWasRequested && m_UpdateCoreWasRunning) {
        if (appConfig().processMode() == Service && m_ServiceStopPending) {
            m_ServiceRestartPending = true;
        }
        else if (m_UpdateCoreStoppedForInstall) {
            if (appConfig().processMode() == Service) {
                m_ServiceRestartPending = true;
                m_ServiceRestartAwaitingReconnect = true;
                if (m_ServiceReconnectOverride) m_ServiceReconnectOverride();
                else m_IpcClient.connectToHost();
            }
            else {
                start_cmd_app();
            }
        }
    }
    releaseUpdateTransferBarrier();
    releaseUpdateInstallMutex(m_UpdateInstallMutex);
    m_UpdateStopRequested = false;
    m_UpdateCoreStoppedForInstall = false;
    if (m_UpdateStatus) {
        m_UpdateStatus->setText(message);
        m_UpdateStatus->show();
    }
    if (m_UpdateProgress)
        m_UpdateProgress->hide();
    if (m_UpdateButton)
        m_UpdateButton->setEnabled(true);
    setStatus(message);
}

bool MainWindow::persistPendingUpdateResult(
    const UpdateHelperInstruction& instruction, QString* error)
{
    const QString version = m_PendingUpdateRelease
        ? m_PendingUpdateRelease->version : QString();
    const QFileInfo resultInfo(instruction.resultPath);
    const QString expectedResultPath = QDir(m_UpdateStagingDirectory)
        .filePath(QStringLiteral("install.result.json"));
    const bool validPath = resultInfo.isAbsolute() &&
        QDir::cleanPath(instruction.resultPath) == instruction.resultPath &&
        instruction.resultPath.size() <= 32767 &&
        instruction.resultPath.compare(
            QDir::cleanPath(expectedResultPath), Qt::CaseInsensitive) == 0;
    const bool validVersion = !version.isEmpty() && version.size() <= 128 &&
        !version.contains(QLatin1Char('\0')) &&
        !version.contains(QChar::CarriageReturn) &&
        !version.contains(QLatin1Char('\n'));
    const QFileInfo msiInfo(instruction.msiPath);
    const QByteArray boundAppSha256 = instruction.appSha256.isEmpty()
        ? updateFileSha256(QCoreApplication::applicationFilePath())
        : instruction.appSha256;
    const bool validMsiPath = msiInfo.isAbsolute() &&
        QDir::cleanPath(instruction.msiPath) == instruction.msiPath &&
        instruction.msiPath.size() <= 32767 &&
        msiInfo.suffix().compare(QStringLiteral("msi"), Qt::CaseInsensitive) == 0 &&
        msiInfo.absolutePath().compare(
            QDir::cleanPath(m_UpdateStagingDirectory), Qt::CaseInsensitive) == 0;
    if (!validPath || instruction.readyNonce.size() != 16 ||
        instruction.msiSha256.size() != 32 || boundAppSha256.size() != 32 ||
        !validVersion || !validMsiPath) {
        if (error) *error = QStringLiteral("pending update result binding is invalid");
        return false;
    }
    const auto resultAuthenticationKey =
        RecoveryArtifactAuthenticator::loadOrCreateKey(
            m_AppConfig->m_CredentialStore,
            UpdateHelperProtocol::resultAuthenticationAccount());
    if (!resultAuthenticationKey) {
        if (error)
            *error = QStringLiteral("update result authentication is unavailable");
        return false;
    }

    const QString group = QStringLiteral("SecureUpdate/PendingResult");
    m_Settings.remove(group);
    m_Settings.beginGroup(group);
    m_Settings.setValue(QStringLiteral("schema"), 2);
    m_Settings.setValue(QStringLiteral("createdAtUtc"),
        QDateTime::currentDateTimeUtc().toString(
            QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    m_Settings.setValue(QStringLiteral("resultPath"), instruction.resultPath);
    m_Settings.setValue(
        QStringLiteral("nonce"),
        QString::fromLatin1(instruction.readyNonce.toBase64(
            QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
    m_Settings.setValue(QStringLiteral("version"), version);
    m_Settings.setValue(QStringLiteral("originVersion"),
                        QStringLiteral(INPUTLEAP_VERSION));
    m_Settings.setValue(QStringLiteral("msiPath"), instruction.msiPath);
    m_Settings.setValue(QStringLiteral("msiSha256"),
                        QString::fromLatin1(instruction.msiSha256.toHex()));
    m_Settings.setValue(QStringLiteral("appSha256"),
                        QString::fromLatin1(boundAppSha256.toHex()));
    m_Settings.endGroup();
    m_Settings.sync();
    if (m_Settings.status() == QSettings::NoError)
        return true;

    m_Settings.remove(group);
    m_Settings.sync();
    if (error) *error = QStringLiteral("pending update result could not be persisted");
    return false;
}

void MainWindow::schedulePendingUpdateResultRetry(int retryMs)
{
    if (m_UpdateResultRetryTimer == nullptr) {
        m_UpdateResultRetryTimer = new QTimer(this);
        m_UpdateResultRetryTimer->setObjectName(
            QStringLiteral("pendingUpdateResultRetryTimer"));
        m_UpdateResultRetryTimer->setSingleShot(true);
        connect(m_UpdateResultRetryTimer, &QTimer::timeout,
                this, &MainWindow::consumePendingUpdateResult);
    }
    if (!m_UpdateResultRetryTimer->isActive() ||
        m_UpdateResultRetryTimer->remainingTime() > retryMs) {
        m_UpdateResultRetryTimer->start(qMax(1, retryMs));
    }
}

void MainWindow::consumePendingUpdateResult()
{
    const QString group = QStringLiteral("SecureUpdate/PendingResult");
    if (!m_Settings.contains(group + QStringLiteral("/schema"))) {
        if (m_UpdateResultRetryTimer != nullptr)
            m_UpdateResultRetryTimer->stop();
        m_UpdateResultPendingNoticeLogged = false;
        return;
    }
    const QFileInfo stagingInfo(m_UpdateStagingDirectory);
    if (stagingInfo.exists() && stagingInfo.isSymLink()) {
        setStatus(tr("O diretório temporário da atualização não é confiável."));
        schedulePendingUpdateResultRetry(60000);
        return;
    }

    m_Settings.beginGroup(group);
    const int schema = m_Settings.value(QStringLiteral("schema"), -1).toInt();
    const QString createdAtEncoded = m_Settings.value(
        QStringLiteral("createdAtUtc")).toString();
    const QString resultPath = m_Settings.value(
        QStringLiteral("resultPath")).toString();
    const QByteArray nonceEncoded = m_Settings.value(
        QStringLiteral("nonce")).toString().toLatin1();
    const QString version = m_Settings.value(QStringLiteral("version")).toString();
    const QString originVersion = m_Settings.value(
        QStringLiteral("originVersion")).toString();
    const QString msiPath = m_Settings.value(QStringLiteral("msiPath")).toString();
    const QByteArray hashEncoded = m_Settings.value(
        QStringLiteral("msiSha256")).toString().toLatin1();
    const QByteArray appHashEncoded = m_Settings.value(
        QStringLiteral("appSha256")).toString().toLatin1();
    const bool cleanupOnly = m_Settings.value(
        QStringLiteral("cleanupOnly"), false).toBool();
    const bool helperLaunchInFlight = m_Settings.value(
        QStringLiteral("helperLaunchInFlight"), false).toBool();
    const qint64 helperPid = m_Settings.value(
        QStringLiteral("helperPid"), 0).toLongLong();
    const QString helperPath = m_Settings.value(
        QStringLiteral("helperPath")).toString();
    const QByteArray helperHashEncoded = m_Settings.value(
        QStringLiteral("helperSha256")).toString().toLatin1();
    m_Settings.endGroup();

    const auto unconfirmed = [this] {
        const QString message = tr(
            "O resultado da atualização não pôde ser confirmado.");
        setStatus(message);
        if (!m_UpdateResultPendingNoticeLogged) {
            appendLogError(message);
            m_UpdateResultPendingNoticeLogged = true;
        }
    };
    const QFileInfo resultInfo(resultPath);
    const QString expectedResultPath = QDir(m_UpdateStagingDirectory)
        .filePath(QStringLiteral("install.result.json"));
    const bool validPath = resultInfo.isAbsolute() &&
        QDir::cleanPath(resultPath) == resultPath && resultPath.size() <= 32767 &&
        resultPath.compare(
            QDir::cleanPath(expectedResultPath), Qt::CaseInsensitive) == 0;
    static const QRegularExpression nonceExpression(
        QStringLiteral("^[A-Za-z0-9_-]{22}$"));
    const QByteArray nonce = QByteArray::fromBase64(
        nonceEncoded,
        QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    const bool validNonce = nonceExpression.match(
        QString::fromLatin1(nonceEncoded)).hasMatch() && nonce.size() == 16 &&
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals) == nonceEncoded;
    static const QRegularExpression hashExpression(
        QStringLiteral("^[0-9a-f]{64}$"));
    const QByteArray msiSha256 = QByteArray::fromHex(hashEncoded);
    const bool validHash = hashExpression.match(
        QString::fromLatin1(hashEncoded)).hasMatch() && msiSha256.size() == 32;
    const QByteArray appSha256 = QByteArray::fromHex(appHashEncoded);
    const bool validAppHash = hashExpression.match(
        QString::fromLatin1(appHashEncoded)).hasMatch() && appSha256.size() == 32;
    const bool validVersion = !version.isEmpty() && version.size() <= 128 &&
        !version.contains(QLatin1Char('\0')) &&
        !version.contains(QChar::CarriageReturn) &&
        !version.contains(QLatin1Char('\n'));
    const bool validOriginVersion = !originVersion.isEmpty() &&
        originVersion.size() <= 128 && !originVersion.contains(QLatin1Char('\0')) &&
        !originVersion.contains(QChar::CarriageReturn) &&
        !originVersion.contains(QLatin1Char('\n'));
    const QFileInfo msiInfo(msiPath);
    const bool validMsiPath = msiInfo.isAbsolute() &&
        QDir::cleanPath(msiPath) == msiPath && msiPath.size() <= 32767 &&
        msiInfo.suffix().compare(QStringLiteral("msi"), Qt::CaseInsensitive) == 0 &&
        msiInfo.absolutePath().compare(
            QDir::cleanPath(m_UpdateStagingDirectory), Qt::CaseInsensitive) == 0;
    const QFileInfo helperInfo(helperPath);
    const QByteArray helperSha256 = QByteArray::fromHex(helperHashEncoded);
    const bool validHelperIdentity = helperPid > 0 && helperInfo.isAbsolute() &&
        QDir::cleanPath(helperPath) == helperPath && helperPath.size() <= 32767 &&
        helperInfo.fileName().compare(QStringLiteral("inputleap-update-helper.exe"),
                                      Qt::CaseInsensitive) == 0 &&
        helperInfo.absolutePath().compare(
            QDir::cleanPath(m_UpdateStagingDirectory), Qt::CaseInsensitive) == 0 &&
        hashExpression.match(QString::fromLatin1(helperHashEncoded)).hasMatch() &&
        helperSha256.size() == 32;
    const auto helperIdentityStillActive = [this, validHelperIdentity, helperPid,
                                            helperPath, helperSha256] {
        if (!validHelperIdentity)
            return false;
        const auto processMatches = [this, helperPid, &helperPath] {
            return m_UpdateProcessIdentityOverride
                ? m_UpdateProcessIdentityOverride(helperPid, helperPath)
                : updateProcessPathMatches(helperPid, helperPath);
        };
        if (!processMatches())
            return false;
        const bool hashMatches = updateFileSha256(helperPath) == helperSha256;
        return hashMatches && processMatches();
    };
    static const QRegularExpression utcExpression(
        QStringLiteral("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"));
    QDateTime createdAt = QDateTime::fromString(
        createdAtEncoded, QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'"));
    createdAt.setTimeSpec(Qt::UTC);
    const bool validCreatedAt = utcExpression.match(createdAtEncoded).hasMatch() &&
        createdAt.isValid();
    const bool validPendingBinding = schema == 2 && validPath && validNonce &&
        validHash && validAppHash && validVersion && validOriginVersion &&
        validMsiPath && validCreatedAt;
    const auto clearPending = [this, &group] {
        if (m_UpdateResultRetryTimer != nullptr)
            m_UpdateResultRetryTimer->stop();
        m_UpdateResultPendingNoticeLogged = false;
        m_Settings.remove(group);
        m_Settings.sync();
    };
    const auto scheduleRetry = [this](int retryMs) {
        schedulePendingUpdateResultRetry(retryMs);
    };
    const auto cleanupAndClear = [this, &clearPending, &scheduleRetry](
                                        const QString& path,
                                        bool preserveAuthenticatedResult = true,
                                        bool removeProtectedIfHelperInactive = false) {
        if (!cleanupStagedUpdateArtifacts(path, preserveAuthenticatedResult,
                                          removeProtectedIfHelperInactive)) {
            scheduleRetry(1000);
            return false;
        }
        clearPending();
        return true;
    };
    const bool authenticatedResultAlreadyPresent =
        authenticatedStagedUpdateResultPresent();
    if (helperLaunchInFlight) {
        setStatus(tr("A atualização permanece protegida enquanto a identidade do instalador não é confirmada."));
        scheduleRetry(60000);
        return;
    }
    if (cleanupOnly &&
        !(authenticatedResultAlreadyPresent && validPendingBinding)) {
        const bool helperStillActive = helperIdentityStillActive();
        const bool removeProtectedIfHelperInactive =
            !authenticatedResultAlreadyPresent && !helperStillActive;
        if (!cleanupAndClear(validMsiPath ? msiPath : QString(),
                             true, removeProtectedIfHelperInactive)) {
            setStatus(tr("A limpeza dos arquivos temporários da atualização será repetida."));
        }
        return;
    }

    // the normal parser again. This re-establishes HMAC, binding, version and
    // age authority before cleanup is retried with preservation disabled.
    if (!validPendingBinding) {
        if (authenticatedResultAlreadyPresent) {
            unconfirmed();
            return;
        }
        if (!cleanupAndClear(validMsiPath ? msiPath : QString())) {
            m_Settings.setValue(group + QStringLiteral("/cleanupOnly"), true);
            m_Settings.sync();
        }
        unconfirmed();
        return;
    }

    QByteArray encoded;
    if (!readResultPayloadWithIdentity(resultPath, encoded)) {
        if (helperIdentityStillActive()) {
            setStatus(tr("A atualização ainda está em andamento; o resultado será relido."));
            scheduleRetry(1000);
            return;
        }
        const qint64 ageSeconds = createdAt.secsTo(QDateTime::currentDateTimeUtc());
        if (!resultInfo.exists()) {
            if (ageSeconds >= -300 && ageSeconds <= 3600) {
                const QString message = tr(
                    "A atualização ainda não publicou um resultado verificável.");
                setStatus(message);
                if (!m_UpdateResultPendingNoticeLogged) {
                    appendLogInfo(message);
                    m_UpdateResultPendingNoticeLogged = true;
                }
                const qint64 remainingMs = qMax<qint64>(
                    1000, (3601 - ageSeconds) * 1000);
                const int retryMs = int(qMin<qint64>(
                    ageSeconds < 60 ? 1000 : 60000, remainingMs));
                scheduleRetry(retryMs);
                return;
            }
            if (helperIdentityStillActive()) {
                setStatus(tr("A atualização ainda não publicou um resultado verificável."));
                scheduleRetry(60000);
                return;
            }
        }
        m_Settings.setValue(group + QStringLiteral("/cleanupOnly"), true);
        m_Settings.sync();
        cleanupAndClear(msiPath);
        unconfirmed();
        return;
    }
    QString parseError;
    const auto result = UpdateHelperProtocol::parseResult(encoded, &parseError);
    if (!result) {
        Q_UNUSED(parseError);
        if (helperIdentityStillActive()) {
            setStatus(tr("A atualização ainda está publicando o resultado."));
            scheduleRetry(1000);
            return;
        }
        m_Settings.setValue(group + QStringLiteral("/cleanupOnly"), true);
        m_Settings.sync();
        cleanupAndClear(msiPath);
        unconfirmed();
        return;
    }

    const auto resultAuthenticationKey = RecoveryArtifactAuthenticator::loadKey(
        m_AppConfig->m_CredentialStore,
        UpdateHelperProtocol::resultAuthenticationAccount());
    if (!resultAuthenticationKey ||
        !UpdateHelperProtocol::verifyResultAuthentication(
            *result, resultAuthenticationKey->bytes())) {
        unconfirmed();
        return;
    }
    const auto resultStillCanonicalForCleanup = [this,
                                              &resultAuthenticationKey,
                                              &resultPath,
                                              encoded] {
        if (!resultAuthenticationKey || encoded.isEmpty()) {
            return false;
        }
        QByteArray currentPayload;
        if (!readResultPayloadWithIdentity(resultPath, currentPayload)) {
            return false;
        }
        if (currentPayload != encoded) {
            return false;
        }
        const auto reparsed = UpdateHelperProtocol::parseResult(currentPayload);
        return reparsed && UpdateHelperProtocol::verifyResultAuthentication(
                              *reparsed, resultAuthenticationKey->bytes());
    };

    const auto quarantineStaleResult = [this, &helperIdentityStillActive, &resultPath, &resultStillCanonicalForCleanup] {
        if (helperIdentityStillActive() || !resultStillCanonicalForCleanup())
            return false;
        StagingDirectoryLock stagingLock(m_UpdateStagingDirectory);
        return stagingLock.valid() && removeFileWithoutReparseRace(resultPath);
    };

    if (result->nonce != nonce || result->version != version ||
        result->msiSha256 != msiSha256) {
        // An authenticated result can belong to an older transaction. It has
        // no authority to remove the current transaction's pending state,
        // installer, helper, or result channel. Once the helper is inactive,
        // the still-canonical stale result is quarantined alone so it cannot
        // retain the current transaction forever.
        if (!quarantineStaleResult())
            scheduleRetry(1000);
        unconfirmed();
        return;
    }

    if (result->outcome == UpdateInstallPolicy::MsiOutcome::Installing) {
        const qint64 progressAgeSeconds = result->completedAtUtc.secsTo(
            QDateTime::currentDateTimeUtc());
        const bool helperStillActive = helperIdentityStillActive();
        if (helperStillActive) {
            setStatus(tr("A instalação da atualização ainda está em andamento."));
            scheduleRetry(1000);
            return;
        }
        if (progressAgeSeconds < -300) {
            setStatus(tr("A atualização não publicou um carimbo de tempo válido."));
            // A future-dated Installing result is still non-terminal. It may
            // be clock-skewed or in-flight, so preserve every staged artifact
            // and retry instead of treating it as a failed installation.
            scheduleRetry(1000);
            return;
        }
        if (progressAgeSeconds > 3600) {
            // Installing is deliberately non-terminal. An old result does
            // not prove that installation failed, so it cannot authorize
            // removal of the result, helper, MSI, or pending transaction.
            unconfirmed();
            return;
        }
        setStatus(tr("A instalação da atualização ainda está em andamento."));
        const qint64 remainingMs = qMax<qint64>(1000, (3600 - progressAgeSeconds) * 1000);
        const int retryMs = int(qMin<qint64>(
            progressAgeSeconds < 60 ? 1000 : 60000, remainingMs));
        scheduleRetry(retryMs);
        return;

    }
    const QString runningVersion = QStringLiteral(INPUTLEAP_VERSION);
    const bool runningExpectedVersion =
        result->outcome == UpdateInstallPolicy::MsiOutcome::Success
            ? version == runningVersion
            : (result->outcome ==
                       UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired
                   ? (version == runningVersion)
                   : originVersion == runningVersion);
    if (!runningExpectedVersion) {
        if (helperIdentityStillActive()) {
            setStatus(tr("O processo de atualização ainda está ativo; aguardando confirmação."));
            scheduleRetry(1000);
            return;
        }
        if (!resultStillCanonicalForCleanup()) {
            setStatus(tr("A atualização foi atualizada durante a validação."
                       " A confirmação será reexecutada."));
            scheduleRetry(1000);
            return;
        }
        m_Settings.setValue(group + QStringLiteral("/cleanupOnly"), true);
        m_Settings.sync();
        cleanupAndClear(msiPath, false);
        unconfirmed();
        return;
    }

    const qint64 resultAgeSeconds = result->completedAtUtc.secsTo(
        QDateTime::currentDateTimeUtc());
    if (resultAgeSeconds < -300 || resultAgeSeconds > 3600) {
        unconfirmed();
        return;
    }
    const bool relaunchConfirmed = result->relaunchVerified;
    // appSha256 binds the pre-install executable for rollback/failure outcomes.
    // A successful MSI is expected to replace those bytes; the newly launched
    // GUI confirms success with the nonce-bound helper result and its compiled
    // target version, not by matching the obsolete pre-install hash.
    if (!relaunchConfirmed && runningExpectedVersion &&
        (result->outcome == UpdateInstallPolicy::MsiOutcome::Success ||
         result->outcome == UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired) &&
        resultAgeSeconds >= -300 && resultAgeSeconds <= 60) {
        const QByteArray promoted = UpdateHelperProtocol::serializeResult(
            result->outcome, result->msiExitCode, true, result->nonce,
            result->version, result->msiSha256,
            resultAuthenticationKey->bytes());
        bool promotedResultWritten = false;
#if defined(Q_OS_WIN)
        StagingDirectoryLock promotionLock(m_UpdateStagingDirectory);
        promotedResultWritten = promotionLock.valid() &&
            !pathContainsWindowsReparsePoint(resultPath) &&
            writeAtomicFileWithoutReparseRace(resultPath, promoted);
#else
        QSaveFile promotedResult(resultPath);
        promotedResultWritten = promotedResult.open(QIODevice::WriteOnly) &&
            promotedResult.write(promoted) == promoted.size() &&
            !pathContainsWindowsReparsePoint(m_UpdateStagingDirectory) &&
            !pathContainsWindowsReparsePoint(resultPath) &&
            promotedResult.commit();
#endif
        if (!promotedResultWritten) {
            setStatus(tr("A confirmação da atualização não pôde ser publicada."));
            scheduleRetry(1000);
            return;
        }
        consumePendingUpdateResult();
        return;
    }
    if (!relaunchConfirmed && resultAgeSeconds >= -300 &&
        resultAgeSeconds <= 60) {
        const QString pendingMessage = tr(
            "A instalação foi processada; o reinício ainda está sendo confirmado.");
        setStatus(pendingMessage);
        scheduleRetry(100);
        return;
    }
    if (helperIdentityStillActive()) {
        setStatus(tr("O processo de atualização ainda está ativo; o resultado será relido."));
        scheduleRetry(1000);
        return;
    }
    if (!resultStillCanonicalForCleanup()) {
        setStatus(tr("A atualização foi atualizada durante a validação."
                   " A confirmação será reexecutada."));
        scheduleRetry(1000);
        return;
    }

    const QString consumedAccount = QStringLiteral(
        "InputLeap/update-result/consumed-v1");
    const QByteArray ledgerMagic = QByteArrayLiteral("ILUPD1");
    const QByteArray fingerprintDomain = QByteArrayLiteral(
        "inputleap-update-result-consumed-v1");
    const QByteArray fingerprintOutcome = QByteArray::number(
        static_cast<int>(result->outcome));
    const QByteArray fingerprintExitCode = QByteArray::number(result->msiExitCode);
    const QByteArray fingerprintVersion = result->version.toUtf8();
    const QByteArray resultFingerprint = RecoveryArtifactAuthenticator::authenticate(
        resultAuthenticationKey->bytes(), QByteArrayView(fingerprintDomain),
        {QByteArrayView(fingerprintOutcome), QByteArrayView(fingerprintExitCode),
         QByteArrayView(result->nonce), QByteArrayView(fingerprintVersion),
         QByteArrayView(result->msiSha256)});
    if (resultFingerprint.size() != 32) {
        unconfirmed();
        return;
    }
    auto consumedState = m_AppConfig->m_CredentialStore.read(consumedAccount);
    if (consumedState.status == SecureCredentialStore::ReadResult::Status::Error) {
        unconfirmed();
        return;
    }
    QByteArray consumedLedger = consumedState
        ? QByteArray(consumedState->bytes().data(), consumedState->bytes().size())
        : ledgerMagic;
    const bool validLedger = consumedLedger.startsWith(ledgerMagic) &&
        (consumedLedger.size() - ledgerMagic.size()) % resultFingerprint.size() == 0 &&
        consumedLedger.size() <= ledgerMagic.size() + (32 * resultFingerprint.size());
    if (!validLedger) {
        unconfirmed();
        return;
    }
    bool alreadyConsumed = false;
    for (qsizetype offset = ledgerMagic.size(); offset < consumedLedger.size();
         offset += resultFingerprint.size()) {
        if (QByteArrayView(consumedLedger).sliced(offset, resultFingerprint.size()) ==
            QByteArrayView(resultFingerprint)) {
            alreadyConsumed = true;
            break;
        }
    }
    if (alreadyConsumed) {
        m_Settings.setValue(group + QStringLiteral("/cleanupOnly"), true);
        m_Settings.sync();
        cleanupAndClear(msiPath, false);
        unconfirmed();
        return;
    }

    QByteArray nextLedger = consumedLedger;
    if (nextLedger.size() == ledgerMagic.size() + (32 * resultFingerprint.size()))
        nextLedger.remove(ledgerMagic.size(), resultFingerprint.size());
    nextLedger.append(resultFingerprint);
    const std::optional<QByteArrayView> expectedLedger = consumedState
        ? std::optional<QByteArrayView>(QByteArrayView(consumedLedger))
        : std::nullopt;
    if (m_AppConfig->m_CredentialStore.compareAndSwap(
            consumedAccount, expectedLedger, QByteArrayView(nextLedger)) !=
        SecureCredentialStore::CompareAndSwapResult::Success) {
        unconfirmed();
        return;
    }

    m_Settings.setValue(group + QStringLiteral("/cleanupOnly"), true);
    m_Settings.sync();
    if (!cleanupAndClear(msiPath, false)) {
        unconfirmed();
        return;
    }

    QString message;
    if (!relaunchConfirmed) {
        message = tr(
            "A instalação da versão %1 terminou, mas o reinício automático "
            "do InputLeap não foi confirmado.").arg(version);
    }
    else {
        switch (result->outcome) {
        case UpdateInstallPolicy::MsiOutcome::Success:
            message = tr("A atualização para a versão %1 foi concluída com sucesso.")
                          .arg(version);
            break;
        case UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired:
            message = tr(
                "A atualização para a versão %1 foi instalada. "
                "Reinicie o Windows para concluir.").arg(version);
            break;
        case UpdateInstallPolicy::MsiOutcome::Cancelled:
            message = tr(
                "A atualização para a versão %1 foi cancelada. "
                "A versão anterior continua em uso.").arg(version);
            break;
        case UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall:
            message = tr(
                "A atualização para a versão %1 não foi instalada. "
                "A versão anterior continua em uso.").arg(version);
            break;
        case UpdateInstallPolicy::MsiOutcome::Failed:
            message = tr(
                "A atualização para a versão %1 falhou. "
                "A aplicação anterior verificada foi reaberta, mas a restauração "
                "completa do sistema não foi confirmada.").arg(version);
            break;
        }
    }
    setStatus(message);
    if (result->outcome == UpdateInstallPolicy::MsiOutcome::Success ||
        result->outcome ==
            UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired) {
        appendLogInfo(message);
    }
    else {
        appendLogError(message);
    }
}

bool MainWindow::launchUpdateHelper(const UpdateHelperInstruction& instruction,
                                    QString* error)
{
    const QByteArray encoded = UpdateHelperProtocol::serializeInstruction(instruction);
    if (!UpdateHelperProtocol::parseInstruction(encoded, error))
        return false;
    StagingDirectoryLock stagingLock(m_UpdateStagingDirectory);
    if (!stagingLock.valid()) {
        if (error)
            *error = QStringLiteral("staging namespace could not be locked");
        return false;
    }
    if (pathContainsWindowsReparsePoint(m_UpdateStagingDirectory) ||
        pathContainsWindowsReparsePoint(instruction.resultPath) ||
        pathContainsWindowsReparsePoint(instruction.readyPath)) {
        if (error)
            *error = QStringLiteral("staging namespace is not reparse-safe");
        return false;
    }
    const QString instructionPath = QDir(QFileInfo(instruction.msiPath).absolutePath())
        .filePath(QStringLiteral("install.instruction.json"));
    const auto removeStaleHandshake = [this](const QString& path) {
        if (!QFileInfo::exists(path))
            return true;
        if (pathContainsWindowsReparsePoint(m_UpdateStagingDirectory) ||
            pathContainsWindowsReparsePoint(path))
            return false;
        const bool removed = m_UpdateArtifactRemoveOverride
            ? m_UpdateArtifactRemoveOverride(path)
            : QFile::remove(path);
        return removed && !QFileInfo::exists(path);
    };
    if (!removeStaleHandshake(instruction.resultPath) ||
        !removeStaleHandshake(instruction.readyPath)) {
        if (error)
            *error = QStringLiteral("stale update handshake could not be removed");
        return false;
    }
    QSaveFile instructionFile(instructionPath);
    if (!instructionFile.open(QIODevice::WriteOnly) ||
        instructionFile.write(encoded) != encoded.size() ||
        pathContainsWindowsReparsePoint(m_UpdateStagingDirectory) ||
        pathContainsWindowsReparsePoint(instructionPath) ||
        !instructionFile.commit()) {
        instructionFile.cancelWriting();
        if (error) *error = QStringLiteral("instruction could not be persisted");
        return false;
    }
    if (!persistPendingUpdateResult(instruction, error)) {
        QFile::remove(instructionPath);
        return false;
    }
    if (m_UpdateHelperLaunchOverride)
        return m_UpdateHelperLaunchOverride(instruction, error);

#if defined(Q_OS_WIN)
    const QString sourceHelperPath = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("inputleap-update-helper.exe"));
    const QByteArray helperHash = updateFileSha256(sourceHelperPath);
    if (helperHash.size() != 32) {
        QFile::remove(instructionPath);
        if (error) *error = QStringLiteral("helper is unavailable");
        return false;
    }
    const QString helperPath = QDir(QFileInfo(instruction.msiPath).absolutePath())
        .filePath(QStringLiteral("inputleap-update-helper.exe"));
    if (pathContainsWindowsReparsePoint(m_UpdateStagingDirectory) ||
        pathContainsWindowsReparsePoint(helperPath)) {
        QFile::remove(instructionPath);
        if (error) *error = QStringLiteral("staging namespace changed");
        return false;
    }
    QFile sourceHelper(sourceHelperPath);
    QSaveFile stagedHelper(helperPath);
    bool copied = sourceHelper.open(QIODevice::ReadOnly) &&
        stagedHelper.open(QIODevice::WriteOnly);
    while (copied && !sourceHelper.atEnd()) {
        const QByteArray chunk = sourceHelper.read(64 * 1024);
        copied = !chunk.isEmpty() && stagedHelper.write(chunk) == chunk.size();
    }
    if (!copied || pathContainsWindowsReparsePoint(m_UpdateStagingDirectory) ||
        pathContainsWindowsReparsePoint(helperPath) || !stagedHelper.commit() ||
        updateFileSha256(helperPath) != helperHash) {
        stagedHelper.cancelWriting();
        QFile::remove(instructionPath);
        QFile::remove(helperPath);
        if (error) *error = QStringLiteral("helper could not be staged and verified");
        return false;
    }
    const QString pendingGroup = QStringLiteral("SecureUpdate/PendingResult");
    m_Settings.setValue(pendingGroup + QStringLiteral("/helperLaunchInFlight"), true);
    m_Settings.sync();
    if (m_Settings.status() != QSettings::NoError) {
        QFile::remove(instructionPath);
        QFile::remove(helperPath);
        if (error) *error = QStringLiteral("helper launch marker could not be persisted");
        return false;
    }
    const auto clearLaunchMarker = [this, &pendingGroup] {
        m_Settings.setValue(pendingGroup + QStringLiteral("/helperLaunchInFlight"), false);
        m_Settings.sync();
    };
    qint64 helperPid = 0;
    const bool started = QProcess::startDetached(
        helperPath, {QStringLiteral("--instruction"), instructionPath},
        QCoreApplication::applicationDirPath(), &helperPid);
    bool verified = false;
    for (int attempt = 0; started && attempt < 20 && !verified; ++attempt) {
        verified = updateProcessPathMatches(helperPid, helperPath) &&
                   updateFileSha256(helperPath) == helperHash;
        if (!verified) QThread::msleep(10);
    }
    if (!verified) {
        if (started && updateProcessPathMatches(helperPid, helperPath))
            terminateVerifiedUpdateProcess(helperPid, helperPath);
        clearLaunchMarker();
        if (error) *error = QStringLiteral("helper process identity was not verified");
        return false;
    }
    m_Settings.setValue(pendingGroup + QStringLiteral("/helperPid"), helperPid);
    m_Settings.setValue(pendingGroup + QStringLiteral("/helperPath"), helperPath);
    m_Settings.setValue(pendingGroup + QStringLiteral("/helperSha256"),
                        QString::fromLatin1(helperHash.toHex()));
    m_Settings.setValue(pendingGroup + QStringLiteral("/helperLaunchInFlight"), false);
    m_Settings.sync();
    if (m_Settings.status() != QSettings::NoError) {
        terminateVerifiedUpdateProcess(helperPid, helperPath);
        if (error) *error = QStringLiteral("helper process identity could not be persisted");
        return false;
    }
    const QByteArray expectedReady = QJsonDocument(QJsonObject{
        {QStringLiteral("nonce"), QString::fromLatin1(
            instruction.readyNonce.toBase64(
                QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))},
        {QStringLiteral("schema"), 1},
    }).toJson(QJsonDocument::Compact);
    QElapsedTimer handshakeTimer;
    handshakeTimer.start();
    while (handshakeTimer.elapsed() < 5000) {
        if (!updateProcessPathMatches(helperPid, helperPath)) break;
        QByteArray readyPayload;
        if (readResultPayloadWithIdentity(instruction.readyPath, readyPayload) &&
            readyPayload == expectedReady) {
            const bool safeToExit = m_RuntimeConsumersEnabled &&
                m_UpdateTransferBarrierActive &&
                !m_EnvironmentProfileIntegrationPolicy.hasActiveTransfers() &&
                m_TransferControllers.isEmpty() && !m_FileTransferReceiveBusy;
            if (!safeToExit) {
                terminateVerifiedUpdateProcess(helperPid, helperPath);
                if (error) *error = QStringLiteral(
                    "runtime conditions changed during helper handshake");
                return false;
            }
            return true;
        }
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 5);
        QThread::msleep(10);
    }
    terminateVerifiedUpdateProcess(helperPid, helperPath);
    if (error) *error = QStringLiteral("helper did not bind the parent process");
    return false;
#else
    QFile::remove(instructionPath);
    if (error) *error = QStringLiteral("installation is supported only on Windows");
    return false;
#endif
}

void MainWindow::showReleaseNotes()
{
    QMessageBox::information(
        this,
        tr("Novidades do InputLeap"),
        tr("InputLeap Modernized 3.7.0\n\n"
           "COMPUTADORES E CONEXÃO\n"
           "• Descoberta automática por identidade persistente, cartões reais e apelidos locais.\n"
           "• Pareamento guiado e reconexão resiliente após mudanças de rede.\n"
           "• Layout visual de telas e suporte a vários monitores por computador.\n\n"
           "SEGURANÇA E PRIVACIDADE\n"
           "• Sessões TLS autenticadas por dispositivo, sem downgrade para credenciais legadas.\n"
           "• Permissões por computador aplicadas nos consumidores reais.\n"
           "• Credenciais protegidas pelo Windows Credential Manager.\n\n"
           "TRANSFERÊNCIAS E PRODUTIVIDADE\n"
           "• Retomada, fila persistente, conflitos, deduplicação e histórico opcional.\n"
           "• Perfis de ambiente e exportação/importação com backup e rollback.\n\n"
           "CONFIABILIDADE\n"
           "• Diagnóstico orientado, recuperação segura e preparação de atualização verificada.\n"
           "• Interface e mensagens revisadas para uso simples em português."));
}

void MainWindow::autoAddScreen(const QString name)
{
    if (!m_ServerConfig.ignoreAutoConfigClient()) {
        int r = m_ServerConfig.autoAddScreen(name);
        if (r != kAutoAddScreenOk) {
            switch (r) {
            case kAutoAddScreenManualServer:
                showConfigureServer(
                    tr("Please add the server (%1) to the grid.")
                        .arg(appConfig().screenName()));
                break;

            case kAutoAddScreenManualClient:
                showConfigureServer(
                    tr("Please drag the new client screen (%1) "
                        "to the desired position on the grid.")
                        .arg(name));
                break;
            default:
                break;
            }
        }
        else {
            restart_cmd_app();
        }
    }
}

void MainWindow::showConfigureServer(const QString& message)
{
    ServerConfigDialog dlg(this, serverConfig(), appConfig().screenName(), m_DeviceRegistry.devices());
    dlg.message(message);
    dlg.exec();
}

void MainWindow::on_m_pButtonConfigureServer_clicked()
{
    showConfigureServer();
}

void MainWindow::on_m_pButtonReload_clicked()
{
    restart_cmd_app();
}

#if defined(Q_OS_WIN)
bool MainWindow::isServiceRunning(QString name)
{
    SC_HANDLE hSCManager;
    hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCManager == nullptr) {
        appendLogError("failed to open a service controller manager, error: " +
            GetLastError());
        return false;
    }

    auto array = name.toLocal8Bit();

#if QT_VERSION_MAJOR < 6
    SC_HANDLE hService = OpenService(hSCManager, array.data(), SERVICE_QUERY_STATUS);
#else
    SC_HANDLE hService = OpenService(hSCManager, reinterpret_cast<LPCWSTR>(array.data()), SERVICE_QUERY_STATUS);
#endif
    if (hService == nullptr) {
        appendLogDebug("failed to open service: " + name);
        return false;
    }

    SERVICE_STATUS status;
    if (QueryServiceStatus(hService, &status)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            return true;
        }
    }

    return false;
}
#else
bool MainWindow::isServiceRunning()
{
    return false;
}
#endif

bool MainWindow::isBonjourRunning()
{
    bool result = false;

#if defined(Q_OS_WIN)
    result = isServiceRunning("Bonjour Service");
#else
    result = true;
#endif

    return result;
}

void MainWindow::downloadBonjour()
{
    if (!m_RuntimeConsumersEnabled) return;
#if defined(Q_OS_WIN)
    QUrl url;
    int arch = getProcessorArch();
    if (arch == kProcessorArchWin32) {
        url.setUrl(bonjourBaseUrl + bonjourFilename32);
        appendLogInfo("downloading 32-bit Bonjour");
    }
    else if (arch == kProcessorArchWin64) {
        url.setUrl(bonjourBaseUrl + bonjourFilename64);
        appendLogInfo("downloading 64-bit Bonjour");
    }
    else {
        QMessageBox::critical(
            this, tr("InputLeap"),
            tr("Failed to detect system architecture."));
        return;
    }

    if (m_pDataDownloader == nullptr) {
        m_pDataDownloader = new DataDownloader(this);
        connect(m_pDataDownloader, &DataDownloader::isComplete, this, &MainWindow::installBonjour);
    }

    m_pDataDownloader->download(url);

    if (m_DownloadMessageBox == nullptr) {
        m_DownloadMessageBox = new QMessageBox(this);
        m_DownloadMessageBox->setWindowTitle("InputLeap");
        m_DownloadMessageBox->setIcon(QMessageBox::Information);
        m_DownloadMessageBox->setText("Installing Bonjour, please wait...");
#if QT_VERSION_MAJOR < 6
        m_DownloadMessageBox->setStandardButtons(0);
#else
        m_DownloadMessageBox->setStandardButtons(QMessageBox::NoButton);
#endif
        m_pCancelButton = m_DownloadMessageBox->addButton(
            tr("Cancel"), QMessageBox::RejectRole);
    }
    m_DownloadMessageBox->exec();

    if (m_DownloadMessageBox->clickedButton() == m_pCancelButton) {
        m_pDataDownloader->cancel();
    }
#endif
}

void MainWindow::installBonjour()
{
    if (!m_RuntimeConsumersEnabled) return;
#if defined(Q_OS_WIN)
#if QT_VERSION >= 0x050000
    QString tempLocation = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
#else
    QString tempLocation = QDesktopServices::storageLocation(
                                QDesktopServices::TempLocation);
#endif
    QString filename = tempLocation;
    filename.append("\\").append(bonjourTargetFilename);
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
        m_DownloadMessageBox->hide();

        QMessageBox::warning(
            this, "InputLeap",
            tr("Failed to download Bonjour installer to location: %1")
            .arg(tempLocation));
        return;
    }

    file.write(m_pDataDownloader->data());
    file.close();

    QStringList arguments;
    arguments.append("/i");
    QString winFilename = QDir::toNativeSeparators(filename);
    arguments.append(winFilename);
    arguments.append("/passive");
    if (m_BonjourInstall == nullptr) {
        m_BonjourInstall = new CommandProcess("msiexec", arguments);
    }

    QThread* thread = new QThread;
    connect(m_BonjourInstall, &CommandProcess::finished, this, &MainWindow::bonjourInstallFinished);
    connect(m_BonjourInstall, &CommandProcess::finished, thread, &QThread::quit);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    m_BonjourInstall->moveToThread(thread);
    thread->start();

    QMetaObject::invokeMethod(m_BonjourInstall, "run", Qt::QueuedConnection);

    m_DownloadMessageBox->hide();
#endif
}

void MainWindow::promptAutoConfig()
{
    if (!m_RuntimeConsumersEnabled) return;
    if (!isBonjourRunning()) {
        int r = QMessageBox::question(
            this, tr("InputLeap"),
            tr("Do you want to enable auto config and install Bonjour?\n\n"
               "This feature helps you establish the connection."),
            QMessageBox::Yes | QMessageBox::No);

        if (r == QMessageBox::Yes) {
            m_AppConfig->setAutoConfig(true);
            downloadBonjour();
        }
        else {
            m_AppConfig->setAutoConfig(false);
            ui_->m_pCheckBoxAutoConfig->setChecked(false);
        }
    }

    m_AppConfig->setAutoConfigPrompted(true);
}

void MainWindow::comboServerList_currentIndexChanged(QString )
{
    if (ui_->m_pComboServerList->count() != 0) {
        settings().setValue("serverHostname", ui_->m_pComboServerList->currentText().trimmed());
        settings().sync();
        restart_cmd_app();
    }
}

void MainWindow::on_m_pCheckBoxAutoConfig_toggled(bool checked)
{
    if (!m_RuntimeConsumersEnabled) return;
    if (!isBonjourRunning() && checked) {
        if (!m_SuppressAutoConfigWarning) {
            int r = QMessageBox::information(
                this, tr("InputLeap"),
                tr("Auto config feature requires Bonjour.\n\n"
                   "Do you want to install Bonjour?"),
                QMessageBox::Yes | QMessageBox::No);

            if (r == QMessageBox::Yes) {
                downloadBonjour();
            }
        }

        ui_->m_pCheckBoxAutoConfig->setChecked(false);
        return;
    }

    ui_->m_pLineEditHostname->setDisabled(checked);
    appConfig().setAutoConfig(checked);
    updateZeroconfService();

    if (!checked) {
        ui_->m_pComboServerList->clear();
        ui_->m_pComboServerList->hide();
    }
}

void MainWindow::bonjourInstallFinished()
{
    appendLogInfo("Bonjour install finished");

    ui_->m_pCheckBoxAutoConfig->setChecked(true);
}

void MainWindow::windowStateChanged()
{
    if (windowState() == Qt::WindowMinimized && appConfig().getMinimizeToTray())
        hide();
}

void MainWindow::showLogWindow()
{
    m_pLogWindow->show();
}
