#include "AppConfig.h"
#include "DeviceRegistry.h"
#include "FileTransferController.h"
#include "LocalDeviceIdentity.h"
#include "MainWindow.h"
#include "PairingWizard.h"
#include "ProtectionPanel.h"
#include "QInputLeapApplication.h"
#include "RecoveryArtifactAuthenticator.h"
#include "SettingsDialog.h"
#include "SetupWizard.h"
#include "TransferQueue.h"
#include "UpdateDownloadService.h"
#include "UpdateHelperProtocol.h"
#include "UpdateTrustConfig.h"

#include <gtest/gtest.h>

#include <QApplication>
#include <QAction>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QScrollArea>
#include <QMenu>
#include <QRadioButton>
#include <QPushButton>
#include <QScrollBar>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtEndian>
#include <QtTest>

#include <algorithm>
#include <cstring>
#include <utility>

namespace {
constexpr quint16 kInstalledFileTransferPort = 24810;

class SessionUpdateReply final : public QNetworkReply
{
public:
    SessionUpdateReply(const QNetworkRequest& request, QByteArray body, int status,
                       QString contentType, QByteArray etag, QObject* parent)
        : QNetworkReply(parent), body_(std::move(body))
    {
        setRequest(request);
        setUrl(request.url());
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
        setRawHeader(QByteArrayLiteral("Content-Type"), contentType.toLatin1());
        setRawHeader(QByteArrayLiteral("Content-Length"), QByteArray::number(body_.size()));
        if (!etag.isEmpty()) setRawHeader(QByteArrayLiteral("ETag"), etag);
        open(QIODevice::ReadOnly);
        QTimer::singleShot(0, this, [this] {
            Q_EMIT readyRead();
            setFinished(true);
            Q_EMIT finished();
        });
    }

    void abort() override { setError(OperationCanceledError, QStringLiteral("cancelled")); }
    qint64 bytesAvailable() const override
    {
        return body_.size() - offset_ + QNetworkReply::bytesAvailable();
    }

protected:
    qint64 readData(char* data, qint64 maxSize) override
    {
        const qint64 count = qMin(maxSize, qint64(body_.size() - offset_));
        if (count <= 0)
            return -1;
        std::memcpy(data, body_.constData() + offset_, size_t(count));
        offset_ += count;
        return count;
    }

private:
    QByteArray body_;
    qint64 offset_ = 0;
};

class SessionUpdateNetwork final : public QNetworkAccessManager
{
public:
    QByteArray response;
    int status = 200;
    QString contentType = QStringLiteral("application/json");
    QByteArray etag;
    QList<QNetworkRequest> requests;

protected:
    QNetworkReply* createRequest(Operation, const QNetworkRequest& request,
                                 QIODevice*) override
    {
        requests.append(request);
        return new SessionUpdateReply(request, response, status, contentType, etag, this);
    }
};

QByteArray sessionStopNonce(const QByteArray& wire)
{
    const qsizetype offset = wire.indexOf(QByteArrayLiteral("ISTP"));
    if (offset < 0 || wire.size() < offset + 24) return {};
    const auto length = qFromBigEndian<quint32>(
        reinterpret_cast<const uchar*>(wire.constData() + offset + 4));
    return length == 16 ? wire.mid(offset + 8, 16) : QByteArray{};
}

QByteArray sessionAppliedAcknowledgement(const QByteArray& nonce)
{
    QByteArray frame = QByteArrayLiteral("IACK");
    const quint32 length = static_cast<quint32>(nonce.size());
    frame.append(char((length >> 24) & 0xff));
    frame.append(char((length >> 16) & 0xff));
    frame.append(char((length >> 8) & 0xff));
    frame.append(char(length & 0xff));
    frame.append(nonce);
    return frame;
}
}

struct MainWindowEnvironmentProfileSessionTestAccess
{
    static void seed(MainWindow& window, const QUuid& uuid, const QByteArray& key)
    {
        QByteArray independentKey = key;
        independentKey.detach();
        window.m_PairedSessions.insert(uuid, MainWindow::PairedSession{std::move(independentKey)});
    }

    static std::pair<FileTransferController*, QByteArray> trackDirectController(MainWindow& window)
    {
        auto* controller = new FileTransferController(&window);
        return {controller, window.trackTransferController(controller, {})};
    }

    static bool hasShutdownIntent(const MainWindow& window, const QByteArray& key)
    {
        return window.m_TransferCancelIntents.value(key) ==
               MainWindow::TransferCancelIntent::Shutdown;
    }

    static QByteArray key(const MainWindow& window, const QUuid& uuid)
    {
        const auto it = window.m_PairedSessions.constFind(uuid);
        return it == window.m_PairedSessions.cend() ? QByteArray{} : it->key;
    }

    static bool initialized(const MainWindow& window)
    {
        return window.m_EnvironmentProfilesInitialized;
    }

    static QString runtimeBlockMessage(const MainWindow& window)
    {
        return window.m_RuntimeBlockMessage;
    }

    static EnvironmentProfileController& controller(MainWindow& window)
    {
        return window.m_EnvironmentProfileController;
    }

    static bool selectInternalServer(MainWindow& window)
    {
        window.setServerMode(true);
        auto* internal = window.findChild<QRadioButton*>(
            QStringLiteral("m_pRadioInternalConfig"));
        if (internal == nullptr) return false;
        internal->setChecked(true);
        return internal->isChecked();
    }

    static void selectClient(MainWindow& window)
    {
        window.setServerMode(false);
    }

    static bool configureInvalidClientStart(MainWindow& window)
    {
        selectClient(window);
        auto* automatic = window.findChild<QCheckBox*>(
            QStringLiteral("m_pCheckBoxAutoConfig"));
        auto* hostname = window.findChild<QLineEdit*>(
            QStringLiteral("m_pLineEditHostname"));
        if (automatic == nullptr || hostname == nullptr) return false;
        automatic->setChecked(false);
        hostname->clear();
        window.m_SuppressEmptyServerWarning = true;
        return true;
    }

    static bool configureClientStart(MainWindow& window, const QString& hostname)
    {
        selectClient(window);
        auto* automatic = window.findChild<QCheckBox*>(
            QStringLiteral("m_pCheckBoxAutoConfig"));
        auto* host = window.findChild<QLineEdit*>(
            QStringLiteral("m_pLineEditHostname"));
        if (automatic == nullptr || host == nullptr) return false;
        automatic->setChecked(false);
        host->setText(hostname);
        return true;
    }

    static void setProcessMode(AppConfig& config, ProcessMode mode)
    {
        config.m_ProcessMode = mode;
    }
    static void markAutoConfigPrompted(AppConfig& config)
    {
        config.m_AutoConfigPrompted = true;
    }
    static void markStartedBefore(AppConfig& config)
    {
        config.setStartedBefore(true);
    }
    static void useExecutable(MainWindow& window, const QString& executable)
    {
        window.m_AppPathResolver = [executable](const QString&) { return executable; };
    }
    static void useExecutableWithArguments(MainWindow& window, const QString& executable,
                                           const QStringList& arguments)
    {
        useExecutable(window, executable);
        window.m_AppArgumentsOverride = [arguments](const QStringList&) { return arguments; };
    }
    static void observeServiceReconnect(MainWindow& window, std::function<void()> observer)
    {
        window.m_ServiceReconnectOverride = std::move(observer);
    }
    static void clearDesktopProcessDuringStopWait(MainWindow& window)
    {
        window.m_DesktopStopPostWaitHook = [&window] {
            if (window.cmd_app_process_ == nullptr) return;
            window.cmd_app_process_->kill();
            window.cmd_app_process_->waitForFinished(3000);
        };
    }
    static bool loadedPairingSecretPresent(const AppConfig& config)
    {
        return config.m_LoadedPairingSecret.has_value() &&
               !config.m_LoadedPairingSecret->isEmpty();
    }

    static void reportServiceDisconnected(MainWindow& window)
    {
        Q_EMIT window.m_IpcClient.startCommandApplied();
        window.handleCoreConnectionState(
            IpcConnectionState::Disconnected, IpcConnectionRole::ServerPeer,
            QString(), QStringLiteral("service rejected start"),
            IpcIdentityPresence::Known);
    }
    static void reportServiceStarted(MainWindow& window)
    {
        Q_EMIT window.m_IpcClient.startCommandApplied();
        window.handleCoreConnectionState(
            IpcConnectionState::Connected, IpcConnectionRole::ServerPeer,
            QStringLiteral("peer"), QStringLiteral("service started"),
            IpcIdentityPresence::Known);
    }
    static void reportUnacknowledgedServiceStarted(MainWindow& window)
    {
        window.handleCoreConnectionState(
            IpcConnectionState::Connected, IpcConnectionRole::ServerPeer,
            QStringLiteral("peer"), QStringLiteral("service started"),
            IpcIdentityPresence::Known);
    }

    static void reportServiceReconnectReady(MainWindow& window)
    {
        window.handleServiceReconnectReady();
    }

    static void reportServiceStartTimeout(MainWindow& window)
    {
        window.handleServiceStartTimeout(window.m_ServiceStartGeneration);
    }

    static void reportUnexpectedDesktopExit(MainWindow& window)
    {
        window.m_ExpectedRunningState = MainWindow::kStarted;
        window.m_LastStartSucceeded = true;
        window.set_connection_state(AppConnectionState::CONNECTING);
        window.cmd_app_finished(1, QProcess::CrashExit);
    }

    static void reportUnexpectedDesktopNormalFailure(MainWindow& window)
    {
        window.m_ExpectedRunningState = MainWindow::kStarted;
        window.m_LastStartSucceeded = true;
        window.set_connection_state(AppConnectionState::CONNECTING);
        window.cmd_app_finished(1, QProcess::NormalExit);
    }

    static bool environmentProfileBusy(const MainWindow& window)
    {
        return window.environmentProfileBusy();
    }

    static bool selectExternalServer(MainWindow& window)
    {
        window.setServerMode(true);
        auto* external = window.findChild<QRadioButton*>(
            QStringLiteral("m_pRadioExternalConfig"));
        if (external == nullptr) return false;
        external->setChecked(true);
        return external->isChecked();
    }

    static void start(MainWindow& window) { window.start_cmd_app(); }
    static void stop(MainWindow& window) { window.stop_cmd_app(); }
    static void restart(MainWindow& window) { window.restart_cmd_app(); }
    static void acceptFingerprint(MainWindow& window)
    {
        window.restartAfterFingerprintAcceptance();
    }
    static void useFingerprintDialog(MainWindow& window, std::function<int()> exec)
    {
        window.m_FingerprintDialogExecOverride = std::move(exec);
    }
    static void useFingerprintTrustStore(MainWindow& window,
                                         std::function<bool(bool)> access)
    {
        window.m_FingerprintTrustOverride = std::move(access);
    }
    static void processUntrustedFingerprint(MainWindow& window)
    {
        window.checkFingerprint(QStringLiteral(
            "peer fingerprint (SHA1): AA:BB (SHA256): CC:DD"));
    }
    static void invalidateRuntime(MainWindow& window)
    {
        window.handleRuntimeInvalidation();
    }
    static void reportConnected(MainWindow& window)
    {
        window.m_ExpectedRunningState = MainWindow::kStarted;
        window.set_connection_state(AppConnectionState::CONNECTED);
    }
    static void reportServiceTransportUnavailable(MainWindow& window)
    {
        Q_EMIT window.m_IpcClient.transportUnavailable();
    }
    static void failTemporaryConfigCreation(MainWindow& window)
    {
        window.m_TempConfigFileFactory = [] { return nullptr; };
    }
    static bool expectedStopped(const MainWindow& window)
    {
        return window.m_ExpectedRunningState == MainWindow::kStopped;
    }
    static bool processCreated(const MainWindow& window)
    {
        return window.cmd_app_process_ != nullptr;
    }
    static bool installRunningDesktopProcess(MainWindow& window)
    {
        auto* process = new QProcess(&window);
        window.cmd_app_process_ = process;
        QObject::connect(process,
                         QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                         &window, &MainWindow::cmd_app_finished);
        process->start(QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH),
                       {QStringLiteral("--wait")});
        if (!process->waitForStarted(3000)) return false;
        window.m_ExpectedRunningState = MainWindow::kStarted;
        return true;
    }
    static bool lastStartSucceeded(const MainWindow& window)
    {
        return window.m_LastStartSucceeded;
    }
    static bool serviceStartPending(const MainWindow& window)
    {
        return window.m_ServiceStartPending;
    }
    static bool serviceStopPending(const MainWindow& window)
    {
        return window.m_ServiceStopPending;
    }
    static bool serviceStopUnconfirmed(const MainWindow& window)
    {
        return window.m_ServiceStopUnconfirmed;
    }
    static void reportServiceStopTimeout(MainWindow& window)
    {
        window.handleServiceStopTimeout(window.m_ServiceStopGeneration);
    }
    static quint64 serviceStopGeneration(const MainWindow& window)
    {
        return window.m_ServiceStopGeneration;
    }
    static int serviceStopConfirmationTimeoutMs()
    {
        return MainWindow::kServiceStopConfirmationTimeoutMs;
    }
    static int serviceStartConfirmationTimeoutMs()
    {
        return MainWindow::kServiceStartConfirmationTimeoutMs;
    }
    static bool serviceRestartPending(const MainWindow& window)
    {
        return window.m_ServiceRestartPending;
    }
    static bool serviceRestartAwaitingReconnect(const MainWindow& window)
    {
        return window.m_ServiceRestartAwaitingReconnect;
    }
    static bool internalReconnect(const MainWindow& window)
    {
        return window.m_InternalReconnect;
    }
    static bool startActionEnabled(const MainWindow& window)
    {
        const auto* action = window.findChild<QAction*>(
            QStringLiteral("m_pActionStartCmdApp"));
        return action != nullptr && action->isEnabled();
    }
    static bool stopActionEnabled(const MainWindow& window)
    {
        const auto* action = window.findChild<QAction*>(
            QStringLiteral("m_pActionStopCmdApp"));
        return action != nullptr && action->isEnabled();
    }
    static AppConnectionState connectionState(const MainWindow& window)
    {
        return window.connection_state_;
    }
    static quint16 fileTransferPort(const MainWindow& window)
    {
        return window.m_pFileTransferService->port();
    }
    static bool updateTransferBarrierActive(const MainWindow& window)
    {
        return window.m_UpdateTransferBarrierActive;
    }
    static bool transferQueueShuttingDown(const MainWindow& window)
    {
        return window.m_TransferQueueShuttingDown;
    }
    static bool legacyPairingEnabled(const MainWindow& window)
    {
        return window.m_pFileTransferService->legacyPairingEnabled();
    }
    static bool runtimeConsumersEnabled(const MainWindow& window)
    {
        return window.m_RuntimeConsumersEnabled;
    }
    static bool zeroconfCreated(const MainWindow& window)
    {
        return window.m_pZeroconfService != nullptr;
    }
    static void invokePersistentSaves(MainWindow& window)
    {
        window.saveSettings();
        window.saveTransferHistory();
    }
    static int trayActionCount(const MainWindow& window)
    {
        return window.m_pTrayIconMenu == nullptr
            ? 0 : window.m_pTrayIconMenu->actions().size();
    }
    static QStringList trayActionTexts(const MainWindow& window)
    {
        QStringList texts;
        if (window.m_pTrayIconMenu == nullptr)
            return texts;
        for (const QAction* action : window.m_pTrayIconMenu->actions()) {
            if (!action->isSeparator()) {
                QString text = action->text();
                text.remove(QLatin1Char('&'));
                texts.append(text);
            }
        }
        return texts;
    }
    static bool trayContainsWindowAction(const MainWindow& window,
                                         const char* objectName)
    {
        if (window.m_pTrayIconMenu == nullptr)
            return false;
        const auto* action = window.findChild<QAction*>(
            QString::fromLatin1(objectName));
        return action != nullptr && window.m_pTrayIconMenu->actions().contains(action);
    }
    static void createTray(MainWindow& window) { window.createTrayIcon(); }
    static void showTransferQueue(MainWindow& window) { window.showTransferQueue(); }
    static bool transferQueueDialogVisible(const MainWindow& window)
    {
        return window.m_pTransferQueueDialog && !window.m_pTransferQueueDialog->isHidden();
    }
    static bool transferQueuePersistenceEnabled(const MainWindow& window)
    {
        return window.m_TransferQueue && window.m_TransferQueue->persistenceEnabled();
    }
    static bool transferQueueActionEnabled(const MainWindow& window)
    {
        return window.m_pActionTransferQueue && window.m_pActionTransferQueue->isEnabled();
    }
    static void armReconnectTimers(MainWindow& window)
    {
        if (window.m_ReconnectTimer) window.m_ReconnectTimer->start(60000);
        if (window.m_ReconnectCountdownTimer) window.m_ReconnectCountdownTimer->start(60000);
        if (window.m_ReconnectStableTimer) window.m_ReconnectStableTimer->start(60000);
    }
    static bool reconnectTimersActive(const MainWindow& window)
    {
        return (window.m_ReconnectTimer && window.m_ReconnectTimer->isActive()) ||
               (window.m_ReconnectCountdownTimer && window.m_ReconnectCountdownTimer->isActive()) ||
               (window.m_ReconnectStableTimer && window.m_ReconnectStableTimer->isActive());
    }
    static void createPairingWizard(MainWindow& window)
    {
        window.m_ActivePairingWizard = new PairingWizard(
            QUuid(QStringLiteral("{33333333-3333-3333-3333-333333333333}")),
            QUuid(QStringLiteral("{44444444-4444-4444-4444-444444444444}")),
            QHostAddress::Any, &window);
    }
    static bool pairingWizardAlive(const MainWindow& window)
    {
        return !window.m_ActivePairingWizard.isNull();
    }
    static SettingsDialog* createSettingsDialog(MainWindow& window)
    {
        auto* dialog = new SettingsDialog(
            &window, *window.m_AppConfig, &window.m_EnvironmentProfileController,
            window.m_EnvironmentProfilesInitialized, window.environmentProfileBusy(), false);
        window.m_ActiveSettingsDialog = dialog;
        return dialog;
    }
    static bool settingsDialogAlive(const MainWindow& window)
    {
        return !window.m_ActiveSettingsDialog.isNull();
    }
    static int pairedSessionCount(const MainWindow& window)
    {
        return window.m_PairedSessions.size();
    }
    static void startDirectTransfer(MainWindow& window, const QString& sourcePath,
                                    const QUuid& peerUuid, quint16 port)
    {
        FileTransferService::TransferItem item;
        item.sourcePath = sourcePath;
        item.relativePath = QStringLiteral("direct.txt");
        window.startFileTransfer(
            QStringLiteral("127.0.0.1"), {item}, QStringLiteral("direct"),
            QStringLiteral("done"), QStringLiteral("failed"),
            QStringLiteral("cancelled"), QStringLiteral("direct.txt"),
            QFileInfo(sourcePath).absolutePath(), peerUuid, port);
    }
    static int activeTransferControllerCount(const MainWindow& window)
    {
        return window.m_TransferControllers.size();
    }
    static bool sslCertificateCreated(const MainWindow& window)
    {
        return window.m_pSslCertificate != nullptr;
    }
    static QByteArray seedInvalidQueuedTransfer(MainWindow& window,
                                                const QString& storePath)
    {
        window.m_TransferQueue = std::make_unique<TransferQueue>(storePath);
        TransferQueue::Item item;
        item.transferId = TransferQueue::newTransferId();
        item.peerUuid = QUuid(QStringLiteral("{22222222-2222-2222-2222-222222222222}"));
        item.displayName = QStringLiteral("missing.txt");
        item.sources = {{storePath + QStringLiteral(".missing"),
                         QStringLiteral("missing-file.txt")}};
        item.state = TransferQueue::State::Pending;
        item.userEnqueued = true;
        item.createdAtUtc = QDateTime::currentDateTimeUtc();
        item.updatedAtUtc = item.createdAtUtc;
        return window.m_TransferQueue->enqueue(item) ? item.transferId : QByteArray{};
    }
    static void dispatchTransfers(MainWindow& window)
    {
        window.dispatchNextTransfer();
    }
    static std::optional<TransferQueue::State> queuedState(
        const MainWindow& window, const QByteArray& id)
    {
        const auto item = window.m_TransferQueue->find(id);
        return item ? std::optional<TransferQueue::State>{item->state} : std::nullopt;
    }
    static QString dashboardState(const MainWindow& window)
    {
        return window.m_pDashboardState == nullptr
            ? QString() : window.m_pDashboardState->text();
    }
    static QString connectedDashboardDetail(MainWindow& window)
    {
        QLabel detail(&window);
        window.m_pDashboardRemote = &detail;
        window.updateDashboardState(DeviceConnectionModel::State::Connected);
        window.m_pDashboardRemote = nullptr;
        return detail.text();
    }
    static bool padlockExplicitlyHidden(const MainWindow& window)
    {
        const auto* padlock = window.findChild<QLabel*>(
            QStringLiteral("m_pLabelPadlock"));
        return padlock != nullptr && padlock->isHidden();
    }
    static QString protectionBadge(const MainWindow& window)
    {
        return window.m_pSecurityBadge == nullptr
            ? QString() : window.m_pSecurityBadge->text();
    }
    static QString statusText(const MainWindow& window)
    {
        const auto* label = window.findChild<QLabel*>(QStringLiteral("m_pStatusLabel"));
        return label == nullptr ? QString() : label->text();
    }
    static int transferHistoryCount(const MainWindow& window)
    {
        return window.m_TransferHistory.size();
    }
    static QString latestTransferStatus(const MainWindow& window)
    {
        return window.m_TransferHistory.isEmpty()?QString():window.m_TransferHistory.first().value(4);
    }
    static QString latestTransferPath(const MainWindow& window)
    {
        return window.m_TransferHistory.isEmpty()?QString():window.m_TransferHistory.first().value(5);
    }
    static QString lastReceivedFolder(const MainWindow& window)
    {
        return window.m_LastReceivedFilesFolder;
    }
    static QString latestTransferPeer(const MainWindow& window)
    {
        return window.m_TransferHistory.isEmpty()?QString():window.m_TransferHistory.first().value(3);
    }
    static bool receiveBusy(const MainWindow& window)
    {
        return window.m_FileTransferReceiveBusy;
    }
    static bool receivedNotificationOpenable(const MainWindow& window)
    {
        return window.m_ReceivedFileNotificationOpenable;
    }
    static void emitLateReceiverCallbacks(MainWindow& window,
                                          const QUuid& peerUuid)
    {
        ASSERT_NE(window.m_pFileTransferService, nullptr);
        Q_EMIT window.m_pFileTransferService->receivingStarted(
            QStringLiteral("late.bin"), 1024);
        Q_EMIT window.m_pFileTransferService->receivingProgress(
            QStringLiteral("late.bin"), 512, 1024);
        Q_EMIT window.m_pFileTransferService->fileRejected(
            QStringLiteral("late.bin"), QStringLiteral("192.0.2.10"));
        Q_EMIT window.m_pFileTransferService->fileReceived(
            QStringLiteral("late.bin"), QStringLiteral("C:/late/late.bin"),
            true, peerUuid);
    }
    static void emitRecoveryRequired(MainWindow& window,const QString& recoveryPath)
    {
        ASSERT_NE(window.m_pFileTransferService,nullptr);
        const QString fileName=QStringLiteral("important.bin");
        const QByteArray transferId=QByteArrayLiteral("recovery-required-transfer");
        Q_EMIT window.m_pFileTransferService->publicationCompleted(fileName,
            {FileTransferService::PublicationStatus::RecoveryRequired,
             QStringLiteral("C:/received/important.bin"),recoveryPath,
             QUuid(QStringLiteral("{11111111-1111-1111-1111-111111111111}")),transferId});
        Q_EMIT window.m_pFileTransferService->fileRejected(
            fileName,QStringLiteral("192.0.2.10"),transferId);
    }
    static void emitReviewRequired(MainWindow& window,const QString& destinationPath)
    {
        ASSERT_NE(window.m_pFileTransferService,nullptr);
        const QString fileName=QStringLiteral("indeterminate.bin");
        const QByteArray transferId=QByteArrayLiteral("review-required-transfer");
        Q_EMIT window.m_pFileTransferService->publicationCompleted(fileName,
            {FileTransferService::PublicationStatus::ReviewRequired,destinationPath,{},
             QUuid(QStringLiteral("{66666666-6666-6666-6666-666666666666}")),transferId});
        Q_EMIT window.m_pFileTransferService->fileRejected(
            fileName,QStringLiteral("192.0.2.12"),transferId);
    }
    static void emitUnchanged(MainWindow& window,const QString& destinationPath)
    {
        const QString fileName=QStringLiteral("unchanged.bin");
        const QByteArray transferId=QByteArrayLiteral("unchanged-transfer");
        Q_EMIT window.m_pFileTransferService->publicationCompleted(fileName,
            {FileTransferService::PublicationStatus::Unchanged,destinationPath,{},
             QUuid(QStringLiteral("{77777777-7777-7777-7777-777777777777}")),transferId});
        Q_EMIT window.m_pFileTransferService->fileRejected(
            fileName,QStringLiteral("192.0.2.13"),transferId);
    }
    static void emitFailedVerification(MainWindow& window,const QString& destinationPath)
    {
        Q_EMIT window.m_pFileTransferService->fileReceived(
            QStringLiteral("invalid.bin"),destinationPath,false,
            QUuid(QStringLiteral("{88888888-8888-8888-8888-888888888888}")),
            QByteArrayLiteral("failed-verification-transfer"));
    }
    static void emitCommittedWithRecovery(MainWindow& window,const QString& destinationPath,
                                          const QString& recoveryPath)
    {
        ASSERT_NE(window.m_pFileTransferService,nullptr);
        const QString fileName=QStringLiteral("committed.bin");
        const QUuid peer(QStringLiteral("{22222222-2222-2222-2222-222222222222}"));
        const QByteArray transferId=QByteArrayLiteral("committed-recovery-transfer");
        Q_EMIT window.m_pFileTransferService->publicationCompleted(fileName,
            {FileTransferService::PublicationStatus::CommittedWithRecovery,
             destinationPath,recoveryPath,peer,transferId});
        Q_EMIT window.m_pFileTransferService->fileReceived(
            fileName,destinationPath,true,peer,transferId);
    }
    static void queueSameNamePublicationOutcomes(MainWindow& window,
                                                 const QString& failedRecovery,
                                                 const QString& committedDestination,
                                                 const QString& committedRecovery)
    {
        const QString fileName=QStringLiteral("same-name.bin");
        Q_EMIT window.m_pFileTransferService->publicationCompleted(fileName,
            {FileTransferService::PublicationStatus::RecoveryRequired,
             QStringLiteral("C:/received/same-name.bin"),failedRecovery,
             QUuid(QStringLiteral("{33333333-3333-3333-3333-333333333333}")),
             QByteArrayLiteral("same-name-failed")});
        Q_EMIT window.m_pFileTransferService->publicationCompleted(fileName,
            {FileTransferService::PublicationStatus::CommittedWithRecovery,
             committedDestination,committedRecovery,
             QUuid(QStringLiteral("{44444444-4444-4444-4444-444444444444}")),
             QByteArrayLiteral("same-name-committed")});
    }
    static void emitSameNameCommitted(MainWindow& window,const QString& destinationPath)
    {
        Q_EMIT window.m_pFileTransferService->fileReceived(
            QStringLiteral("same-name.bin"),destinationPath,true,
            QUuid(QStringLiteral("{44444444-4444-4444-4444-444444444444}")),
            QByteArrayLiteral("same-name-committed"));
    }
    static void emitSameNameRejected(MainWindow& window)
    {
        Q_EMIT window.m_pFileTransferService->fileRejected(
            QStringLiteral("same-name.bin"),QStringLiteral("192.0.2.11"),
            QByteArrayLiteral("same-name-failed"));
    }
    static QUuid emitVerifiedWithoutOutcome(MainWindow& window)
    {
        const QUuid peer(QStringLiteral("{55555555-5555-5555-5555-555555555555}"));
        Q_EMIT window.m_pFileTransferService->fileReceived(
            QStringLiteral("orphan.bin"),QStringLiteral("C:/received/orphan.bin"),true,
            peer,QByteArrayLiteral("orphan-transfer"));
        return peer;
    }
    static void emitServiceStopConfirmed(MainWindow& window)
    {
        Q_EMIT window.m_IpcClient.commandApplied();
    }

    static QUuid authorizeAutomaticReconnect(MainWindow& window)
    {
        const QUuid uuid(QStringLiteral("{88888888-8888-8888-8888-888888888888}"));
        window.m_DeviceAllowsOverride = [uuid](
            const QUuid& candidate, DevicePermissions::Permission permission) {
            return candidate == uuid && permission == DevicePermissions::AutoConnect;
        };
        return uuid;
    }

    static bool reconnect(MainWindow& window, const QUuid& uuid,
                          const QString& endpoint)
    {
        window.m_ReconnectTargetUuid = uuid;
        return window.performReconnectAttempt(endpoint);
    }
    static void deliverUpdateResult(MainWindow& window,
                                    const UpdateService::Result& result)
    {
        window.handleUpdateCheckFinished(result);
    }
    static void installUpdateNetwork(MainWindow& window, QNetworkAccessManager* network,
                                     const QString& replayPath,
                                     const QString& currentVersion = QStringLiteral(INPUTLEAP_VERSION))
    {
        delete window.m_pUpdateService;
        const UpdateTrustConfig config = UpdateTrustConfig::production();
        window.m_UpdateReplayStore = std::make_unique<UpdateReplayStore>(
            replayPath, window.appConfig().m_CredentialStore,
            replayPath + QStringLiteral(".anchor"));
        window.m_pUpdateNetwork = network;
        window.m_pUpdateService = new UpdateService(
            network, config.trustedKeys, currentVersion, &window,
            window.m_UpdateReplayStore.get(), config.minimumValidSignatures);
        QObject::connect(window.m_pUpdateService, &UpdateService::checkFinished,
                         &window, &MainWindow::handleUpdateCheckFinished);
        window.m_UpdateStagingDirectory = QFileInfo(replayPath).dir()
            .filePath(QStringLiteral("update-staging"));
        window.m_UpdateDownloadService = std::make_unique<UpdateDownloadService>(
            network, window.m_UpdateStagingDirectory);
        QObject::connect(window.m_UpdateDownloadService.get(),
                         &UpdateDownloadService::failed, &window,
                         [&window](const QString&) {
            window.updateInstallationFailed(MainWindow::tr(
                "Não foi possível baixar e verificar a atualização. Tente novamente."));
        });
        QObject::connect(window.m_UpdateDownloadService.get(),
                         &UpdateDownloadService::ready, &window,
                         [&window](const QString& path) {
            window.m_StagedUpdatePath = path;
            window.prepareUpdateInstallation();
        });
    }
    static void installUpdateHelperSeams(
        MainWindow& window,
        std::function<bool(const UpdateHelperInstruction&, QString*)> launcher,
        std::function<void()> exitObserver)
    {
        window.m_UpdateHelperLaunchOverride = std::move(launcher);
        window.m_UpdateExitOverride = std::move(exitObserver);
    }
    static void installUpdateClock(MainWindow& window, const QDateTime& nowUtc)
    {
        window.m_UpdateNowUtcOverride = [nowUtc] { return nowUtc; };
    }
    static bool launchUpdateHelper(MainWindow& window,
                                   const UpdateHelperInstruction& instruction,
                                   QString* error = nullptr)
    {
        return window.launchUpdateHelper(instruction, error);
    }
    static bool updateAwaitingStop(const MainWindow& window)
    {
        return window.m_UpdateInstallAwaitingStop;
    }
    static bool persistPendingUpdateResult(MainWindow& window,
                                           const UpdateHelperInstruction& instruction,
                                           const QString& version,
                                           QString* error = nullptr)
    {
        UpdateHelperInstruction boundInstruction = instruction;
        if (boundInstruction.msiPath.isEmpty()) {
            boundInstruction.msiPath = QDir(window.m_UpdateStagingDirectory)
                .filePath(QStringLiteral("fixture-update.msi"));
        }
        UpdateService::Release release;
        release.version = version;
        release.sha256 = boundInstruction.msiSha256;
        window.m_PendingUpdateRelease = release;
        return window.persistPendingUpdateResult(boundInstruction, error);
    }
    static bool pendingUpdateResultStored(const QSettings& settings)
    {
        return settings.contains(
            QStringLiteral("SecureUpdate/PendingResult/schema"));
    }
    static void installUpdateArtifactRemoveSeam(
        MainWindow& window, std::function<bool(const QString&)> remover)
    {
        window.m_UpdateArtifactRemoveOverride = std::move(remover);
    }
    static void installUpdateProcessIdentitySeam(
        MainWindow& window, std::function<bool(qint64, const QString&)> matcher)
    {
        window.m_UpdateProcessIdentityOverride = std::move(matcher);
    }
    static void consumePendingUpdateResult(MainWindow& window)
    {
        window.consumePendingUpdateResult();
    }
    static void failUpdate(MainWindow& window, const QString& message)
    {
        window.updateInstallationFailed(message);
    }
    static void useUpdateStagingDirectory(MainWindow& window,
                                          const QString& directory)
    {
        window.m_UpdateStagingDirectory = QDir::cleanPath(directory);
        QDir().mkpath(window.m_UpdateStagingDirectory);
    }
    static QString stagedUpdatePath(const MainWindow& window)
    {
        return window.m_StagedUpdatePath;
    }
    static void setStagedUpdatePath(MainWindow& window, const QString& path)
    {
        window.m_StagedUpdatePath = QDir::cleanPath(path);
    }
    static void prepareStagedUpdate(MainWindow& window,
                                    const UpdateService::Release& release,
                                    const QString& path, const QByteArray& envelope,
                                    bool receiveBusy)
    {
        window.m_PendingUpdateRelease = release;
        window.m_StagedUpdatePath = path;
        window.m_PendingUpdateEnvelope = envelope;
        window.m_FileTransferReceiveBusy = receiveBusy;
        window.prepareUpdateInstallation();
    }
    static UpdateReplayStore::Decision primeUpdateReplay(
        MainWindow& window, const UpdateService::Release& release)
    {
        return window.m_UpdateReplayStore->accept(release);
    }
};

TEST(EnvironmentProfileSessionIntegrationTests,
     MainWindowInteractiveControlsHaveAccessibleNames)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("a11y.ini")), QSettings::IniFormat);
    AppConfig config(&settings, SecureCredentialStore());
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));

    const auto buttons = window.findChildren<QPushButton*>();
    ASSERT_FALSE(buttons.isEmpty());
    for (const auto* button : buttons) {
        if (button->isEnabled() && button->focusPolicy() != Qt::NoFocus)
            EXPECT_FALSE(button->accessibleName().trimmed().isEmpty()) << button->objectName().toStdString();
    }
}

TEST(EnvironmentProfileSessionIntegrationTests,
     MainWindowTabNavigationAdvancesAcrossInteractiveControls)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("keyboard.ini")), QSettings::IniFormat);
    AppConfig config(&settings, SecureCredentialStore());
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    window.show();
    QApplication::processEvents();

    QList<QWidget*> focusable;
    for (QWidget* widget : window.findChildren<QWidget*>()) {
        if (widget->isVisible() && widget->isEnabled() &&
            widget->focusPolicy() != Qt::NoFocus)
            focusable.append(widget);
    }
    ASSERT_GE(focusable.size(), 2);
    focusable.first()->setFocus(Qt::OtherFocusReason);
    QWidget* first = QApplication::focusWidget();
    ASSERT_NE(first, nullptr);

    QSet<QWidget*> visited;
    visited.insert(first);
    for (int i = 0; i < qMin(12, focusable.size() + 2); ++i) {
        QTest::keyClick(&window, Qt::Key_Tab);
        if (QWidget* current = QApplication::focusWidget())
            visited.insert(current);
    }
    EXPECT_GE(visited.size(), 2);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     SetupWizardCanBeSkippedWithoutPersistingAComputerRole)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("wizard.ini")), QSettings::IniFormat);
    AppConfig config(&settings, SecureCredentialStore());
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));

    SetupWizard wizard(window, false);
    auto* cancel = wizard.button(QWizard::CancelButton);
    ASSERT_NE(cancel, nullptr);
    auto* next = wizard.button(QWizard::NextButton);
    ASSERT_NE(next, nullptr);
    auto* finish = wizard.button(QWizard::FinishButton);
    ASSERT_NE(finish, nullptr);
    QEvent languageChange(QEvent::LanguageChange);
    QApplication::sendEvent(&wizard, &languageChange);
    EXPECT_EQ(cancel->text(), QObject::tr("Pular por agora"));
    EXPECT_EQ(cancel->accessibleName(), cancel->text());
    EXPECT_FALSE(cancel->toolTip().isEmpty());
    EXPECT_EQ(next->accessibleName(), next->text());
    EXPECT_EQ(finish->accessibleName(), finish->text());
    QTest::mouseClick(cancel, Qt::LeftButton);
    EXPECT_EQ(wizard.result(), QDialog::Rejected);
    EXPECT_FALSE(settings.contains(QStringLiteral("groupServerChecked")));
    EXPECT_FALSE(settings.contains(QStringLiteral("groupClientChecked")));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     SetupWizardCompletionPersistsSelectedServerRole)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("wizard-complete.ini")), QSettings::IniFormat);
    AppConfig config(&settings, SecureCredentialStore());
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));

    SetupWizard wizard(window, false);
    wizard.show();
    QApplication::processEvents();
    auto* next = wizard.button(QWizard::NextButton);
    ASSERT_NE(next, nullptr);
    QTest::mouseClick(next, Qt::LeftButton);
    auto* server = wizard.findChild<QRadioButton*>(QStringLiteral("m_pServerRadioButton"));
    ASSERT_NE(server, nullptr);
    server->setChecked(true);
    auto* finish = wizard.button(QWizard::FinishButton);
    ASSERT_NE(finish, nullptr);
    QTest::mouseClick(finish, Qt::LeftButton);

    EXPECT_EQ(wizard.result(), QDialog::Accepted);
    EXPECT_TRUE(settings.value(QStringLiteral("groupServerChecked")).toBool());
    EXPECT_FALSE(settings.value(QStringLiteral("groupClientChecked")).toBool());
    QSettings reopened(directory.filePath(QStringLiteral("wizard-complete.ini")), QSettings::IniFormat);
    ASSERT_EQ(reopened.status(), QSettings::NoError);
    EXPECT_TRUE(reopened.value(QStringLiteral("groupServerChecked")).toBool());
    EXPECT_FALSE(reopened.value(QStringLiteral("groupClientChecked")).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests,
     SecureUpdateCheckIsExposedAsAnExplicitHelpAction)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("update-action.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    QFile fixture(QStringLiteral(UPDATE_TEST_FIXTURE_DIR "/signed-update-manifest-v2.json"));
    ASSERT_TRUE(fixture.open(QIODevice::ReadOnly));
    SessionUpdateNetwork network;
    network.response = fixture.readAll();
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    const QString replayPath = directory.filePath(QStringLiteral("update-replay.ini"));
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateNetwork(
        window, &network, replayPath, QStringLiteral("3.1.0-modernized"));
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateClock(
        window, QDateTime::fromString(
            QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    const qsizetype credentialCountBeforeUpdate = credentials.size();
    auto* action = window.findChild<QAction*>(
        QStringLiteral("checkForUpdatesAction"));

    ASSERT_NE(action, nullptr);
    EXPECT_TRUE(action->isEnabled());
    EXPECT_EQ(action->text(), MainWindow::tr("Verificar atualizações..."));
    EXPECT_EQ(window.findChildren<QMessageBox*>().size(), 0);
    action->trigger();
    EXPECT_FALSE(action->isEnabled());
    QEventLoop loop;
    QTimer::singleShot(100, &loop, &QEventLoop::quit);
    loop.exec();
    EXPECT_TRUE(action->isEnabled());
    EXPECT_NE(window.findChild<QLabel*>(QStringLiteral("updateVersionLabel")), nullptr);
    EXPECT_EQ(credentials.size(), credentialCountBeforeUpdate + 3);
    EXPECT_TRUE(std::any_of(credentials.keyBegin(), credentials.keyEnd(),
                            [](const QString& account) {
        return account.contains(QStringLiteral("/init/"));
    }));
    QSettings replayMarker(replayPath, QSettings::IniFormat);
    EXPECT_TRUE(replayMarker.value(
        QStringLiteral("SecureUpdateReplay/v2/initialized"), false).toBool());
    for (auto* dialog : window.findChildren<QDialog*>())
        dialog->close();
    QCoreApplication::processEvents();

    UpdateService::Release newer{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(32),
        QStringLiteral("Release posterior"),
        QUrl(QStringLiteral("https://updates.input-leap.example/stable/input-leap-3.3.0.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    ASSERT_EQ(MainWindowEnvironmentProfileSessionTestAccess::primeUpdateReplay(window, newer),
              UpdateReplayStore::Decision::Accepted);
    network.status = 200;
    action->trigger();
    QEventLoop replayLoop;
    QTimer::singleShot(100, &replayLoop, &QEventLoop::quit);
    replayLoop.exec();
    EXPECT_TRUE(action->isEnabled());
    auto replayMessages = window.findChildren<QMessageBox*>();
    ASSERT_EQ(replayMessages.size(), 1);
    EXPECT_EQ(replayMessages.first()->windowTitle(), MainWindow::tr("Não foi possível verificar"));
    replayMessages.first()->close();
    QCoreApplication::processEvents();

    network.status = 404;
    action->trigger();
    EXPECT_FALSE(action->isEnabled());
    QEventLoop errorLoop;
    QTimer::singleShot(100, &errorLoop, &QEventLoop::quit);
    errorLoop.exec();
    EXPECT_TRUE(action->isEnabled());
    const auto messages = window.findChildren<QMessageBox*>();
    ASSERT_EQ(messages.size(), 1);
    EXPECT_EQ(messages.first()->windowTitle(),
              MainWindow::tr("Serviço de atualização indisponível"));
    EXPECT_EQ(messages.first()->text(),
              MainWindow::tr("O serviço de atualizações ainda não está disponível. "
                             "Nenhuma atualização foi baixada ou instalada. "
                             "Tente novamente mais tarde."));
    messages.first()->close();
}

TEST(EnvironmentProfileSessionIntegrationTests,
     VerifiedUpdateResultShowsVersionSizeAndReleaseNotes)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("update-details.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    UpdateService::Result result;
    result.updateAvailable = true;
    QString releaseNotes;
    for (int line = 1; line <= 80; ++line)
        releaseNotes += QStringLiteral("Linha %1: <b>Conexões</b> estáveis e seguras.\n").arg(line);
    result.release = UpdateService::Release{
        QStringLiteral("stable"), QStringLiteral("3.2.0"), quint64(73400320),
        releaseNotes,
        QUrl(QStringLiteral("https://example.invalid/input-leap.exe")), QByteArray(32, '\x01'),
        QDateTime(), QDateTime()};

    MainWindowEnvironmentProfileSessionTestAccess::deliverUpdateResult(window, result);
    QCoreApplication::processEvents();

    const auto* version = window.findChild<QLabel*>(QStringLiteral("updateVersionLabel"));
    const auto* size = window.findChild<QLabel*>(QStringLiteral("updateSizeLabel"));
    const auto* notes = window.findChild<QLabel*>(QStringLiteral("updateNotesLabel"));
    ASSERT_NE(version, nullptr);
    ASSERT_NE(size, nullptr);
    ASSERT_NE(notes, nullptr);
    auto* scrollArea = window.findChild<QScrollArea*>(
        QStringLiteral("updateNotesScrollArea"));
    ASSERT_NE(scrollArea, nullptr);
    EXPECT_EQ(version->text(), MainWindow::tr("Versão 3.2.0"));
    EXPECT_TRUE(size->text().contains(QStringLiteral("70")));
    EXPECT_EQ(notes->text(), releaseNotes);
    EXPECT_EQ(notes->textFormat(), Qt::PlainText);
    EXPECT_EQ(version->accessibleName(), version->text());
    EXPECT_EQ(size->accessibleName(), size->text());
    EXPECT_TRUE(notes->accessibleName().contains(notes->text()));
    EXPECT_TRUE(scrollArea->hasFocus());
    EXPECT_TRUE(scrollArea->isVisible());
    auto* dialog = qobject_cast<QDialog*>(scrollArea->window());
    ASSERT_NE(dialog, nullptr);
    auto* buttons = dialog->findChild<QDialogButtonBox*>(
        QStringLiteral("updateDialogButtons"));
    ASSERT_NE(buttons, nullptr);
    auto* closeButton = buttons->button(QDialogButtonBox::Close);
    ASSERT_NE(closeButton, nullptr);
    EXPECT_EQ(closeButton->text(), MainWindow::tr("Fechar"));
    EXPECT_EQ(dialog->minimumHeight(), 1);
    EXPECT_EQ(dialog->minimumSizeHint().height(), 1);
    EXPECT_EQ(dialog->layout()->sizeConstraint(), QLayout::SetNoConstraint);
    dialog->resize(320, 320);
    QCoreApplication::processEvents();
    EXPECT_LE(dialog->width(), 320);
    EXPECT_LE(dialog->height(), 320);
    const QRect buttonGeometry(buttons->mapTo(dialog, QPoint(0, 0)), buttons->size());
    EXPECT_TRUE(dialog->rect().contains(buttonGeometry));
    ASSERT_GT(scrollArea->verticalScrollBar()->maximum(), 0);
    const int initialScroll = scrollArea->verticalScrollBar()->value();
    QTest::keyClick(scrollArea, Qt::Key_PageDown);
    QCoreApplication::processEvents();
    EXPECT_GT(scrollArea->verticalScrollBar()->value(), initialScroll);
    for (auto* openDialog : window.findChildren<QDialog*>())
        openDialog->close();
}

TEST(EnvironmentProfileSessionIntegrationTests,
     InstallableUpdateDownloadsStopsOnTypedAckAndLaunchesBoundHelper)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("update-install.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    MainWindow window(settings, config, false, [&] { ++stopRequests; },
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_NE(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window), 0);

    const QByteArray package = QByteArrayLiteral("fixture-msi-package");
    SessionUpdateNetwork network;
    network.response = package;
    network.contentType = QStringLiteral("application/x-msi");
    network.etag = QByteArrayLiteral("\"fixture-etag\"");
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateNetwork(
        window, &network, directory.filePath(QStringLiteral("update-replay.ini")));
    bool helperLaunched = false;
    bool exitRequested = false;
    UpdateHelperInstruction captured;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateHelperSeams(
        window,
        [&](const UpdateHelperInstruction& instruction, QString*) {
            EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                            updateTransferBarrierActive(window));
            EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                            transferQueueShuttingDown(window));
            EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::
                          fileTransferPort(window), 0);
            EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                            pendingUpdateResultStored(settings));
            EXPECT_EQ(settings.value(QStringLiteral(
                          "SecureUpdate/PendingResult/resultPath")).toString(),
                      instruction.resultPath);
            EXPECT_EQ(settings.value(QStringLiteral(
                          "SecureUpdate/PendingResult/version")).toString(),
                      QStringLiteral("4.0.0"));
            helperLaunched = true;
            captured = instruction;
            return true;
        },
        [&] { exitRequested = true; });

    UpdateService::Release release;
    release.version = QStringLiteral("4.0.0");
    release.packageUrl = QUrl(QStringLiteral("https://updates.example/inputleap.msi"));
    release.size = package.size();
    release.sha256 = QCryptographicHash::hash(package, QCryptographicHash::Sha256);
    release.packageType = UpdateService::PackageType::WindowsMsi;
    release.installable = true;
    UpdateService::Result result;
    result.release = release;
    result.signedEnvelope = QByteArrayLiteral("signed-envelope-fixture");
    result.updateAvailable = true;
    MainWindowEnvironmentProfileSessionTestAccess::deliverUpdateResult(window, result);

    auto* updateButton = window.findChild<QPushButton*>(QStringLiteral("updateNowButton"));
    ASSERT_NE(updateButton, nullptr);
    EXPECT_EQ(updateButton->text(), MainWindow::tr("Atualizar agora"));
    updateButton->click();

    QTRY_COMPARE_WITH_TIMEOUT(stopRequests, 1, 2000);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::updateAwaitingStop(window));
    EXPECT_FALSE(helperLaunched);
    EXPECT_FALSE(exitRequested);
    ASSERT_EQ(network.requests.size(), 1);
    EXPECT_EQ(network.requests.constFirst().url(), release.packageUrl);
    EXPECT_TRUE(QFileInfo::exists(
        MainWindowEnvironmentProfileSessionTestAccess::stagedUpdatePath(window)));

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);

    QTRY_VERIFY_WITH_TIMEOUT(helperLaunched, 2000);
    EXPECT_TRUE(exitRequested);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::updateAwaitingStop(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "Preparação concluída. O pacote será verificado pelo Windows antes da instalação. "
                  "O InputLeap será fechado agora."));
    EXPECT_EQ(captured.parentPid, quint32(QCoreApplication::applicationPid()));
    EXPECT_EQ(captured.parentPath,
              QFileInfo(QCoreApplication::applicationFilePath()).canonicalFilePath());
    EXPECT_EQ(captured.parentPath, captured.appPath);
    EXPECT_EQ(captured.msiSha256, release.sha256);
    EXPECT_EQ(captured.msiSize, release.size);
    EXPECT_EQ(captured.manifestEnvelope, result.signedEnvelope);
    EXPECT_EQ(QFileInfo(captured.msiPath).absolutePath(),
              QFileInfo(captured.resultPath).absolutePath());
    EXPECT_EQ(settings.status(), QSettings::NoError);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     MatchingUpdateResultIsConsumedOnceAndCannotBeRestoredForReplay)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("update-result.ini"));
    const QString resultPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation))
        .filePath(QStringLiteral("update-staging/install.result.json"));
    QDir().mkpath(QFileInfo(resultPath).absolutePath());
    QFile::remove(resultPath);
    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    QVariantMap capturedPending;
    QByteArray capturedResult;
    QHash<QString, QByteArray> credentials;
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& account) -> std::optional<QByteArray> {
                const auto it = credentials.constFind(account);
                return it == credentials.cend() ? std::nullopt
                                                 : std::optional<QByteArray>(*it);
            },
            [&credentials](const QString& account, const QByteArray& value) {
                credentials.insert(account, value); return true;
            },
            [&credentials](const QString& account) {
                credentials.remove(account); return true;
            });
    };
    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        UpdateHelperInstruction instruction;
        instruction.resultPath = resultPath;
        instruction.readyNonce = nonce;
        instruction.msiSha256 = msiSha256;
        QString error;
        ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                        persistPendingUpdateResult(
                            window, instruction, version, &error))
            << error.toStdString();
        settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
        for (const QString& key : settings.allKeys())
            capturedPending.insert(key, settings.value(key));
        settings.endGroup();
        QFile result(resultPath);
        ASSERT_TRUE(result.open(QIODevice::WriteOnly));
        capturedResult = UpdateHelperProtocol::serializeResult(
            UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired, 3010, false,
            nonce, version, msiSha256,
            credentials.value(UpdateHelperProtocol::resultAuthenticationAccount()),
            QDateTime::currentDateTimeUtc().addSecs(-10));
        ASSERT_EQ(result.write(capturedResult), capturedResult.size());
    }

    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
                  MainWindow::tr(
                      "A atualização para a versão %1 foi instalada. "
                      "Reinicie o Windows para concluir.").arg(version));
        EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::
                         pendingUpdateResultStored(settings));
        EXPECT_FALSE(QFile::exists(resultPath));
    }

    QTest::qWait(1100);
    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
        for (auto it = capturedPending.cbegin(); it != capturedPending.cend(); ++it)
            settings.setValue(it.key(), it.value());
        settings.endGroup();
        settings.sync();
        QFile result(resultPath);
        ASSERT_TRUE(result.open(QIODevice::WriteOnly));
        ASSERT_EQ(result.write(capturedResult), capturedResult.size());
        result.close();
        const QString replayMsiPath = capturedPending.value(
            QStringLiteral("msiPath")).toString();
        const QString replayHelperPath = QFileInfo(resultPath).dir().filePath(
            QStringLiteral("inputleap-update-helper.exe"));
        for (const QString& staged : {replayMsiPath, replayHelperPath}) {
            QFile file(staged);
            ASSERT_TRUE(file.open(QIODevice::WriteOnly));
            ASSERT_EQ(file.write("current-transaction"), 19);
        }

        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
                  MainWindow::tr(
                      "O resultado da atualização não pôde ser confirmado."));
    }
}

TEST(EnvironmentProfileSessionIntegrationTests,
     OldPendingAgeUsesFreshUpdateResultTimestampUntilFailureRelaunchIsConfirmed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("rollback-result.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);
    UpdateHelperInstruction instruction;
    instruction.msiPath = QDir(stagingPath).filePath(QStringLiteral("update-4.0.0.msi"));
    instruction.resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    instruction.readyNonce = QByteArray(16, '\x6b');
    instruction.msiSha256 = QByteArray(32, '\x4d');
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::persistPendingUpdateResult(
        window, instruction, QStringLiteral("4.0.0")));
    settings.setValue(QStringLiteral("SecureUpdate/PendingResult/createdAtUtc"),
                      QDateTime::currentDateTimeUtc().addSecs(-120).toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.sync();
    QFile result(instruction.resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Failed, 1603, false,
        instruction.readyNonce, QStringLiteral("4.0.0"), instruction.msiSha256,
        credentials.value(UpdateHelperProtocol::resultAuthenticationAccount()));
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "A instalação foi processada; o reinício ainda está sendo confirmado."));
    ASSERT_TRUE(result.open(QIODevice::WriteOnly | QIODevice::Truncate));
    encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Failed, 1603, true,
        instruction.readyNonce, QStringLiteral("4.0.0"), instruction.msiSha256,
        credentials.value(UpdateHelperProtocol::resultAuthenticationAccount()));
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    QTRY_COMPARE_WITH_TIMEOUT(
        MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
        MainWindow::tr(
            "A atualização para a versão 4.0.0 falhou. "
            "A aplicação anterior verificada foi reaberta, mas a restauração "
            "completa do sistema não foi confirmada."), 2000);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::
                     pendingUpdateResultStored(settings));
    EXPECT_FALSE(QFile::exists(instruction.resultPath));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     AuthenticatedReplayWithWrongBindingCannotCleanCurrentTransactionArtifacts)
{
    const auto runMismatch = [](int mismatch) {
        QTemporaryDir directory;
        ASSERT_TRUE(directory.isValid());
        const QString settingsPath = directory.filePath(QStringLiteral("mismatch.ini"));
        const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
        const QString resultPath = QDir(stagingPath).filePath(
            QStringLiteral("install.result.json"));
        QDir().mkpath(stagingPath);
        QFile::remove(resultPath);
        const QByteArray expectedNonce(16, '\x6b');
        const QByteArray expectedHash(32, '\x4d');
        const QString expectedVersion = mismatch == 3
            ? QStringLiteral("4.0.0") : QStringLiteral(INPUTLEAP_VERSION);
        QHash<QString, QByteArray> credentials;
        const auto makeStore = [&credentials] {
            return SecureCredentialStore(
                [&credentials](const QString& account) -> std::optional<QByteArray> {
                    const auto it = credentials.constFind(account);
                    return it == credentials.cend() ? std::nullopt
                                                     : std::optional<QByteArray>(*it);
                },
                [&credentials](const QString& account, const QByteArray& value) {
                    credentials.insert(account, value); return true;
                },
                [&credentials](const QString& account) {
                    credentials.remove(account); return true;
                });
        };
        {
            QSettings settings(settingsPath, QSettings::IniFormat);
            settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
            AppConfig config(&settings, makeStore());
            MainWindow window(settings, config, false, {},
                              std::optional<quint16>{0}, std::optional<quint16>{0});
            MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
                window, stagingPath);
            UpdateHelperInstruction instruction;
            instruction.resultPath = resultPath;
            instruction.msiPath = QFileInfo(resultPath).dir().filePath(
                QStringLiteral("fixture-update.msi"));
            instruction.readyNonce = expectedNonce;
            instruction.msiSha256 = expectedHash;
            const QString helperPath = QFileInfo(resultPath).dir().filePath(
                QStringLiteral("inputleap-update-helper.exe"));
            for (const QString& staged : {instruction.msiPath, helperPath}) {
                QFile file(staged);
                ASSERT_TRUE(file.open(QIODevice::WriteOnly));
                ASSERT_EQ(file.write("current-transaction"), 19);
            }
            ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                            persistPendingUpdateResult(
                                window, instruction, expectedVersion));
            const QByteArray actualNonce = mismatch == 0
                ? QByteArray(16, '\x7c') : expectedNonce;
            const QString actualVersion = mismatch == 1
                ? QStringLiteral("4.0.1") : expectedVersion;
            const QByteArray actualHash = mismatch == 2
                ? QByteArray(32, '\x5e') : expectedHash;
            QFile result(resultPath);
            ASSERT_TRUE(result.open(QIODevice::WriteOnly));
            const QByteArray encoded = UpdateHelperProtocol::serializeResult(
                UpdateInstallPolicy::MsiOutcome::Success, 0, true,
                actualNonce, actualVersion, actualHash,
                credentials.value(
                    UpdateHelperProtocol::resultAuthenticationAccount()),
                QDateTime::currentDateTimeUtc().addSecs(-7200));
            ASSERT_EQ(result.write(encoded), encoded.size());
        }
        {
            QSettings settings(settingsPath, QSettings::IniFormat);
            AppConfig config(&settings, makeStore());
            MainWindow window(settings, config, false, {},
                              std::optional<quint16>{0}, std::optional<quint16>{0});
            MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
                window, stagingPath);
            settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
            settings.setValue(QStringLiteral("schema"), 2);
            settings.setValue(QStringLiteral("createdAtUtc"),
                              QDateTime::currentDateTimeUtc().toString(
                                  QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
            settings.setValue(QStringLiteral("resultPath"), resultPath);
            settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
                expectedNonce.toBase64(QByteArray::Base64UrlEncoding |
                                       QByteArray::OmitTrailingEquals)));
            settings.setValue(QStringLiteral("version"), expectedVersion);
            settings.setValue(QStringLiteral("originVersion"),
                              QStringLiteral(INPUTLEAP_VERSION));
            settings.setValue(QStringLiteral("msiPath"),
                              QFileInfo(resultPath).dir().filePath(
                                  QStringLiteral("fixture-update.msi")));
            settings.setValue(QStringLiteral("msiSha256"),
                              QString::fromLatin1(expectedHash.toHex()));
            settings.setValue(QStringLiteral("appSha256"),
                              QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
            settings.endGroup();
            settings.sync();
            MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(
                window);
            EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
                      MainWindow::tr(
                          "O resultado da atualização não pôde ser confirmado."));
            EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                            pendingUpdateResultStored(settings));
            EXPECT_FALSE(QFile::exists(resultPath));
            EXPECT_TRUE(QFile::exists(QFileInfo(resultPath).dir().filePath(
                QStringLiteral("fixture-update.msi"))));
            EXPECT_TRUE(QFile::exists(QFileInfo(resultPath).dir().filePath(
                QStringLiteral("inputleap-update-helper.exe"))));
            QFile::remove(resultPath);
            QFile::remove(QFileInfo(resultPath).dir().filePath(
                QStringLiteral("fixture-update.msi")));
            QFile::remove(QFileInfo(resultPath).dir().filePath(
                QStringLiteral("inputleap-update-helper.exe")));
        }
    };

    for (int mismatch = 0; mismatch < 3; ++mismatch)
        runMismatch(mismatch);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     TamperedPendingResultPathCannotReadOrDeleteFileOutsideUpdateStaging)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("path-tamper.ini"));
    const QString expectedResultPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation))
        .filePath(QStringLiteral("update-staging/install.result.json"));
    QDir().mkpath(QFileInfo(expectedResultPath).absolutePath());
    QFile::remove(expectedResultPath);
    const QString outsidePath = directory.filePath(QStringLiteral("outside.result.json"));
    const QByteArray sentinel = QByteArrayLiteral("must-not-be-read-or-deleted");
    QHash<QString, QByteArray> credentials;
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& account) -> std::optional<QByteArray> {
                const auto it = credentials.constFind(account);
                return it == credentials.cend() ? std::nullopt
                                                 : std::optional<QByteArray>(*it);
            },
            [&credentials](const QString& account, const QByteArray& value) {
                credentials.insert(account, value); return true;
            },
            [&credentials](const QString& account) {
                credentials.remove(account); return true;
            });
    };
    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        UpdateHelperInstruction instruction;
        instruction.resultPath = expectedResultPath;
        instruction.readyNonce = QByteArray(16, '\x6b');
        instruction.msiSha256 = QByteArray(32, '\x4d');
        ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                        persistPendingUpdateResult(
                            window, instruction, QStringLiteral("4.0.0")));
        settings.setValue(QStringLiteral("SecureUpdate/PendingResult/resultPath"),
                          outsidePath);
        settings.sync();
        QFile outside(outsidePath);
        ASSERT_TRUE(outside.open(QIODevice::WriteOnly));
        ASSERT_EQ(outside.write(sentinel), sentinel.size());
    }
    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        QFile outside(outsidePath);
        ASSERT_TRUE(outside.open(QIODevice::ReadOnly));
        EXPECT_EQ(outside.readAll(), sentinel);
        EXPECT_TRUE(QFile::exists(outsidePath));
        EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::
                         pendingUpdateResultStored(settings));
        EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
                  MainWindow::tr(
                      "O resultado da atualização não pôde ser confirmado."));
    }
}

TEST(EnvironmentProfileSessionIntegrationTests,
     FreshPendingUpdateWithoutResultRemainsPending)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("still-running.ini"));
    const QString resultPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation))
        .filePath(QStringLiteral("update-staging/install.result.json"));
    QString msiPath;
    const QString helperPath = QFileInfo(resultPath).dir().filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(QFileInfo(resultPath).absolutePath());
    QFile::remove(resultPath);
    QHash<QString, QByteArray> credentials;
    const auto makeStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& account) -> std::optional<QByteArray> {
                const auto it = credentials.constFind(account);
                return it == credentials.cend() ? std::nullopt
                                                 : std::optional<QByteArray>(*it);
            },
            [&credentials](const QString& account, const QByteArray& value) {
                credentials.insert(account, value); return true;
            },
            [&credentials](const QString& account) {
                credentials.remove(account); return true;
            });
    };
    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        UpdateHelperInstruction instruction;
        instruction.resultPath = resultPath;
        instruction.readyNonce = QByteArray(16, '\x6b');
        instruction.msiSha256 = QByteArray(32, '\x4d');
        ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                        persistPendingUpdateResult(
                            window, instruction,
                            QStringLiteral(INPUTLEAP_VERSION)));
        msiPath = settings.value(QStringLiteral(
            "SecureUpdate/PendingResult/msiPath")).toString();
        for (const QString& stagedPath : {msiPath, helperPath}) {
            QFile staged(stagedPath);
            ASSERT_TRUE(staged.open(QIODevice::WriteOnly));
            ASSERT_EQ(staged.write("staged"), 6);
        }
    }
    {
        QSettings settings(settingsPath, QSettings::IniFormat);
        AppConfig config(&settings, makeStore());
        MainWindow window(settings, config, false, {},
                          std::optional<quint16>{0}, std::optional<quint16>{0});
        EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                        pendingUpdateResultStored(settings));
        EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
                  MainWindow::tr(
                      "A atualização ainda não publicou um resultado verificável."));
        auto* retryTimer = window.findChild<QTimer*>(
            QStringLiteral("pendingUpdateResultRetryTimer"));
        ASSERT_NE(retryTimer, nullptr);
        EXPECT_TRUE(retryTimer->isActive());
        bool helperActive = true;
        MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
            window, [](const QString& path) {
                return QFile::remove(path);
            });
        MainWindowEnvironmentProfileSessionTestAccess::installUpdateProcessIdentitySeam(
            window, [&helperActive, &helperPath](qint64 pid, const QString& path) {
                return helperActive && pid == 123 && path == helperPath;
            });
        settings.setValue(QStringLiteral("SecureUpdate/PendingResult/helperPid"),
                          qlonglong(123));
        settings.setValue(QStringLiteral("SecureUpdate/PendingResult/helperPath"),
                          helperPath);
        settings.setValue(QStringLiteral("SecureUpdate/PendingResult/helperSha256"),
                          QString::fromLatin1(QCryptographicHash::hash(
                              QByteArrayLiteral("staged"),
                              QCryptographicHash::Sha256).toHex()));
        settings.setValue(QStringLiteral("SecureUpdate/PendingResult/createdAtUtc"),
                          QDateTime::currentDateTimeUtc().addSecs(-3601).toString(
                              QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
        settings.sync();
        ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                        pendingUpdateResultStored(settings));
        ASSERT_TRUE(QFile::exists(msiPath));
        ASSERT_TRUE(QFile::exists(helperPath));
        MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);
        EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                        pendingUpdateResultStored(settings));
        EXPECT_TRUE(QFile::exists(msiPath));
        EXPECT_TRUE(QFile::exists(helperPath));
        EXPECT_TRUE(retryTimer->isActive());
        helperActive = false;
        MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);
        QTRY_VERIFY_WITH_TIMEOUT(
            !MainWindowEnvironmentProfileSessionTestAccess::
                 pendingUpdateResultStored(settings),
            2500);
        EXPECT_FALSE(QFile::exists(msiPath));
        EXPECT_FALSE(QFile::exists(helperPath));
        EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
                  MainWindow::tr(
                      "O resultado da atualização não pôde ser confirmado."));
    }
}

TEST(EnvironmentProfileSessionIntegrationTests,
     NewGuiPromotesSuccessfulPreliminaryUpdateAfterCompiledVersionConfirmation)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("result-race.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("fixture-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    const QByteArray resultAuthenticationKey(32, '\x7a');
    QHash<QString, QByteArray> credentials;
    credentials.insert(UpdateHelperProtocol::resultAuthenticationAccount(),
                       resultAuthenticationKey);
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"), version);
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    // A successful MSI replaces the previous executable.  The pending record
    // therefore binds the pre-install binary, which must differ from this new
    // GUI while it confirms the compiled target version.
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();
    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Success, 0, false,
        nonce, version, msiSha256, resultAuthenticationKey);
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::
                     pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "A atualização para a versão %1 foi concluída com sucesso.")
                  .arg(version));
    EXPECT_FALSE(QFile::exists(resultPath));
    EXPECT_FALSE(QFile::exists(msiPath));
    EXPECT_FALSE(QFile::exists(helperPath));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     UnsignedPreliminaryUpdateResultCannotBePromoted)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("unsigned-result.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("unsigned-fixture-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"), version);
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();
    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Success, 0, false,
        nonce, version, msiSha256);
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "O resultado da atualização não pôde ser confirmado."));
    EXPECT_TRUE(QFile::exists(resultPath));
    EXPECT_TRUE(QFile::exists(msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));

    QFile::remove(resultPath);
    QFile::remove(msiPath);
    QFile::remove(helperPath);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     UnsignedFailureResultCannotClaimVerifiedRollbackOrCleanArtifacts)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("unsigned-failure.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("unsigned-failure-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QString version = QStringLiteral("4.0.0");
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"),
                      QStringLiteral(INPUTLEAP_VERSION));
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();
    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Failed, 1603, true,
        nonce, version, msiSha256);
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "O resultado da atualização não pôde ser confirmado."));
    EXPECT_TRUE(QFile::exists(resultPath));
    EXPECT_TRUE(QFile::exists(msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));

    QFile::remove(resultPath);
    QFile::remove(msiPath);
    QFile::remove(helperPath);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     AuthenticatedResultTamperedAfterSigningCannotCleanPendingArtifacts)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("tampered-binding.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("tampered-binding-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }

    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QByteArray authenticationKey(32, '\x7a');
    const QString version = QStringLiteral("4.0.0");
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"),
                      QStringLiteral(INPUTLEAP_VERSION));
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();

    const QByteArray signedResult = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Failed, 1603, true,
        nonce, version, msiSha256, authenticationKey);
    QJsonObject tampered = QJsonDocument::fromJson(signedResult).object();
    tampered.insert(QStringLiteral("version"), QStringLiteral("4.0.1"));
    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = QJsonDocument(tampered).toJson(QJsonDocument::Compact);
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    QHash<QString, QByteArray> credentials;
    credentials.insert(UpdateHelperProtocol::resultAuthenticationAccount(),
                       authenticationKey);
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "O resultado da atualização não pôde ser confirmado."));
    EXPECT_TRUE(QFile::exists(resultPath));
    EXPECT_TRUE(QFile::exists(msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));

    QFile::remove(resultPath);
    QFile::remove(msiPath);
    QFile::remove(helperPath);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     AuthenticatedTerminalResultDuringCleanupRetryIsRevalidatedAndConsumed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("cleanup-retry-result.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(QStringLiteral("cleanup-retry-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }

    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QByteArray authenticationKey(32, '\x7a');
    const QString version = QStringLiteral("4.0.0");
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("cleanupOnly"), true);
    settings.setValue(QStringLiteral("createdAtUtc"), QDateTime::currentDateTimeUtc().toString(
        QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(nonce.toBase64(
        QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"), QStringLiteral(INPUTLEAP_VERSION));
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"), QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();

    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Failed, 1603, true,
        nonce, version, msiSha256, authenticationKey);
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    QHash<QString, QByteArray> credentials;
    credentials.insert(UpdateHelperProtocol::resultAuthenticationAccount(), authenticationKey);
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "A atualização para a versão 4.0.0 falhou. "
                  "A aplicação anterior verificada foi reaberta, mas a restauração "
                  "completa do sistema não foi confirmada."));
    EXPECT_FALSE(QFile::exists(resultPath));
    EXPECT_FALSE(QFile::exists(msiPath));
    EXPECT_FALSE(QFile::exists(helperPath));

    QFile::remove(resultPath);
    QFile::remove(msiPath);
    QFile::remove(helperPath);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     CanonicalAuthenticatedResultSurvivesInvalidPendingResultPath)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(
        QStringLiteral("invalid-pending-result-path.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("invalid-result-path-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }

    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QByteArray authenticationKey(32, '\x7a');
    const QString version = QStringLiteral("4.0.0");
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"),
                      directory.filePath(QStringLiteral("outside-result.json")));
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"),
                      QStringLiteral(INPUTLEAP_VERSION));
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();

    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Failed, 1603, true,
        nonce, version, msiSha256, authenticationKey);
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    QHash<QString, QByteArray> credentials;
    credentials.insert(UpdateHelperProtocol::resultAuthenticationAccount(),
                       authenticationKey);
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "O resultado da atualização não pôde ser confirmado."));
    EXPECT_TRUE(QFile::exists(resultPath));
    EXPECT_TRUE(QFile::exists(msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));

    QFile::remove(resultPath);
    QFile::remove(msiPath);
    QFile::remove(helperPath);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     UnauthenticatedCleanupNeverRemovesProtectedArtifacts)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("late-result.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));

    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QByteArray authenticationKey(32, '\x7a');
    const QString version = QStringLiteral("4.0.0");
    QHash<QString, QByteArray> credentials;
    credentials.insert(UpdateHelperProtocol::resultAuthenticationAccount(),
                       authenticationKey);
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});

    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);
    const QString instructionPath = QDir(stagingPath).filePath(
        QStringLiteral("install.instruction.json"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("late-result-update.msi"));
    for (const QString& staged : {instructionPath, helperPath, msiPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }

    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("cleanupOnly"), true);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"),
                      QStringLiteral(INPUTLEAP_VERSION));
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();

    bool published = false;
    QStringList removalAttempts;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
        window, [&](const QString& path) {
            removalAttempts.append(path);
            return QFile::remove(path);
        });

    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);

    EXPECT_FALSE(published);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "A limpeza dos arquivos temporários da atualização será repetida."));
    EXPECT_FALSE(QFile::exists(resultPath));
    EXPECT_TRUE(QFile::exists(helperPath));
    EXPECT_TRUE(QFile::exists(msiPath));
    EXPECT_TRUE(removalAttempts.contains(instructionPath));
    EXPECT_FALSE(removalAttempts.contains(resultPath));
    EXPECT_FALSE(removalAttempts.contains(helperPath));
    EXPECT_FALSE(removalAttempts.contains(msiPath));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     AuthenticatedTerminalCleanupRetriesWithoutBecomingPermanentlyPending)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("terminal-cleanup-retry.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});

    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);
    UpdateHelperInstruction instruction;
    instruction.msiPath = QDir(stagingPath).filePath(QStringLiteral("update.msi"));
    instruction.resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    instruction.readyNonce = QByteArray(16, '\x6b');
    instruction.msiSha256 = QByteArray(32, '\x4d');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::persistPendingUpdateResult(
        window, instruction, version));

    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    for (const QString& path : {instruction.msiPath, helperPath}) {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    QFile result(instruction.resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired, 3010, true,
        instruction.readyNonce, version, instruction.msiSha256,
        credentials.value(UpdateHelperProtocol::resultAuthenticationAccount()));
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    bool failCleanup = true;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
        window, [&failCleanup](const QString& path) {
            return !failCleanup && QFile::remove(path);
        });
    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_TRUE(settings.value(QStringLiteral(
        "SecureUpdate/PendingResult/cleanupOnly")).toBool());

    failCleanup = false;
    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::
                     pendingUpdateResultStored(settings));
    EXPECT_FALSE(QFile::exists(instruction.resultPath));
    EXPECT_FALSE(QFile::exists(instruction.msiPath));
    EXPECT_FALSE(QFile::exists(helperPath));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     StaleInstallingResultNeverAuthorizesDestructiveCleanup)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("stale-installing.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});

    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);
    UpdateHelperInstruction instruction;
    instruction.msiPath = QDir(stagingPath).filePath(QStringLiteral("stale.msi"));
    instruction.resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    instruction.readyNonce = QByteArray(16, '\x6b');
    instruction.msiSha256 = QByteArray(32, '\x4d');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::persistPendingUpdateResult(
        window, instruction, version));
    settings.setValue(QStringLiteral(
        "SecureUpdate/PendingResult/helperLaunchInFlight"), true);
    settings.sync();

    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    const QString instructionPath = QDir(stagingPath).filePath(
        QStringLiteral("install.instruction.json"));
    for (const QString& path : {instruction.msiPath, helperPath, instructionPath}) {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    QFile result(instruction.resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Installing,
        std::numeric_limits<quint32>::max(), false,
        instruction.readyNonce, version, instruction.msiSha256,
        credentials.value(UpdateHelperProtocol::resultAuthenticationAccount()),
        QDateTime::currentDateTimeUtc().addSecs(-7200));
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();

    QStringList removalAttempts;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
        window, [&removalAttempts](const QString& path) {
            removalAttempts.append(path);
            return QFile::remove(path);
        });

    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_NE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window)
                  .indexOf(QStringLiteral("identidade do instalador")), -1);
    EXPECT_TRUE(QFile::exists(instruction.resultPath));
    EXPECT_TRUE(QFile::exists(instruction.msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));
    EXPECT_TRUE(QFile::exists(instructionPath));
    EXPECT_TRUE(removalAttempts.isEmpty());
}

TEST(EnvironmentProfileSessionIntegrationTests,
     FutureInstallingTimestampNeverAuthorizesDestructiveCleanup)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("future-installing.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);
    UpdateHelperInstruction instruction;
    instruction.msiPath = QDir(stagingPath).filePath(QStringLiteral("future.msi"));
    instruction.resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    instruction.readyNonce = QByteArray(16, '\x6b');
    instruction.msiSha256 = QByteArray(32, '\x4d');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::persistPendingUpdateResult(
        window, instruction, version));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    for (const QString& path : {instruction.msiPath, helperPath}) {
        QFile file(path);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    QFile result(instruction.resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Installing,
        std::numeric_limits<quint32>::max(), false,
        instruction.readyNonce, version, instruction.msiSha256,
        credentials.value(UpdateHelperProtocol::resultAuthenticationAccount()),
        QDateTime::currentDateTimeUtc().addSecs(301));
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();
    QStringList removalAttempts;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
        window, [&removalAttempts](const QString& path) {
            removalAttempts.append(path);
            return QFile::remove(path);
        });

    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_TRUE(QFile::exists(instruction.resultPath));
    EXPECT_TRUE(QFile::exists(instruction.msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));
    EXPECT_TRUE(removalAttempts.isEmpty());
}

TEST(EnvironmentProfileSessionIntegrationTests,
     ExpiredConfirmedUpdateResultCannotBeReplayed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString settingsPath = directory.filePath(QStringLiteral("expired-result.ini"));
    const QString stagingPath = QDir(QStandardPaths::writableLocation(
        QStandardPaths::AppLocalDataLocation)).filePath(QStringLiteral("update-staging"));
    const QString resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    const QString msiPath = QDir(stagingPath).filePath(
        QStringLiteral("expired-fixture-update.msi"));
    const QString helperPath = QDir(stagingPath).filePath(
        QStringLiteral("inputleap-update-helper.exe"));
    QDir().mkpath(stagingPath);
    QFile::remove(resultPath);
    for (const QString& staged : {msiPath, helperPath}) {
        QFile file(staged);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QByteArray resultAuthenticationKey(32, '\x7a');
    const QString version = QStringLiteral(INPUTLEAP_VERSION);
    QHash<QString, QByteArray> credentials;
    credentials.insert(UpdateHelperProtocol::resultAuthenticationAccount(),
                       resultAuthenticationKey);
    QSettings settings(settingsPath, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.beginGroup(QStringLiteral("SecureUpdate/PendingResult"));
    settings.setValue(QStringLiteral("schema"), 2);
    settings.setValue(QStringLiteral("createdAtUtc"),
                      QDateTime::currentDateTimeUtc().toString(
                          QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    settings.setValue(QStringLiteral("resultPath"), resultPath);
    settings.setValue(QStringLiteral("nonce"), QString::fromLatin1(
        nonce.toBase64(QByteArray::Base64UrlEncoding |
                       QByteArray::OmitTrailingEquals)));
    settings.setValue(QStringLiteral("version"), version);
    settings.setValue(QStringLiteral("originVersion"), version);
    settings.setValue(QStringLiteral("msiPath"), msiPath);
    settings.setValue(QStringLiteral("msiSha256"),
                      QString::fromLatin1(msiSha256.toHex()));
    settings.setValue(QStringLiteral("appSha256"),
                      QString::fromLatin1(QByteArray(32, '\x2a').toHex()));
    settings.endGroup();
    settings.sync();
    QFile result(resultPath);
    ASSERT_TRUE(result.open(QIODevice::WriteOnly));
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Success, 0, true,
        nonce, version, msiSha256, resultAuthenticationKey,
        QDateTime::currentDateTimeUtc().addSecs(-7200));
    ASSERT_EQ(result.write(encoded), encoded.size());
    result.close();
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr(
                  "O resultado da atualização não pôde ser confirmado."));
    EXPECT_TRUE(QFile::exists(resultPath));
    EXPECT_TRUE(QFile::exists(msiPath));
    EXPECT_TRUE(QFile::exists(helperPath));

    QFile::remove(resultPath);
    QFile::remove(msiPath);
    QFile::remove(helperPath);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     UpdateInstallationFailureWithoutAuthenticatedResultRetainsProtectedArtifacts)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("helper-failure.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);
    const QString msiPath = QDir(stagingPath).filePath(QStringLiteral("update.msi"));
    MainWindowEnvironmentProfileSessionTestAccess::setStagedUpdatePath(window, msiPath);
    const QStringList artifacts{
        msiPath,
        QDir(stagingPath).filePath(QStringLiteral("install.instruction.json")),
        QDir(stagingPath).filePath(QStringLiteral("install.ready.json")),
        QDir(stagingPath).filePath(QStringLiteral("install.result.json")),
        QDir(stagingPath).filePath(QStringLiteral("inputleap-update-helper.exe")),
    };
    for (const QString& artifact : artifacts) {
        QFile file(artifact);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        ASSERT_EQ(file.write("staged"), 6);
    }
    settings.setValue(QStringLiteral("SecureUpdate/PendingResult/schema"), 2);
    const QString helperPath = artifacts.at(4);
    const QStringList protectedArtifacts{msiPath, artifacts.at(3), helperPath};
    settings.setValue(QStringLiteral("SecureUpdate/PendingResult/helperPid"),
                      qlonglong(123));
    settings.setValue(QStringLiteral("SecureUpdate/PendingResult/helperPath"),
                      helperPath);
    settings.setValue(QStringLiteral("SecureUpdate/PendingResult/helperSha256"),
                      QString::fromLatin1(QCryptographicHash::hash(
                          QByteArrayLiteral("staged"),
                          QCryptographicHash::Sha256).toHex()));
    settings.sync();
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));

    bool helperActive = true;
    int cleanupMode = 0;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateProcessIdentitySeam(
        window, [&helperActive, &helperPath](qint64 pid, const QString& path) {
            return helperActive && pid == 123 && path == helperPath;
        });
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
        window, [&cleanupMode](const QString& path) {
            return cleanupMode == 1 && QFile::remove(path);
        });

    MainWindowEnvironmentProfileSessionTestAccess::failUpdate(
        window, MainWindow::tr("Não foi possível iniciar a atualização."));

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    EXPECT_TRUE(settings.value(QStringLiteral(
        "SecureUpdate/PendingResult/cleanupOnly")).toBool());
    auto* retryTimer = window.findChild<QTimer*>(
        QStringLiteral("pendingUpdateResultRetryTimer"));
    ASSERT_NE(retryTimer, nullptr);
    EXPECT_TRUE(retryTimer->isActive());
    for (const QString& artifact : artifacts)
        EXPECT_TRUE(QFile::exists(artifact));

    cleanupMode = 1;
    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    for (const QString& artifact : protectedArtifacts)
        EXPECT_TRUE(QFile::exists(artifact));

    helperActive = false;
    MainWindowEnvironmentProfileSessionTestAccess::consumePendingUpdateResult(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
                    pendingUpdateResultStored(settings));
    for (const QString& artifact : protectedArtifacts)
        EXPECT_TRUE(QFile::exists(artifact));
    EXPECT_FALSE(QFile::exists(artifacts.at(1)));
    EXPECT_FALSE(QFile::exists(artifacts.at(2)));

}

TEST(EnvironmentProfileSessionIntegrationTests,
     LockedStaleResultBlocksHelperBeforeInstallationCanStart)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("locked-stale-result.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    const QString stagingPath = directory.filePath(QStringLiteral("update-staging"));
    MainWindowEnvironmentProfileSessionTestAccess::useUpdateStagingDirectory(
        window, stagingPath);

    UpdateHelperInstruction instruction;
    instruction.parentPid = 1;
    instruction.parentPath = directory.filePath(QStringLiteral("parent.exe"));
    instruction.parentSha256 = QByteArray(32, '\x31');
    instruction.msiPath = QDir(stagingPath).filePath(QStringLiteral("update.msi"));
    instruction.msiSize = 1;
    instruction.msiSha256 = QByteArray(32, '\x32');
    instruction.appPath = directory.filePath(QStringLiteral("input-leap.exe"));
    instruction.appSha256 = QByteArray(32, '\x33');
    instruction.resultPath = QDir(stagingPath).filePath(
        QStringLiteral("install.result.json"));
    instruction.readyPath = QDir(stagingPath).filePath(
        QStringLiteral("install.ready.json"));
    instruction.readyNonce = QByteArray(16, '\x34');
    instruction.manifestEnvelope = QByteArrayLiteral("signed-envelope");

    // Bind the release metadata used by launchUpdateHelper without leaving a
    // pre-existing pending result that could mask whether launch created one.
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::
        persistPendingUpdateResult(window, instruction, QStringLiteral("4.0.0")));
    settings.remove(QStringLiteral("SecureUpdate/PendingResult"));
    settings.sync();

    QFile staleResult(instruction.resultPath);
    ASSERT_TRUE(staleResult.open(QIODevice::WriteOnly));
    ASSERT_EQ(staleResult.write("stale"), 5);
    staleResult.close();
    bool helperLaunched = false;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateHelperSeams(
        window,
        [&helperLaunched](const UpdateHelperInstruction&, QString*) {
            helperLaunched = true;
            return true;
        }, {});
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateArtifactRemoveSeam(
        window, [&instruction](const QString& path) {
            if (path == instruction.resultPath)
                return false;
            return QFile::remove(path);
        });

    QString error;
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::launchUpdateHelper(
        window, instruction, &error));
    EXPECT_FALSE(helperLaunched);
    EXPECT_TRUE(error.contains(QStringLiteral("stale")));
    EXPECT_TRUE(QFile::exists(instruction.resultPath));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::
                     pendingUpdateResultStored(settings));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     ActiveReceiveTransferBlocksUpdateBeforeStopAndHelper)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("update-transfer-block.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    MainWindow window(settings, config, false, [&] { ++stopRequests; },
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    bool helperLaunched = false;
    MainWindowEnvironmentProfileSessionTestAccess::installUpdateHelperSeams(
        window,
        [&](const UpdateHelperInstruction&, QString*) {
            helperLaunched = true;
            return true;
        }, {});

    const QByteArray package = QByteArrayLiteral("blocked-msi");
    const QString staged = directory.filePath(QStringLiteral("blocked.msi"));
    QFile stagedFile(staged);
    ASSERT_TRUE(stagedFile.open(QIODevice::WriteOnly));
    ASSERT_EQ(stagedFile.write(package), package.size());
    stagedFile.close();
    UpdateService::Release release;
    release.version = QStringLiteral("4.0.0");
    release.packageUrl = QUrl(QStringLiteral("https://updates.example/blocked.msi"));
    release.size = package.size();
    release.sha256 = QCryptographicHash::hash(package, QCryptographicHash::Sha256);
    release.packageType = UpdateService::PackageType::WindowsMsi;
    release.installable = true;

    MainWindowEnvironmentProfileSessionTestAccess::prepareStagedUpdate(
        window, release, staged, QByteArrayLiteral("signed-envelope"), true);

    EXPECT_EQ(stopRequests, 0);
    EXPECT_FALSE(helperLaunched);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::updateAwaitingStop(window));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     ContradictoryUpdateResultFailsClosedInsteadOfClaimingCurrent)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("update-invalid-result.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    UpdateService::Result contradictory;
    contradictory.updateAvailable = true;

    MainWindowEnvironmentProfileSessionTestAccess::deliverUpdateResult(window, contradictory);
    QCoreApplication::processEvents();

    const auto messages = window.findChildren<QMessageBox*>();
    ASSERT_EQ(messages.size(), 1);
    EXPECT_EQ(messages.first()->windowTitle(), MainWindow::tr("Não foi possível verificar"));
    EXPECT_NE(messages.first()->windowTitle(), MainWindow::tr("InputLeap está atualizado"));
    messages.first()->close();
}

TEST(EnvironmentProfileSessionIntegrationTests,
     OneShotAutomaticStartSuppressionLeavesPersistedAutoStartUntouched)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("suppress-autostart.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::markStartedBefore(config);
    config.setAutoStart(true);
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);
    MainWindowEnvironmentProfileSessionTestAccess::markAutoConfigPrompted(config);

    ASSERT_TRUE(config.saveSettings());
    settings.sync();
    QSettings persistedBefore(directory.filePath(QStringLiteral("suppress-autostart.ini")),
                              QSettings::IniFormat);
    ASSERT_TRUE(persistedBefore.value(QStringLiteral("startedBefore"), false).toBool());
    ASSERT_TRUE(persistedBefore.value(QStringLiteral("autoStart"), false).toBool());

    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutableWithArguments(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH),
        {QStringLiteral("--wait")});

    window.suppressAutomaticStartOnce();
    window.open();

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_TRUE(config.startedBefore());
    EXPECT_TRUE(config.getAutoStart());
    settings.sync();
    QSettings persistedAfter(directory.filePath(QStringLiteral("suppress-autostart.ini")),
                             QSettings::IniFormat);
    EXPECT_TRUE(persistedAfter.value(QStringLiteral("startedBefore"), false).toBool());
    EXPECT_TRUE(persistedAfter.value(QStringLiteral("autoStart"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, ConnectedDashboardDoesNotClaimSecurityWithoutPairedTlsSession)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("unpaired-dashboard.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    config.setCryptoEnabled(true);
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));

    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectedDashboardDetail(window),
              MainWindow::tr("Conectado sem proteção confirmada"));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::padlockExplicitlyHidden(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::protectionBadge(window),
              ProtectionPanel::badgeLabel({}));
}

TEST(EnvironmentProfileSessionIntegrationTests, DaemonTransportLossClearsConnectedDashboardState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("daemon-transport-loss.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);
    ASSERT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceTransportUnavailable(window);

    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     CriticalDeviceRegistryStartupFailureIsTranslatedInBrazilianPortuguese)
{
    auto* application = QInputLeapApplication::getInstance();
    ASSERT_NE(application, nullptr);
    application->switchTranslator(QStringLiteral("pt-BR"));

    EXPECT_EQ(MainWindow::tr(
                  "The device registry could not be promoted to writable storage. "
                  "InputLeap was not started."),
              QStringLiteral(
                  "O registro de dispositivos não pôde ser promovido para o armazenamento "
                  "gravável. O InputLeap não foi iniciado."));

    application->switchTranslator(QStringLiteral("en"));
}

TEST(EnvironmentProfileSessionIntegrationTests, RecoveryRequiredIsActionableInMainWindow)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("recovery-window.ini")),QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"),QStringLiteral("local"));
    QHash<QString,QByteArray> credentials;
    AppConfig config(&settings,SecureCredentialStore(
        [&credentials](const QString& account)->std::optional<QByteArray>{
            const auto it=credentials.constFind(account);
            return it==credentials.cend()?std::nullopt:std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account,const QByteArray& value){credentials.insert(account,value);return true;},
        [&credentials](const QString& account){credentials.remove(account);return true;}));
    MainWindow window(settings,config,false,{},std::optional<quint16>{0},std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_NE(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window),0);
    const QString recovery=directory.filePath(QStringLiteral("InputLeap original recovery - important.bin"));
    MainWindowEnvironmentProfileSessionTestAccess::emitRecoveryRequired(window,recovery);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window).contains(recovery));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window).contains(recovery));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window),QFileInfo(recovery).absolutePath());
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPeer(window),
              QStringLiteral("11111111-1111-1111-1111-111111111111"));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window));
    const QString reviewDestination=directory.filePath(QStringLiteral("indeterminate.bin"));
    MainWindowEnvironmentProfileSessionTestAccess::emitReviewRequired(window,reviewDestination);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window).contains(reviewDestination));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window).contains(reviewDestination));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window)
                    .contains(QStringLiteral("indeterminada")));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window),
              QFileInfo(reviewDestination).absolutePath());
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPeer(window),
              QStringLiteral("66666666-6666-6666-6666-666666666666"));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window));
    const QString reviewStatus=MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window).toLower();
    EXPECT_FALSE(reviewStatus.contains(QStringLiteral("original")));
    EXPECT_FALSE(reviewStatus.contains(QStringLiteral("preserv")));
    EXPECT_FALSE(reviewStatus.contains(QStringLiteral("recuper")));
    const QString unchangedDestination=directory.filePath(QStringLiteral("not-created.bin"));
    MainWindowEnvironmentProfileSessionTestAccess::emitUnchanged(window,unchangedDestination);
    const QString unchangedStatus=MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window).toLower();
    EXPECT_FALSE(unchangedStatus.contains(QStringLiteral("preserv")));
    EXPECT_TRUE(unchangedStatus.contains(QStringLiteral("não foi concluída")));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window),
              QFileInfo(unchangedDestination).absolutePath());
    MainWindowEnvironmentProfileSessionTestAccess::emitFailedVerification(window,unchangedDestination);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window)
                    .contains(QStringLiteral("nenhum arquivo foi publicado")));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window).isEmpty());
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window));
    const QString committedRecovery=directory.filePath(QStringLiteral("InputLeap original recovery - committed.bin"));
    const QString destination=directory.filePath(QStringLiteral("committed.bin"));
    MainWindowEnvironmentProfileSessionTestAccess::emitCommittedWithRecovery(
        window,destination,committedRecovery);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window).contains(committedRecovery));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window).contains(committedRecovery));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window),QFileInfo(destination).absolutePath());
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPeer(window),
              QStringLiteral("22222222-2222-2222-2222-222222222222"));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window));

    const QString failedSameNameRecovery=directory.filePath(QStringLiteral("failed same-name recovery.bin"));
    const QString committedSameNameDestination=directory.filePath(QStringLiteral("same-name.bin"));
    const QString committedSameNameRecovery=directory.filePath(QStringLiteral("committed same-name recovery.bin"));
    MainWindowEnvironmentProfileSessionTestAccess::queueSameNamePublicationOutcomes(
        window,failedSameNameRecovery,committedSameNameDestination,committedSameNameRecovery);
    MainWindowEnvironmentProfileSessionTestAccess::emitSameNameCommitted(
        window,committedSameNameDestination);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window)
                    .contains(committedSameNameRecovery));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window),
              QFileInfo(committedSameNameDestination).absolutePath());
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPeer(window),
              QStringLiteral("44444444-4444-4444-4444-444444444444"));
    MainWindowEnvironmentProfileSessionTestAccess::emitSameNameRejected(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferStatus(window)
                    .contains(failedSameNameRecovery));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window),
              QFileInfo(failedSameNameRecovery).absolutePath());
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPeer(window),
              QStringLiteral("33333333-3333-3333-3333-333333333333"));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window));
    const QUuid orphanPeer=MainWindowEnvironmentProfileSessionTestAccess::emitVerifiedWithoutOutcome(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window)
                    .contains(QStringLiteral("ausente ou incompatível")));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPeer(window),
              orphanPeer.toString(QUuid::WithoutBraces));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::latestTransferPath(window).isEmpty());
}

TEST(EnvironmentProfileSessionIntegrationTests, RuntimeInvalidationClosesEveryLateConsumer)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("main-window-session.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    credentials.insert(QStringLiteral("InputLeap/file-transfer-pairing-code"),
                       QByteArrayLiteral("LEGACY-RUNTIME-PAIRING-CODE"));
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value);
            return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account);
            return true;
        }));
    ASSERT_EQ(config.fileTransferPairingCode(),
              QStringLiteral("LEGACY-RUNTIME-PAIRING-CODE"));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::loadedPairingSecretPresent(config));
    int stopRequests = 0;
    MainWindow window(settings, config, false, [&stopRequests] { ++stopRequests; },
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_NE(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window), 0)
        << "receiver callbacks were not connected; another GUI may own the test port";
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::legacyPairingEnabled(window));
    const QUuid peer(QStringLiteral("{11111111-1111-1111-1111-111111111111}"));
    constexpr char pskBytes[] = "LIVE_SESSION_PSK\0BINARY";
    QByteArray psk(pskBytes, int(sizeof(pskBytes) - 1));
    psk.detach();
    MainWindowEnvironmentProfileSessionTestAccess::seed(window, peer, psk);

    auto& controller = MainWindowEnvironmentProfileSessionTestAccess::controller(window);
    ASSERT_EQ(controller.capture(EnvironmentProfile::Kind::Office),
              EnvironmentProfileController::Result::Success);
    ASSERT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                  EnvironmentProfileController::ActivationSource::Manual),
              EnvironmentProfileController::Result::Success);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::key(window, peer), psk);
    const auto [directController, directControllerKey] =
        MainWindowEnvironmentProfileSessionTestAccess::trackDirectController(window);
    ASSERT_NE(directController, nullptr);
    ASSERT_FALSE(directControllerKey.isEmpty());
    QSignalSpy directCancelRequested(
        directController, &FileTransferController::cancelRequested);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::activeTransferControllerCount(window), 1);
    const QString queuePath = directory.filePath(QStringLiteral("late-queue.json"));
    const QByteArray queuedId =
        MainWindowEnvironmentProfileSessionTestAccess::seedInvalidQueuedTransfer(
            window, queuePath);
    ASSERT_FALSE(queuedId.isEmpty());
    MainWindowEnvironmentProfileSessionTestAccess::createTray(window);
    MainWindowEnvironmentProfileSessionTestAccess::showTransferQueue(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::transferQueueDialogVisible(window));
    MainWindowEnvironmentProfileSessionTestAccess::armReconnectTimers(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::reconnectTimersActive(window));
    MainWindowEnvironmentProfileSessionTestAccess::createPairingWizard(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::pairingWizardAlive(window));
    QPointer<SettingsDialog> settingsDialog =
        MainWindowEnvironmentProfileSessionTestAccess::createSettingsDialog(window);
    ASSERT_FALSE(settingsDialog.isNull());
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::settingsDialogAlive(window));
    auto* pairingCodeEdit = settingsDialog->findChild<QLineEdit*>(
        QStringLiteral("pairingCodeEdit"));
    ASSERT_NE(pairingCodeEdit, nullptr);
    ASSERT_EQ(pairingCodeEdit->text(), QStringLiteral("LEGACY-RUNTIME-PAIRING-CODE"));
    QSignalSpy settingsRejected(settingsDialog, &QDialog::rejected);
    const quint64 stopGenerationBeforeInvalidation =
        MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window);

    controller.invalidate();
    EXPECT_EQ(stopRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_GT(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              stopGenerationBeforeInvalidation);
    EXPECT_EQ(directCancelRequested.count(), 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::hasShutdownIntent(
        window, directControllerKey));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window), 0);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::zeroconfCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::transferQueuePersistenceEnabled(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::transferQueueDialogVisible(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::transferQueueActionEnabled(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::reconnectTimersActive(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::pairingWizardAlive(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::settingsDialogAlive(window));
    EXPECT_EQ(settingsRejected.count(), 1);
    EXPECT_TRUE(pairingCodeEdit->text().isEmpty());
    EXPECT_TRUE(config.fileTransferPairingCode().isEmpty());
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::loadedPairingSecretPresent(config));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::legacyPairingEnabled(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::pairedSessionCount(window), 0);
    EXPECT_EQ(credentials.value(QStringLiteral("InputLeap/file-transfer-pairing-code")),
              QByteArrayLiteral("LEGACY-RUNTIME-PAIRING-CODE"));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::queuedState(window, queuedId),
              std::optional<TransferQueue::State>{TransferQueue::State::Pending});
    const QString blockedStatus =
        MainWindowEnvironmentProfileSessionTestAccess::statusText(window);
    const int historyCount =
        MainWindowEnvironmentProfileSessionTestAccess::transferHistoryCount(window);
    const QString receivedFolder =
        MainWindowEnvironmentProfileSessionTestAccess::lastReceivedFolder(window);
    const bool receiveBusy =
        MainWindowEnvironmentProfileSessionTestAccess::receiveBusy(window);
    const bool notificationOpenable =
        MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window);
    MainWindowEnvironmentProfileSessionTestAccess::emitLateReceiverCallbacks(window, peer);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window), blockedStatus);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::transferHistoryCount(window),
              historyCount);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::lastReceivedFolder(window),
              receivedFolder);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::receiveBusy(window), receiveBusy);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::receivedNotificationOpenable(window),
              notificationOpenable);
    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window).contains(
        QStringLiteral("confirmed"), Qt::CaseInsensitive));
    window.appendLogRaw(QStringLiteral("accepted client connection from 192.0.2.44"));
    EXPECT_FALSE(settings.contains(QStringLiteral("lastFileTransferDestinationHost")));
}

TEST(EnvironmentProfileSessionIntegrationTests, InvalidStartRestoresDisconnectedUiState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("invalid-start.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    const QString executable = directory.filePath(QStringLiteral("input-leapc.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    ASSERT_GT(placeholder.write("test placeholder"), 0);
    placeholder.close();
    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureInvalidClientStart(
        window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    auto* status = window.findChild<QLabel*>(QStringLiteral("m_pStatusLabel"));
    ASSERT_NE(status, nullptr);
    EXPECT_EQ(status->text(), QStringLiteral("InputLeap is not running."));
}

TEST(EnvironmentProfileSessionIntegrationTests, TemporaryConfigFailureAbortsServiceStart)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("temp-config-failure.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    const QString executable = directory.filePath(QStringLiteral("input-leaps.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    ASSERT_GT(placeholder.write("test placeholder"), 0);
    placeholder.close();

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::failTemporaryConfigCreation(window);
    QTimer::singleShot(0, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* message = qobject_cast<QMessageBox*>(widget))
                message->accept();
        }
    });

    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
}

TEST(EnvironmentProfileSessionIntegrationTests, DesktopLaunchFailureRestoresDisconnectedUiState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("desktop-launch-failure.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);
    const QString executable = directory.filePath(
        QStringLiteral("invalid-input-leapc.exe"));
    QFile invalidExecutable(executable);
    ASSERT_TRUE(invalidExecutable.open(QIODevice::WriteOnly));
    ASSERT_EQ(invalidExecutable.write("not a windows executable"), 24);
    invalidExecutable.close();

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    QTimer::singleShot(0, [] {
        for (QWidget* widget : QApplication::topLevelWidgets()) {
            if (auto* message = qobject_cast<QMessageBox*>(widget))
                message->accept();
        }
    });

    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_FALSE(config.startedBefore());
    settings.sync();
    EXPECT_FALSE(settings.value(QStringLiteral("startedBefore"), false).toBool());

    MainWindowEnvironmentProfileSessionTestAccess::reportUnexpectedDesktopExit(window);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::environmentProfileBusy(window));
    EXPECT_FALSE(config.startedBefore());
    settings.sync();
    EXPECT_FALSE(settings.value(QStringLiteral("startedBefore"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceRejectionRestoresDisconnectedUiState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-start-rejection.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    const QString executable = directory.filePath(QStringLiteral("input-leaps.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    placeholder.close();

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceDisconnected(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_FALSE(config.startedBefore());
    settings.sync();
    EXPECT_FALSE(settings.value(QStringLiteral("startedBefore"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, SuccessfulManualServiceStartPersistsStartedBefore)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-start-success.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    const QString executable = directory.filePath(QStringLiteral("input-leaps.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    placeholder.close();

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    ASSERT_FALSE(config.startedBefore());

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStarted(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_TRUE(config.startedBefore());
    settings.sync();
    EXPECT_TRUE(settings.value(QStringLiteral("startedBefore"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, LateDesktopCrashPreservesConfirmedStartedBefore)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("desktop-start-success.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_GT(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window), 0);
    ASSERT_NE(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window),
              kInstalledFileTransferPort);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window,
        QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH)
    );
    ASSERT_FALSE(config.startedBefore());

    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_TRUE(config.startedBefore());
    settings.sync();
    EXPECT_TRUE(settings.value(QStringLiteral("startedBefore"), false).toBool());

    MainWindowEnvironmentProfileSessionTestAccess::reportUnexpectedDesktopExit(window);
    EXPECT_TRUE(config.startedBefore());
    settings.sync();
    EXPECT_TRUE(settings.value(QStringLiteral("startedBefore"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, RealNonZeroDesktopFinishPreservesConfirmedStartedBefore)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("desktop-real-nonzero.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutableWithArguments(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH),
        {QStringLiteral("--exit-code"), QStringLiteral("7")});

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    ASSERT_TRUE(config.startedBefore());

    QElapsedTimer timeout;
    timeout.start();
    while (MainWindowEnvironmentProfileSessionTestAccess::processCreated(window) &&
           timeout.elapsed() < 3000) {
        QApplication::processEvents(QEventLoop::AllEvents, 50);
    }

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_TRUE(config.startedBefore());
    settings.sync();
    EXPECT_TRUE(settings.value(QStringLiteral("startedBefore"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, LateDesktopNormalFailurePreservesConfirmedStartedBefore)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("desktop-normal-failure.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window,
        QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH)
    );

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    ASSERT_TRUE(config.startedBefore());
    settings.sync();
    ASSERT_TRUE(settings.value(QStringLiteral("startedBefore"), false).toBool());

    MainWindowEnvironmentProfileSessionTestAccess::reportUnexpectedDesktopNormalFailure(window);
    EXPECT_TRUE(config.startedBefore());
    settings.sync();
    EXPECT_TRUE(settings.value(QStringLiteral("startedBefore"), false).toBool());
}

TEST(EnvironmentProfileSessionIntegrationTests, FailedManualDesktopNormalExitReleasesFinishedProcess)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("desktop-process-cleanup.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window,
        QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH)
    );

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));

    QElapsedTimer timeout;
    timeout.start();
    while (MainWindowEnvironmentProfileSessionTestAccess::processCreated(window) &&
           timeout.elapsed() < 3000) {
        QApplication::processEvents(QEventLoop::AllEvents, 50);
    }
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, DesktopStopSurvivesReentrantFinishedProcessCleanup)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("desktop-stop-reentrant.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::installRunningDesktopProcess(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    MainWindowEnvironmentProfileSessionTestAccess::clearDesktopProcessDuringStopWait(window);

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceStartTimeoutRestoresDisconnectedUiState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-start-timeout.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    const QString executable = directory.filePath(QStringLiteral("input-leaps.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    placeholder.close();

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    const quint64 stopGenerationBeforeTimeout =
        MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::startActionEnabled(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::stopActionEnabled(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStartTimeout(window);

    EXPECT_GT(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              stopGenerationBeforeTimeout);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTING);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window).contains(
        QStringLiteral("confirmation is pending"), Qt::CaseInsensitive));
    EXPECT_FALSE(config.startedBefore());
    settings.sync();
    EXPECT_FALSE(settings.value(QStringLiteral("startedBefore"), false).toBool());

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStarted(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTING);
    EXPECT_FALSE(config.startedBefore());

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_FALSE(config.startedBefore());
}

TEST(EnvironmentProfileSessionIntegrationTests,
     TransportLossDuringPendingServiceStartRequestsStopAndCannotRearmStart)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-start-transport-loss.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    const QString executable = directory.filePath(QStringLiteral("input-leaps.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    placeholder.close();
    int stopRequests = 0;

    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0},
                      std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceTransportUnavailable(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::startActionEnabled(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::stopActionEnabled(window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    EXPECT_EQ(stopRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     ReplayedCoreStateBeforeCommandAcknowledgementDoesNotConfirmServiceStart)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-start-stale-replay.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    const QString executable = directory.filePath(QStringLiteral("input-leaps.exe"));
    QFile placeholder(executable);
    ASSERT_TRUE(placeholder.open(QIODevice::WriteOnly));
    placeholder.close();

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0},
                      std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(window, executable);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));

    // The daemon replays its previous snapshot immediately after Hello, before it
    // processes the command queued by this Start attempt. That replay is not proof
    // that the current command was durably applied.
    MainWindowEnvironmentProfileSessionTestAccess::reportUnacknowledgedServiceStarted(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_FALSE(config.startedBefore());
}

TEST(EnvironmentProfileSessionIntegrationTests, MainWindowRemainsResizableAfterLayoutRequest)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("resizable-main-window.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                            : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
    QEvent request(QEvent::LayoutRequest);
    QApplication::sendEvent(&window, &request);

    EXPECT_NE(window.minimumSize(), window.maximumSize());
    const QSize requested = window.size() + QSize(40, 30);
    window.resize(requested);
    EXPECT_EQ(window.size(), requested);
}

TEST(EnvironmentProfileSessionIntegrationTests, CorruptActiveProfileGenerationRestoresCommittedFallbackAndReportsScope)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("main-window-recovery.ini"));
    QSettings settings(path, QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    const auto credentialStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& account) -> std::optional<QByteArray> {
                const auto it = credentials.constFind(account);
                return it == credentials.cend() ? std::nullopt
                                                : std::optional<QByteArray>(*it);
            },
            [&credentials](const QString& account, const QByteArray& value) {
                credentials.insert(account, value);
                return true;
            },
            [&credentials](const QString& account) {
                credentials.remove(account);
                return true;
            });
    };

    {
        AppConfig config(&settings, credentialStore());
        MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});
        ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
        auto& controller = MainWindowEnvironmentProfileSessionTestAccess::controller(window);
        ASSERT_EQ(controller.activate(EnvironmentProfile::Kind::Office,
                                      EnvironmentProfileController::ActivationSource::Manual),
                  EnvironmentProfileController::Result::Success);
    }

    settings.sync();
    const QString failed = settings.value(
        QStringLiteral("environmentProfiles/activeGeneration")).toString();
    const QString fallback = settings.value(
        QStringLiteral("environmentProfiles/recoveryGeneration")).toString();
    ASSERT_FALSE(failed.isEmpty());
    ASSERT_FALSE(fallback.isEmpty());
    ASSERT_NE(failed, fallback);
    settings.setValue(
        QStringLiteral("environmentProfiles/generations/%1/profiles/size").arg(failed),
        QStringLiteral("4"));
    settings.sync();

    AppConfig recoveredConfig(&settings, credentialStore());
    MainWindow recoveredWindow(settings, recoveredConfig, false, {},
                               std::optional<quint16>{0}, std::optional<quint16>{0});
    EXPECT_NE(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(recoveredWindow),
              quint16{24810});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(recoveredWindow));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::controller(
                    recoveredWindow).recoveredOnInitialize());
    EXPECT_EQ(settings.value(
                  QStringLiteral("environmentProfiles/activeGeneration")).toString(),
              fallback);

    auto* status = recoveredWindow.findChild<QLabel*>(QStringLiteral("m_pStatusLabel"));
    ASSERT_NE(status, nullptr);
    EXPECT_TRUE(status->text().contains(QStringLiteral("Previous profiles were restored")));
    EXPECT_FALSE(status->text().contains(QStringLiteral("credencial"),
                                         Qt::CaseInsensitive));
    EXPECT_EQ(status->accessibleName(), status->text());
    const auto collection = MainWindowEnvironmentProfileSessionTestAccess::controller(
        recoveredWindow).collectionSnapshot();
    ASSERT_TRUE(collection);
    const auto active = std::find_if(
        collection->profiles.cbegin(), collection->profiles.cend(),
        [kind = collection->activeKind](const EnvironmentProfile& profile) {
            return profile.kind == kind;
        });
    ASSERT_NE(active, collection->profiles.cend());
    EXPECT_EQ(recoveredWindow.serverConfig().numRows(), active->layout.rows);
    EXPECT_EQ(recoveredWindow.serverConfig().numColumns(), active->layout.columns);
    ASSERT_EQ(recoveredWindow.serverConfig().screenLayout().devices().size(),
              active->layout.extension.devices().size());
    for (size_t i = 0; i < active->layout.extension.devices().size(); ++i) {
        EXPECT_EQ(recoveredWindow.serverConfig().screenLayout().devices()[i].uuid,
                  active->layout.extension.devices()[i].uuid);
        EXPECT_EQ(recoveredWindow.serverConfig().screenLayout().devices()[i].technicalName,
                  active->layout.extension.devices()[i].technicalName);
        EXPECT_EQ(recoveredWindow.serverConfig().screenLayout().devices()[i].geometry,
                  active->layout.extension.devices()[i].geometry);
    }
}

#ifdef Q_OS_WIN
TEST(EnvironmentProfileSessionIntegrationTests, NativeEmptyProfileStoreBootstrapsTwoScreenLegacyLayoutWithStableIdentities)
{
    const QString application = QStringLiteral("EnvironmentProfileSessionIntegrationTests-") +
        QUuid::createUuid().toString(QUuid::WithoutBraces);
    QSettings settings(QSettings::NativeFormat, QSettings::UserScope,
                       QStringLiteral("InputLeapTests"), application);
    settings.clear();
    const auto cleanup = qScopeGuard([&settings] {
        settings.clear();
        settings.sync();
    });
    const QUuid remoteUuid(QStringLiteral("12ae7282-d1d4-43ae-85c3-236a554590bc"));
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("windows-main"));
    settings.beginGroup(QStringLiteral("internalConfig"));
    settings.setValue(QStringLiteral("numColumns"), 5);
    settings.setValue(QStringLiteral("numRows"), 3);
    settings.beginWriteArray(QStringLiteral("screens"));
    for (int i = 0; i < 15; ++i) {
        settings.setArrayIndex(i);
        settings.setValue(QStringLiteral("name"),
                          i == 7 ? QStringLiteral("linux-peer")
                                 : i == 8 ? QStringLiteral("windows-main")
                                          : QString());
    }
    settings.endArray();
    settings.endGroup();
    {
        DeviceRegistry registry(settings);
        DeviceInfo remote(remoteUuid);
        remote.setTechnicalName(QStringLiteral("linux-peer"));
        ASSERT_EQ(registry.add(remote), DeviceRegistry::AddResult::Added);
        ASSERT_EQ(registry.save(), DeviceRegistry::SaveResult::Success);
    }
    settings.setValue(QStringLiteral("environmentProfiles/generations/_seed"), 1);
    settings.sync();
    settings.remove(QStringLiteral("environmentProfiles/generations/_seed"));
    settings.sync();

    EXPECT_FALSE(LocalDeviceIdentity::loadExisting(settings).ok);
    {
        DeviceRegistry registry(settings, {}, DeviceRegistry::PersistenceMode::ReadOnly);
        ASSERT_EQ(registry.loadStatus(), DeviceRegistry::LoadStatus::Loaded);
        ASSERT_TRUE(registry.find(remoteUuid).has_value());
    }

    QHash<QString, QByteArray> credentials;
    const auto credentialStore = [&credentials] {
        return SecureCredentialStore(
            [&credentials](const QString& account) -> std::optional<QByteArray> {
                const auto it = credentials.constFind(account);
                return it == credentials.cend() ? std::nullopt
                                                 : std::optional<QByteArray>(*it);
            },
            [&credentials](const QString& account, const QByteArray& value) {
                credentials.insert(account, value); return true;
            },
            [&credentials](const QString& account) {
                credentials.remove(account); return true;
            });
    };
    AppConfig config(&settings, credentialStore());
    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});

    const auto loadedIdentity = LocalDeviceIdentity::loadExisting(settings);
    ASSERT_TRUE(loadedIdentity.ok) << loadedIdentity.detail.toStdString();
    const QUuid localUuid = loadedIdentity.uuid;
    ASSERT_FALSE(localUuid.isNull());

    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window))
        << MainWindowEnvironmentProfileSessionTestAccess::runtimeBlockMessage(window).toStdString();
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
    const auto& devices = window.serverConfig().screenLayout().devices();
    ASSERT_EQ(devices.size(), 2u);
    const auto local = std::find_if(devices.cbegin(), devices.cend(), [](const auto& device) {
        return device.technicalName == QStringLiteral("windows-main");
    });
    const auto remote = std::find_if(devices.cbegin(), devices.cend(), [](const auto& device) {
        return device.technicalName == QStringLiteral("linux-peer");
    });
    ASSERT_NE(local, devices.cend());
    ASSERT_NE(remote, devices.cend());
    EXPECT_EQ(local->uuid, localUuid);
    EXPECT_EQ(remote->uuid, remoteUuid);

    settings.sync();
    QSettings reopened(QSettings::NativeFormat, QSettings::UserScope,
                       QStringLiteral("InputLeapTests"), application);
    auto authenticate = [&credentials](QByteArrayView payload, bool)
        -> std::optional<QByteArray> {
        const auto it = credentials.constFind(
            QStringLiteral("InputLeap/environment-profiles/auth-key"));
        if (it == credentials.cend())
            return std::nullopt;
        const QByteArray domain = QByteArrayLiteral(
            "inputleap-environment-profile-manifest-v2");
        const QByteArray mac = RecoveryArtifactAuthenticator::authenticate(
            QByteArrayView(*it), QByteArrayView(domain), {payload});
        return mac.isEmpty() ? std::nullopt : std::optional<QByteArray>(mac);
    };
    EnvironmentProfileStore reopenedStore(
        reopened, {}, authenticate,
        [&credentials] {
            return credentials.contains(
                QStringLiteral("InputLeap/environment-profiles/auth-key"));
        });
    ASSERT_EQ(reopenedStore.load(), EnvironmentProfileStore::LoadStatus::Loaded);
    const auto profiles = reopenedStore.profiles();
    ASSERT_EQ(profiles.size(), EnvironmentProfile::canonicalKinds().size());
    for (const auto kind : EnvironmentProfile::canonicalKinds()) {
        const auto profile = reopenedStore.profile(kind);
        ASSERT_TRUE(profile) << static_cast<int>(kind);
        const auto& persisted = profile->layout.extension.devices();
        ASSERT_EQ(persisted.size(), 2u);
        EXPECT_TRUE(std::any_of(persisted.cbegin(), persisted.cend(),
            [&](const auto& device) { return device.uuid == localUuid; }));
        EXPECT_TRUE(std::any_of(persisted.cbegin(), persisted.cend(),
            [&](const auto& device) { return device.uuid == remoteUuid; }));
    }
}
#endif

TEST(EnvironmentProfileSessionIntegrationTests, BlockedStartupDoesNotPersistIdentityRegistryOrShutdownSettings)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("blocked-read-only.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"),
                      EnvironmentProfileStore::SchemaVersion + 1);
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    {
        int stopRequests = 0;
        MainWindow window(settings, config, false,
                          [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
        ASSERT_FALSE(window.runtimeConsumersEnabled());
        EXPECT_EQ(stopRequests, 1);
        ASSERT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
        EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::transferQueuePersistenceEnabled(window));
        EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::transferQueueActionEnabled(window));
        EXPECT_FALSE(settings.contains(QStringLiteral("localDeviceIdentity/activeGeneration")));
        EXPECT_FALSE(settings.contains(QStringLiteral("deviceRegistry/schemaVersion")));
        EXPECT_FALSE(settings.contains(QStringLiteral("groupServerChecked")));
        EXPECT_FALSE(settings.contains(QStringLiteral("internalConfig/numColumns")));

        int bonjourPrompts = 0;
        QTimer::singleShot(0, [&bonjourPrompts] {
            for (QWidget* widget : QApplication::topLevelWidgets()) {
                if (auto* message = qobject_cast<QMessageBox*>(widget)) {
                    ++bonjourPrompts;
                    message->done(QMessageBox::No);
                }
            }
        });
        window.open();
        EXPECT_EQ(bonjourPrompts, 0);
        EXPECT_FALSE(config.autoConfigPrompted());
        EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::trayActionCount(
                      window), 3);
        MainWindowEnvironmentProfileSessionTestAccess::invokePersistentSaves(window);
        EXPECT_FALSE(settings.contains(QStringLiteral("groupServerChecked")));
        EXPECT_FALSE(settings.contains(QStringLiteral("transferHistory/size")));
        window.hide();
    }

    settings.sync();
    EXPECT_FALSE(settings.contains(QStringLiteral("localDeviceIdentity/activeGeneration")));
    EXPECT_FALSE(settings.contains(QStringLiteral("deviceRegistry/schemaVersion")));
    EXPECT_FALSE(settings.contains(QStringLiteral("groupServerChecked")));
    EXPECT_FALSE(settings.contains(QStringLiteral("groupClientChecked")));
    EXPECT_FALSE(settings.contains(QStringLiteral("internalConfig/numColumns")));
}

TEST(EnvironmentProfileSessionIntegrationTests, HiddenTrayMenuExposesEssentialWindowActions)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("tray-actions.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value);
            return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account);
            return true;
        }));
    MainWindow window(settings, config, false, {},
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));

    MainWindowEnvironmentProfileSessionTestAccess::createTray(window);
    const QStringList texts =
        MainWindowEnvironmentProfileSessionTestAccess::trayActionTexts(window);
    EXPECT_TRUE(texts.contains(QStringLiteral("Abrir InputLeap")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Iniciar")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Parar")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Recarregar")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Transferências")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Mostrar log")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Configurações...")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Verificar atualizações...")));
    EXPECT_TRUE(texts.contains(QStringLiteral("Sair")));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::trayContainsWindowAction(
        window, "m_pActionStartCmdApp"));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::trayContainsWindowAction(
        window, "m_pActionStopCmdApp"));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::trayContainsWindowAction(
        window, "m_pActionReload"));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::trayContainsWindowAction(
        window, "m_pActionShowLog"));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::trayContainsWindowAction(
        window, "m_pActionSettings"));
}

TEST(EnvironmentProfileSessionIntegrationTests, InternalServerCannotStartWhenProfileLayoutReconciliationIsUnavailable)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("blocked-start.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.setValue(QStringLiteral("environmentProfiles/schemaVersion"),
                      EnvironmentProfileStore::SchemaVersion + 1);
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    int stopRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    EXPECT_EQ(stopRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::zeroconfCreated(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window), 0);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::sslCertificateCreated(window));
    const QByteArray queuedId =
        MainWindowEnvironmentProfileSessionTestAccess::seedInvalidQueuedTransfer(
            window, directory.filePath(QStringLiteral("blocked-queue.json")));
    ASSERT_FALSE(queuedId.isEmpty());
    MainWindowEnvironmentProfileSessionTestAccess::dispatchTransfers(window);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::queuedState(
                  window, queuedId),
              std::optional<TransferQueue::State>{TransferQueue::State::Pending});
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::dashboardState(window),
              MainWindow::tr("Startup blocked"));
    auto* status = window.findChild<QLabel*>(QStringLiteral("m_pStatusLabel"));
    ASSERT_NE(status, nullptr);
    const QString pendingStopStatus = MainWindow::tr(
        "Startup blocked: the core stop was requested and confirmation is pending.");
    EXPECT_EQ(status->text(), pendingStopStatus);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));

    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_EQ(status->text(), pendingStopStatus);
    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_EQ(status->text(), MainWindow::tr(
        "Startup blocked: persistent configuration became unavailable. "
        "The core stop was confirmed."));

    MainWindowEnvironmentProfileSessionTestAccess::selectClient(window);
    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));

    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectExternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceStopRemainsPendingUntilNonceBoundAcknowledgement)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-stop.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr("InputLeap stop was requested; confirmation is pending."));

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceDisconnected(window);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr("InputLeap stop was requested; confirmation is pending."));
    ASSERT_FALSE(settings.contains(QStringLiteral("lastFileTransferDestinationHost")));
    window.appendLogRaw(QStringLiteral("accepted client connection from 192.0.2.44"));
    EXPECT_FALSE(settings.contains(QStringLiteral("lastFileTransferDestinationHost")));

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);

    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr("InputLeap is not running."));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     TransportUnavailableKeepsStartBlockedWhileServiceStopRemainsPending)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-stop-transport-loss.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    MainWindow window(settings, config, false, [] {}, std::optional<quint16>{0},
                      std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("127.0.0.1")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);
    MainWindowEnvironmentProfileSessionTestAccess::restart(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    const quint64 stopGeneration =
        MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window);
    ASSERT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceTransportUnavailable(window);

    ASSERT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);
    ASSERT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::startActionEnabled(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::stopActionEnabled(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              stopGeneration);

    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              stopGeneration);
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceStopTimeoutOutlastsDaemonStopBudget)
{
    EXPECT_GT(
        MainWindowEnvironmentProfileSessionTestAccess::serviceStopConfirmationTimeoutMs(),
        35000);
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceStartTimeoutOutlastsDaemonStartBudget)
{
    EXPECT_GT(
        MainWindowEnvironmentProfileSessionTestAccess::serviceStartConfirmationTimeoutMs(),
        35000);
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceStopTimeoutEndsPendingTransitionFailClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-stop-timeout.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0},
                      std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStopTimeout(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr("InputLeap stop was not confirmed; the core state is unknown."));

    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("192.0.2.1")));
    MainWindowEnvironmentProfileSessionTestAccess::start(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::statusText(window),
              MainWindow::tr("InputLeap stop was not confirmed; the core state is unknown."));
}

TEST(EnvironmentProfileSessionIntegrationTests, RealIpcStopAcknowledgementClosesTransportAndPublishesToMainWindow)
{
    QTcpServer daemon;
    ASSERT_TRUE(daemon.listen(QHostAddress::LocalHost, 0));

    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("real-ipc-stop.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    MainWindow window(settings, config, true, {}, quint16(0), daemon.serverPort());
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    QTRY_VERIFY_WITH_TIMEOUT(daemon.hasPendingConnections(), 3000);
    QScopedPointer<QTcpSocket> peer(daemon.nextPendingConnection());
    ASSERT_TRUE(peer);
    QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 5, 3000);
    QByteArray wire = peer->readAll();

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);

    QElapsedTimer timeout;
    timeout.start();
    QByteArray nonce;
    while (nonce.isEmpty() && timeout.elapsed() < 3000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        wire += peer->readAll();
        nonce = sessionStopNonce(wire);
        QThread::msleep(10);
    }
    ASSERT_EQ(nonce.size(), 16) << "wire=" << wire.toHex().constData();
    ASSERT_EQ(peer->write(sessionAppliedAcknowledgement(nonce)), qint64(24));
    ASSERT_TRUE(peer->waitForBytesWritten(1000));

    QTRY_VERIFY_WITH_TIMEOUT(
        !MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window), 3000);
    QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
}

TEST(EnvironmentProfileSessionIntegrationTests,
     RepeatedStopAndRuntimeInvalidationCoalesceWithNonceBoundStopAlreadyInFlight)
{
    QTcpServer daemon;
    ASSERT_TRUE(daemon.listen(QHostAddress::LocalHost, 0));

    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("real-ipc-stop-invalidation.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    MainWindow window(settings, config, true, {}, quint16(0), daemon.serverPort());
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    QTRY_VERIFY_WITH_TIMEOUT(daemon.hasPendingConnections(), 3000);
    QScopedPointer<QTcpSocket> peer(daemon.nextPendingConnection());
    ASSERT_TRUE(peer);
    QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 5, 3000);
    QByteArray wire = peer->readAll();

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    QElapsedTimer timeout;
    timeout.start();
    QByteArray nonce;
    while (nonce.isEmpty() && timeout.elapsed() < 3000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        wire += peer->readAll();
        nonce = sessionStopNonce(wire);
        QThread::msleep(10);
    }
    ASSERT_EQ(nonce.size(), 16) << "wire=" << wire.toHex().constData();
    const quint64 inFlightGeneration =
        MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window);

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              inFlightGeneration);

    MainWindowEnvironmentProfileSessionTestAccess::controller(window).invalidate();

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              inFlightGeneration);
    QApplication::processEvents(QEventLoop::AllEvents, 50);
    EXPECT_EQ(peer->bytesAvailable(), qint64(0));

    ASSERT_EQ(peer->write(sessionAppliedAcknowledgement(nonce)), qint64(24));
    ASSERT_TRUE(peer->waitForBytesWritten(1000));
    QTRY_VERIFY_WITH_TIMEOUT(
        !MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window), 3000);
    QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::statusText(window).contains(
        QStringLiteral("confirmed"), Qt::CaseInsensitive));
}

TEST(EnvironmentProfileSessionIntegrationTests,
     StopRequestedAfterTimeoutKeepsOriginalNonceAndUnconfirmedGeneration)
{
    QTcpServer daemon;
    ASSERT_TRUE(daemon.listen(QHostAddress::LocalHost, 0));

    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("real-ipc-stop-after-timeout.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    MainWindow window(settings, config, true, {}, quint16(0), daemon.serverPort());
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    QTRY_VERIFY_WITH_TIMEOUT(daemon.hasPendingConnections(), 3000);
    QScopedPointer<QTcpSocket> peer(daemon.nextPendingConnection());
    ASSERT_TRUE(peer);
    QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 5, 3000);
    QByteArray wire = peer->readAll();

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    QElapsedTimer timeout;
    timeout.start();
    QByteArray nonce;
    while (nonce.isEmpty() && timeout.elapsed() < 3000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        wire += peer->readAll();
        nonce = sessionStopNonce(wire);
        QThread::msleep(10);
    }
    ASSERT_EQ(nonce.size(), 16) << "wire=" << wire.toHex().constData();

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStopTimeout(window);
    ASSERT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopUnconfirmed(window));
    const quint64 timedOutGeneration =
        MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window);

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopUnconfirmed(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window),
              timedOutGeneration);
    QApplication::processEvents(QEventLoop::AllEvents, 50);
    EXPECT_EQ(peer->bytesAvailable(), qint64(0));

    ASSERT_EQ(peer->write(sessionAppliedAcknowledgement(nonce)), qint64(24));
    ASSERT_TRUE(peer->waitForBytesWritten(1000));
    QTRY_VERIFY_WITH_TIMEOUT(
        !MainWindowEnvironmentProfileSessionTestAccess::serviceStopUnconfirmed(window), 3000);
    QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceRestartWaitsForStopAcknowledgementBeforeStarting)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-restart.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window,
        QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH)
    );
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    MainWindowEnvironmentProfileSessionTestAccess::restart(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(reconnectRequests, 0);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStarted(window);
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_EQ(reconnectRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::startActionEnabled(window));
    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(
        window));
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTING);

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStarted(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, FingerprintAcceptanceWaitsForServiceStopAndReconnectReadiness)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("fingerprint-restart.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("peer.example")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintTrustStore(
        window, [](bool) { return false; });
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintDialog(
        window, [] { return int(QDialog::Accepted); });

    MainWindowEnvironmentProfileSessionTestAccess::processUntrustedFingerprint(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(reconnectRequests, 0);

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_EQ(reconnectRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(window));

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, FingerprintDialogAckDuringExecWaitsForReplacementConnection)
{
    QTcpServer daemon;
    ASSERT_TRUE(daemon.listen(QHostAddress::LocalHost, 0));
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("fingerprint-modal-ack.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int reconnectRequests = 0;
    int trustWrites = 0;
    MainWindow window(settings, config, true, {}, std::optional<quint16>{0},
                      daemon.serverPort());
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("peer.example")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    QTRY_VERIFY_WITH_TIMEOUT(daemon.hasPendingConnections(), 3000);
    QScopedPointer<QTcpSocket> peer(daemon.nextPendingConnection());
    ASSERT_TRUE(peer);
    QTRY_VERIFY_WITH_TIMEOUT(peer->bytesAvailable() >= 5, 3000);
    QByteArray wire = peer->readAll();
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintTrustStore(
        window, [&trustWrites](bool persist) {
            if (persist) ++trustWrites;
            return false;
        });
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintDialog(window, [&] {
        EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
        EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
        QElapsedTimer timeout;
        timeout.start();
        QByteArray nonce;
        while (nonce.isEmpty() && timeout.elapsed() < 3000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
            wire += peer->readAll();
            nonce = sessionStopNonce(wire);
            QThread::msleep(10);
        }
        EXPECT_EQ(nonce.size(), 16) << "wire=" << wire.toHex().constData();
        if (nonce.size() != 16) return int(QDialog::Rejected);
        EXPECT_EQ(peer->write(sessionAppliedAcknowledgement(nonce)), qint64(24));
        EXPECT_TRUE(peer->waitForBytesWritten(1000));
        timeout.restart();
        while (MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window) &&
               timeout.elapsed() < 3000) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
            QThread::msleep(10);
        }
        EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
        return int(QDialog::Accepted);
    });

    MainWindowEnvironmentProfileSessionTestAccess::processUntrustedFingerprint(window);

    EXPECT_EQ(trustWrites, 1);
    QTRY_COMPARE_WITH_TIMEOUT(peer->state(), QAbstractSocket::UnconnectedState, 3000);
    EXPECT_EQ(reconnectRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, DesktopFingerprintAcceptanceCreatesNoServiceRestartIntent)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("fingerprint-desktop.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Desktop);
    MainWindow window(settings, config, false, {}, std::optional<quint16>{0},
                      std::optional<quint16>{0});
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("peer.example")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutableWithArguments(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH),
        {QStringLiteral("--wait")});
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintTrustStore(
        window, [](bool) { return false; });
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintDialog(
        window, [] { return int(QDialog::Accepted); });

    MainWindowEnvironmentProfileSessionTestAccess::processUntrustedFingerprint(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
}

TEST(EnvironmentProfileSessionIntegrationTests, ExplicitStopDuringFingerprintDialogCannotBeUndoneByAcceptance)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("fingerprint-explicit-stop.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0},
                      std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("peer.example")));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintTrustStore(
        window, [](bool) { return false; });
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintDialog(window, [&] {
        EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
        MainWindowEnvironmentProfileSessionTestAccess::stop(window);
        return int(QDialog::Accepted);
    });

    MainWindowEnvironmentProfileSessionTestAccess::processUntrustedFingerprint(window);

    // The explicit stop shares the already in-flight physical stop request.
    EXPECT_EQ(stopRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_EQ(reconnectRequests, 0);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, FingerprintAcceptanceCannotRearmRestartAfterRuntimeInvalidation)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("fingerprint-invalidated.ini")), QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    int trustWrites = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("peer.example")));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintTrustStore(
        window, [&trustWrites](bool write) {
            if (write) ++trustWrites;
            return false;
        });
    MainWindowEnvironmentProfileSessionTestAccess::useFingerprintDialog(window, [&] {
        EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
        MainWindowEnvironmentProfileSessionTestAccess::invalidateRuntime(window);
        return int(QDialog::Accepted);
    });

    MainWindowEnvironmentProfileSessionTestAccess::processUntrustedFingerprint(window);

    // Runtime invalidation keeps the existing nonce-bound stop in flight.
    EXPECT_EQ(stopRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(reconnectRequests, 0);
    EXPECT_EQ(trustWrites, 0);
}

TEST(EnvironmentProfileSessionIntegrationTests, ServiceRestartHandlesSynchronousStopAcknowledgement)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-restart-sync-ack.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    bool acknowledgeSynchronously = false;
    MainWindow* windowPtr = nullptr;
    MainWindow window(settings, config, false,
                      [&] {
                          ++stopRequests;
                          if (acknowledgeSynchronously && windowPtr) {
                              MainWindowEnvironmentProfileSessionTestAccess::
                                  emitServiceStopConfirmed(*windowPtr);
                          }
                      },
                      std::optional<quint16>{0}, std::optional<quint16>{0});
    windowPtr = &window;
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH));
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    acknowledgeSynchronously = true;
    MainWindowEnvironmentProfileSessionTestAccess::restart(window);

    EXPECT_EQ(stopRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(
        window));
    EXPECT_EQ(reconnectRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::startActionEnabled(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, ExplicitStopCancelsPendingServiceRestartIntent)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-restart-cancel.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::selectInternalServer(window));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window,
        QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH)
    );
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    MainWindowEnvironmentProfileSessionTestAccess::restart(window);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    ASSERT_EQ(stopRequests, 1);

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    // Cancelling restart intent must not replace the in-flight stop request.
    EXPECT_EQ(stopRequests, 1);
    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);

    EXPECT_EQ(reconnectRequests, 0);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
}

TEST(EnvironmentProfileSessionIntegrationTests, AutomaticReconnectWaitsForStopAcknowledgementBeforeStarting)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-reconnect.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("192.0.2.10")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window,
        QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH)
    );
    const QUuid peer =
        MainWindowEnvironmentProfileSessionTestAccess::authorizeAutomaticReconnect(window);
    ASSERT_FALSE(peer.isNull());
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::reconnect(
        window, peer, QStringLiteral("192.0.2.20")));

    EXPECT_EQ(stopRequests, 1);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTED);

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_EQ(reconnectRequests, 1);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::CONNECTING);
}

TEST(EnvironmentProfileSessionIntegrationTests, ExplicitStopCancelsAutomaticRestartAwaitingReconnect)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-reconnect-cancel.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("192.0.2.10")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH));
    const QUuid peer =
        MainWindowEnvironmentProfileSessionTestAccess::authorizeAutomaticReconnect(window);
    ASSERT_FALSE(peer.isNull());
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::reconnect(
        window, peer, QStringLiteral("192.0.2.20")));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    ASSERT_EQ(stopRequests, 1);

    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    ASSERT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    ASSERT_EQ(reconnectRequests, 1);
    ASSERT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));

    MainWindowEnvironmentProfileSessionTestAccess::stop(window);
    ASSERT_EQ(stopRequests, 2);
    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::connectionState(window),
              AppConnectionState::DISCONNECTED);
}

TEST(EnvironmentProfileSessionIntegrationTests, RuntimeInvalidationCancelsAutomaticRestartAwaitingReconnect)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("service-reconnect-invalidate.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt
                                             : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));
    MainWindowEnvironmentProfileSessionTestAccess::setProcessMode(config, Service);
    int stopRequests = 0;
    int reconnectRequests = 0;
    MainWindow window(settings, config, false,
                      [&stopRequests] { ++stopRequests; }, std::optional<quint16>{0}, std::optional<quint16>{0});
    MainWindowEnvironmentProfileSessionTestAccess::observeServiceReconnect(
        window, [&reconnectRequests] { ++reconnectRequests; });
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::configureClientStart(
        window, QStringLiteral("192.0.2.10")));
    MainWindowEnvironmentProfileSessionTestAccess::useExecutable(
        window, QString::fromUtf8(INPUTLEAP_PROCESS_FIXTURE_HELPER_PATH));
    const QUuid peer =
        MainWindowEnvironmentProfileSessionTestAccess::authorizeAutomaticReconnect(window);
    ASSERT_FALSE(peer.isNull());
    MainWindowEnvironmentProfileSessionTestAccess::reportConnected(window);

    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::reconnect(
        window, peer, QStringLiteral("192.0.2.20")));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    MainWindowEnvironmentProfileSessionTestAccess::emitServiceStopConfirmed(window);
    ASSERT_EQ(reconnectRequests, 1);
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(
        window));
    ASSERT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::internalReconnect(window));

    MainWindowEnvironmentProfileSessionTestAccess::controller(window).invalidate();

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartPending(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceRestartAwaitingReconnect(
        window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::internalReconnect(window));
    MainWindowEnvironmentProfileSessionTestAccess::reportServiceReconnectReady(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStartPending(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
}

TEST(EnvironmentProfileSessionIntegrationTests, InvalidPendingImportBlocksEveryRuntimeConsumer)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QSettings settings(directory.filePath(QStringLiteral("blocked-import.ini")),
                       QSettings::IniFormat);
    settings.setValue(QStringLiteral("screenName"), QStringLiteral("local"));
    settings.setValue(QStringLiteral("configurationImportJournal/state"),
                      QStringLiteral("pending"));
    settings.sync();
    QHash<QString, QByteArray> credentials;
    AppConfig config(&settings, SecureCredentialStore(
        [&credentials](const QString& account) -> std::optional<QByteArray> {
            const auto it = credentials.constFind(account);
            return it == credentials.cend() ? std::nullopt : std::optional<QByteArray>(*it);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value); return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account); return true;
        }));

    MainWindow window(settings, config, false, {}, std::optional<quint16>{0}, std::optional<quint16>{0});

    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::initialized(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::runtimeConsumersEnabled(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::zeroconfCreated(window));
    EXPECT_EQ(MainWindowEnvironmentProfileSessionTestAccess::fileTransferPort(window), 0);
    MainWindowEnvironmentProfileSessionTestAccess::selectClient(window);
    MainWindowEnvironmentProfileSessionTestAccess::start(window);
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::expectedStopped(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::processCreated(window));
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::lastStartSucceeded(window));
    EXPECT_TRUE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_GT(MainWindowEnvironmentProfileSessionTestAccess::serviceStopGeneration(window), 0u);
    auto* status = window.findChild<QLabel*>(QStringLiteral("m_pStatusLabel"));
    ASSERT_NE(status, nullptr);
    EXPECT_EQ(status->text(), MainWindow::tr(
        "An interrupted configuration import could not be recovered safely. "
        "InputLeap will not be started."));

    MainWindowEnvironmentProfileSessionTestAccess::reportServiceStopTimeout(window);
    EXPECT_FALSE(MainWindowEnvironmentProfileSessionTestAccess::serviceStopPending(window));
    EXPECT_EQ(status->text(), MainWindow::tr(
        "InputLeap stop was not confirmed; the core state is unknown."));
}
