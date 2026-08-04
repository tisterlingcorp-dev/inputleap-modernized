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

#pragma once

#include "inputleap/AppRole.h"
#include "AppConnectionState.h"
#include "DeviceConnectionModel.h"
#include "DeviceRegistry.h"
#include "CoreConnectionStateController.h"
#include "DashboardPeerStatePolicy.h"
#include "DiscoveredDevicesModel.h"
#include "DeviceDiscoveryPanel.h"
#include "TrayMenuPolicy.h"
#include "ReconnectionPolicy.h"
#include "ClipboardHistoryModel.h"
#include "EnvironmentProfileController.h"
#include "EnvironmentProfileIntegrationPolicy.h"
#include "EnvironmentProfileStore.h"
#include "UpdateService.h"
#include "NotificationService.h"

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QSettings>
#include <QProcess>
#include <QPointer>

#include <functional>
#include <optional>





#include "ServerConfig.h"
#include "AppConfig.h"
#include "FileTransferService.h"
#include "TransferQueue.h"
#include "TransferPerformance.h"
#include "IpcClient.h"
#include "Ipc.h"
#include "LogWindow.h"

#include <QMutex>
#include <memory>

class QAction;
class QMenu;
class QLineEdit;
class QGroupBox;
class QPushButton;
class QTextEdit;
class QComboBox;
class QTabWidget;
class QCheckBox;
class QRadioButton;
class QTemporaryFile;
class QMessageBox;
class QAbstractButton;
class QDialog;
class QTableWidget;
class QLabel;
class PairingWizard;
class SettingsDialog;
class ProtectionPanel;
class QProgressBar;
class QFrame;
class QTimer;
class QNetworkAccessManager;
class UpdateDownloadService;
class EnvironmentProfileSelector;
class EnvironmentProfileUiBinding;

class LogDialog;
class QInputLeapApplication;
class SetupWizard;
class ZeroconfService;
class DataDownloader;
class CommandProcess;
class SslCertificate;
class FileTransferService;
class FileTransferController;
class NetworkRecoveryCoordinator;
struct MainWindowEnvironmentProfileSessionTestAccess;
struct UpdateHelperInstruction;

namespace Ui
{
    class MainWindow;
}
class MainWindow : public QMainWindow
{
    Q_OBJECT

    friend class QInputLeapApplication;
    friend class SetupWizard;

    public:
        enum qLevel {
            Error,
            Info
        };

        enum qRuningState {
            kStarted,
            kStopped
        };

    public:
        MainWindow(QSettings& settings, AppConfig& appConfig,
                   bool enableSystemIpc = true,
                   std::function<void()> serviceStopOverride = {},
                   std::optional<quint16> fileTransferPortOverride = std::nullopt,
                   std::optional<quint16> ipcPortOverride = std::nullopt);
        ~MainWindow() override;
        quint16 controlPort() const;
        quint16 pairingPort() const;

    public:
        void setVisible(bool visible) override;
        AppRole app_role() const;
        AppConnectionState connection_state() const { return connection_state_; }
        QString hostname() const;
        QString configFilename();
        QString address();
        QString appPath(const QString& name);
        void open();
        void suppressAutomaticStartOnce() noexcept { m_SuppressAutomaticStartOnce = true; }
        bool runtimeConsumersEnabled() const noexcept
        {
            return m_RuntimeConsumersEnabled;
        }
        QString getScreenName();
        ServerConfig& serverConfig() { return m_ServerConfig; }
        void showConfigureServer(const QString& message);
        void showConfigureServer() { showConfigureServer(""); }
        void autoAddScreen(const QString name);
        void updateZeroconfService();
        void serverDetected(const QString name);
        // Receives only stable identities supplied by discovery/core IPC.
        // A null UUID restores the temporary process-wide dashboard fallback.
        void setDashboardDevice(const QUuid& uuid);
        DeviceConnectionModel::TransitionResult updateDeviceConnectionState(
            const QUuid& uuid, DeviceConnectionModel::State state,
            const QString& friendlyDetail = {}, const QString& technicalDetail = {});

    Q_SIGNALS:
        void requestLanguageChange(QString newLanguage);

public slots:
        void appendLogRaw(const QString& text);
        void appendLogInfo(const QString& text);
        void appendLogDebug(const QString& text);
        void appendLogError(const QString& text);
        void start_cmd_app();
        void setServerMode(bool isServerMode);

    protected slots:
        void on_m_pGroupClient_toggled(bool on);
        void on_m_pGroupServer_toggled(bool on);
        bool on_m_pButtonBrowseConfigFile_clicked();
        void on_m_pButtonConfigureServer_clicked();
        bool on_m_pActionSave_triggered();
        void on_m_pActionAbout_triggered();
        void on_m_pActionSettings_triggered();
        void sendFilesCrossPlatform();
        void sendDroppedFiles(const QUuid& deviceUuid, const QStringList& paths);
        void sendFolderCrossPlatform();
        void sendClipboardImageCrossPlatform();
        void sendQuickTextCrossPlatform();
        void sendTestFileCrossPlatform();
        void showTransferHistory();
        void showRecentReceivedFiles();
        void showTransferQueue();
        void showDiagnostics();
        void showClipboardHistory();
        void showReleaseNotes();
        void checkForUpdates();
        void handleUpdateCheckFinished(const UpdateService::Result& result);
        void cmd_app_finished(int exitCode, QProcess::ExitStatus);
        void trayActivated(QSystemTrayIcon::ActivationReason reason);
        void stop_cmd_app();
        void logOutput();
        void logError();
        void bonjourInstallFinished();
        void showLogWindow();

    protected:
        QSettings& settings() { return m_Settings; }
        AppConfig& appConfig() { return *m_AppConfig; }
        void initConnections();
        void createMenuBar();
        void createTrayIcon();
        void rebuildTrayMenu();
        void requestServiceStopAndDisconnect();
        void startUpdateDownload(const UpdateService::Result& result, QDialog* dialog,
                                 QPushButton* updateButton, QProgressBar* progress,
                                 QLabel* status);
        void prepareUpdateInstallation();
        void continueUpdateInstallationAfterStop();
        void updateInstallationFailed(const QString& message);
        bool authenticatedStagedUpdateResultPresent();
        bool cleanupStagedUpdateArtifacts(const QString& msiPath = QString(),
                                           bool preserveAuthenticatedResult = true,
                                           bool removeProtectedIfHelperInactive = false);
        bool engageUpdateTransferBarrier(QString* error);
        void releaseUpdateTransferBarrier();
        void cancelPendingUpdateInstallation();
        bool persistPendingUpdateResult(const UpdateHelperInstruction& instruction,
                                        QString* error);
        void consumePendingUpdateResult();
        void schedulePendingUpdateResultRetry(int retryMs);
        bool launchUpdateHelper(const UpdateHelperInstruction& instruction,
                                QString* error);
        void sendFileFromTray(const TrayMenuPolicy::Target& target);
        void loadSettings();
        void saveSettings();
        void loadTransferHistory();
        void saveTransferHistory();
        void set_icon(AppConnectionState state);
        void set_connection_state(AppConnectionState state);
        void updateProtectionFacts();
        bool environmentProfileBusy() const;
        void refreshEnvironmentProfileUi();
        bool clientArgs(QStringList& args, QString& app);
        bool serverArgs(QStringList& args, QString& app);
        void setStatus(const QString& status);
        void updateFromLogLine(const QString& line);
        void handleCoreConnectionState(IpcConnectionState state, IpcConnectionRole role,
                                       const QString& technicalName, const QString& detail,
                                       IpcIdentityPresence identityPresence);
        void handleServiceStartTimeout(quint64 generation);
        void handleServiceStopTimeout(quint64 generation);
        void handleServiceReconnectReady();
        void recordSuccessfulStart();
        void handleRuntimeInvalidation();
        void applyDashboardPeerPolicy(const QUuid& eventPeer = {});
        QString getIPAddresses();
        void stopService();
        void stopDesktop();
        void changeEvent(QEvent* event) override;
        void retranslateMenuBar();
#if defined(Q_OS_WIN)
        bool isServiceRunning(QString name);
#else
        bool isServiceRunning();
#endif
        bool isBonjourRunning();
        void downloadBonjour();
        void promptAutoConfig();
        void checkFingerprint(const QString& line);
        void restartAfterFingerprintAcceptance();
        void updateFileTransferPeerFromLogLine(const QString& line);
        void restart_cmd_app();
        void beginReconnectionIntent();
        void scheduleReconnectFailure(ReconnectionPolicy::Failure failure);
        bool performReconnectAttempt(const QString& endpoint);
        void updateReconnectCountdown();
        void proofreadInfo();
        void windowStateChanged();
        void updateSSLFingerprint();
        void polishMainView();
        void updateDashboardState(AppConnectionState state);
        void updateDashboardState(DeviceConnectionModel::State state);
        void updateDashboardFromDevice(const QUuid& uuid);
        QString fileTransferDestinationHost();
        QString normalizeFileTransferHost(const QString& host);
        QString promptFileTransferDestinationHost(const QString& title);
        void rememberFileTransferDestinationHost(const QString& host);
        bool confirmFileTransferDestinationReachable(const QString& host);
        bool deviceAllows(const QUuid& uuid, DevicePermissions::Permission permission, const QString& action);
        bool revalidateFileTransferEndpoint(const QUuid& uuid, const QString& host, quint16* transferPort);
        void openLastReceivedFilesFolder();
        void openReceiveFilesFolder();
        void showReceivedFileNotification(const QString& fileName,
                                          const QString& destinationPath,
                                          const QString& message,
                                          bool verified,
                                          const QUuid& peerUuid);
        void startFileTransfer(const QString& host,
                               const QList<FileTransferService::TransferItem>& items,
                               const QString& title,
                               const QString& successMessage,
                               const QString& failureTitle,
                               const QString& cancelledTitle,
                               const QString& historyName,
                               const QString& historyPath,
                               const QUuid& deviceUuid = {},
                               quint16 transferPort = 0,
                               const QByteArray& queueId = {},
                               quint64 queueGeneration = 0);
        QByteArray trackTransferController(FileTransferController* controller,
                                           const QByteArray& queueId);
        void addTransferHistoryEntry(const QString& direction,
                                     const QString& fileName,
                                     const QString& peer,
                                     const QString& status,
                                     const QString& path);
        void ensureTransferQueueDialog();
        void refreshTransferQueueDialog();
        void dispatchNextTransfer();
        PerformancePolicy transferPerformancePolicy() const;
        void cancelQueuedTransfer(const QByteArray& transferId, bool pause);
        void addOrUpdateTransferQueueRow(const QString& name,
                                         const QString& peer,
                                         const QString& status,
                                         const QString& progress,
                                         const QString& details,
                                         const QString& folder);

    private:
        friend struct MainWindowEnvironmentProfileSessionTestAccess;
        static constexpr int kServiceStartConfirmationTimeoutMs = 40000;
        static constexpr int kServiceStopConfirmationTimeoutMs = 40000;
        std::unique_ptr<Ui::MainWindow> ui_;
        QSettings& m_Settings;
        AppConfig* m_AppConfig;
        QProcess* cmd_app_process_;
        AppConnectionState connection_state_ = AppConnectionState::DISCONNECTED;
        DeviceRegistry m_DeviceRegistry;
        DeviceConnectionModel m_DeviceConnectionModel;
        std::unique_ptr<DiscoveredDevicesModel> m_DiscoveredDevicesModel;
        DeviceDiscoveryPanel* m_DeviceDiscoveryPanel = nullptr;
        ProtectionPanel* m_ProtectionPanel = nullptr;
        QUuid m_LocalDeviceUuid;
        struct PairedSession { QByteArray key; };
        QHash<QUuid, PairedSession> m_PairedSessions;
        QPointer<PairingWizard> m_ActivePairingWizard;
        QPointer<SettingsDialog> m_ActiveSettingsDialog;
        CoreConnectionStateController m_CoreConnectionStateController;
        DeviceConnectionModel::State m_LegacyPeerState = DeviceConnectionModel::State::Offline;
        QUuid m_DashboardDeviceUuid;
        ServerConfig m_ServerConfig;
        EnvironmentProfileStore m_EnvironmentProfileStore;
        EnvironmentProfileController m_EnvironmentProfileController;
        EnvironmentProfileSelector* m_EnvironmentProfileSelector = nullptr;
        std::unique_ptr<EnvironmentProfileUiBinding> m_EnvironmentProfileUiBinding;
        bool m_EnvironmentProfilesInitialized = false;
        bool m_RuntimeConsumersEnabled = false;
        QString m_RuntimeBlockMessage;
        EnvironmentProfileIntegrationPolicy m_EnvironmentProfileIntegrationPolicy;
        QTemporaryFile* m_pTempConfigFile;
        std::function<QTemporaryFile*()> m_TempConfigFileFactory;
        std::function<QString(const QString&)> m_AppPathResolver;
        std::function<QStringList(const QStringList&)> m_AppArgumentsOverride;
        std::function<void()> m_DesktopStopPostWaitHook;
        std::function<int()> m_FingerprintDialogExecOverride;
        std::function<bool(bool persist)> m_FingerprintTrustOverride;
        std::function<bool(const QUuid&, DevicePermissions::Permission)> m_DeviceAllowsOverride;
        QSystemTrayIcon* m_pTrayIcon;
        QMenu* m_pTrayIconMenu;
        bool m_AlreadyHidden;
        IpcClient m_IpcClient;
        bool m_SystemIpcEnabled = true;
        std::function<void()> m_ServiceStopOverride;
        std::function<void()> m_ServiceReconnectOverride;
        QMenuBar* m_pMenuBar;
        QMenu* main_menu_;
        QMenu* m_pMenuHelp;
        QAction* m_pActionSendFiles;
        QAction* m_pActionSendFolder;
        QAction* m_pActionSendClipboardImage;
        QAction* m_pActionSendQuickText;
        QAction* m_pActionSendTestFile;
        QAction* m_pActionTransferHistory;
        QAction* m_pActionRecentReceivedFiles;
        QAction* m_pActionTransferQueue;
        QAction* m_pActionOpenReceiveFolder;
        QAction* m_pActionDiagnostics;
        QAction* m_pActionClipboardHistory;
        QAction* m_pActionReleaseNotes;
        QAction* m_pActionCheckUpdates;
        std::unique_ptr<UpdateReplayStore> m_UpdateReplayStore;
        std::unique_ptr<NotificationService> m_NotificationService;
        QNetworkAccessManager* m_pUpdateNetwork;
        UpdateService* m_pUpdateService;
        std::unique_ptr<UpdateDownloadService> m_UpdateDownloadService;
        QString m_UpdateStagingDirectory;
        std::optional<UpdateService::Release> m_PendingUpdateRelease;
        QByteArray m_PendingUpdateEnvelope;
        QString m_StagedUpdatePath;
        QPointer<QDialog> m_UpdateDialog;
        QPointer<QPushButton> m_UpdateButton;
        QPointer<QProgressBar> m_UpdateProgress;
        QPointer<QLabel> m_UpdateStatus;
        QTimer* m_UpdateResultRetryTimer = nullptr;
        bool m_UpdateResultPendingNoticeLogged = false;
        bool m_UpdateInstallAwaitingStop = false;
        bool m_DesktopStopConfirmed = false;
        bool m_UpdateTransferBarrierActive = false;
        bool m_UpdateCoreWasRunning = false;
        bool m_UpdateStopRequested = false;
        bool m_UpdateCoreStoppedForInstall = false;
        bool m_UpdateCancellationRequested = false;
        quint16 m_UpdateTransferListenPort = 0;
        void* m_UpdateInstallMutex = nullptr;
        std::function<bool(const UpdateHelperInstruction&, QString*)>
            m_UpdateHelperLaunchOverride;
        std::function<bool(const QString&)> m_UpdateArtifactRemoveOverride;
        std::function<bool(qint64, const QString&)> m_UpdateProcessIdentityOverride;
        std::function<void()> m_UpdateExitOverride;
        std::function<QDateTime()> m_UpdateNowUtcOverride;
        ZeroconfService* m_pZeroconfService;
        DataDownloader* m_pDataDownloader;
        QMessageBox* m_DownloadMessageBox;
        QAbstractButton* m_pCancelButton;
        QMutex m_UpdateZeroconfMutex;
        bool m_SuppressAutoConfigWarning;
        CommandProcess* m_BonjourInstall;
        bool m_SuppressEmptyServerWarning;
        bool m_SuppressAutomaticStartOnce = false;
        qRuningState m_ExpectedRunningState;
        QMutex m_StopDesktopMutex;
        SslCertificate* m_pSslCertificate;
        FileTransferService* m_pFileTransferService;
        QString m_LastConnectedClientHost;
        QStringList m_FileTransferDestinationHosts;
        QString m_LastReceivedFilesFolder;
        bool m_ReceivedFileNotificationOpenable = false;
        QHash<QByteArray, FileTransferService::PublicationOutcome> m_PendingPublicationOutcomes;
        QList<QStringList> m_TransferHistory;
        std::unique_ptr<TransferQueue> m_TransferQueue;
        std::unique_ptr<ClipboardHistoryModel> m_ClipboardHistoryModel;
        enum class TransferCancelIntent { None, Pause, Cancel, Shutdown };
        QHash<QByteArray, QPointer<FileTransferController>> m_TransferControllers;
        QHash<QByteArray, TransferCancelIntent> m_TransferCancelIntents;
        bool m_TransferQueueShuttingDown = false;
        bool m_FileTransferReceiveBusy = false;

        QDialog* m_pTransferQueueDialog = nullptr;
        QTableWidget* m_pTransferQueueTable = nullptr;
        QLabel* m_pDashboardState = nullptr;
        QLabel* m_pDashboardDetail = nullptr;
        QLabel* m_pSecurityBadge = nullptr;
        QLabel* m_pDashboardRemote = nullptr;
        QLabel* m_pDashboardTransfer = nullptr;
        QProgressBar* m_pDashboardTransferProgress = nullptr;
        QPushButton* m_pServerModeButton = nullptr;
        QPushButton* m_pClientModeButton = nullptr;
        QList<QFrame*> m_DashboardRemoteCards;
        QStringList m_PendingClientNames;
        std::unique_ptr<ReconnectionPolicy> m_ReconnectionPolicy;
        std::unique_ptr<NetworkRecoveryCoordinator> m_NetworkRecoveryCoordinator;
        QTimer* m_ReconnectTimer = nullptr;
        QTimer* m_ReconnectCountdownTimer = nullptr;
        QTimer* m_ReconnectStableTimer = nullptr;
        QUuid m_ReconnectTargetUuid;
        QString m_ReconnectEndpointOverride;
        qint64 m_ReconnectDeadlineMs = 0;
        quint64 m_ReconnectTimerGeneration = 0;
        bool m_InternalReconnect = false;
        bool m_LastStartSucceeded = false;
        bool m_ServiceStartPending = false;
        bool m_ServiceStartCommandApplied = false;
        bool m_ServiceStopPending = false;
        bool m_ServiceStopUnconfirmed = false;
        bool m_ServiceRestartPending = false;
        bool m_ServiceRestartAwaitingReconnect = false;
        quint64 m_ServiceStartGeneration = 0;
        quint64 m_ServiceStopGeneration = 0;
        LogWindow *m_pLogWindow;

        bool m_fingerprint_expanded = false;

private slots:
    void on_m_pCheckBoxAutoConfig_toggled(bool checked);
    void comboServerList_currentIndexChanged(QString );
    void on_m_pButtonReload_clicked();
    void installBonjour();

};
