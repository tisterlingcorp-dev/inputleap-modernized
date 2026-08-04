/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#pragma once

#include "ConflictResolutionPolicy.h"
#include "ProtocolSecurityPolicy.h"
#include <QDateTime>

#include <QByteArray>
#include <QObject>
#include <QStringList>
#include <QSet>
#include <QUuid>

#include <functional>
#include <utility>

class QTcpServer;
class QTcpSocket;

class FileTransferService : public QObject
{
    Q_OBJECT

public:
    enum class SendFailure { None, Transient, Terminal };
    enum class PublicationStatus {
        Unchanged,
        Committed,
        CommittedWithRecovery,
        RecoveryRequired,
        ReviewRequired
    };
    Q_ENUM(PublicationStatus)
    struct PublicationOutcome {
        PublicationStatus status=PublicationStatus::Unchanged;
        QString destinationPath;
        QString recoveryPath;
        QUuid peerUuid;
        QByteArray transferId;
        bool operator==(const PublicationOutcome&) const = default;
    };
    struct TransferSummary { quint32 transferred=0; quint32 deduplicated=0; quint32 skipped=0; };
    struct TransferItem
    {
        QString sourcePath;
        QString relativePath;
        QByteArray transferId;
        QByteArray batchId;
        quint32 batchIndex=0;
        quint32 batchCount=1;
    };

    explicit FileTransferService(QObject* parent = nullptr);
    ~FileTransferService() override;

    bool startListening(quint16 port, QString* errorMessage = nullptr);
    void stopListening();
    quint16 port() const { return port_; }
    QString receiveDirectory() const;
    void setReceiveDirectory(const QString& directory);
    void setPairingCode(const QString& pairingCode);
    void setDevicePreSharedKey(const QUuid& peerUuid, const QByteArray& key);
    void removeDevicePreSharedKey(const QUuid& peerUuid);
    void clearPreSharedKeys();
    bool legacyPairingEnabled() const;

    using ProgressCallback = std::function<void(const QString& fileName, quint64 bytesDone, quint64 bytesTotal)>;
    using CancelCallback = std::function<bool()>;
    using IncomingFileCallback = std::function<bool(const QString& fileName, quint64 bytesTotal, const QString& peerAddress, const QUuid& peerUuid)>;
    // Protocol-side authorization.  This runs after the peer identity has been
    // authenticated and immediately before any destination/payload side effect.
    using PermissionCallback = std::function<bool(const QUuid& peerUuid)>;
    using ConflictCallback = ConflictResolutionPolicy::Callback;

    void setIncomingFileCallback(IncomingFileCallback callback);
    void setReceivePermissionCallback(PermissionCallback callback);
    void setConflictCallback(ConflictCallback callback);
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    enum class AtomicPublishPhase {
        DirectoryComponentPinned,
        BeforePartialOpen,
        PartialParentPinned,
        BeforePublicationChain,
        AncestorsPinned,
        SourcePinned,
        ExistingMoved,
        Committed,
        BeforeCleanup
    };
    enum class AtomicPublishOperation {
        PublishSource,
        RollbackOriginal,
        CleanupOriginal
    };
    struct AtomicPublishTestHooks {
        std::function<void(AtomicPublishPhase, const QString&)> phase;
        std::function<bool(AtomicPublishOperation)> failOperation;
        std::function<bool(bool completed, bool hasRecovery)> failManifestWrite;
        std::function<bool()> failManifestPromotion;
    };
    static bool secureDirectoryForTests(const QString& directory);
    static bool atomicPublishForTests(const QString& source, const QString& destination,
                                      bool replace,
                                      const AtomicPublishTestHooks& hooks = {},
                                      QString* recoveryPath = nullptr);
    void setAtomicPublishTestHooks(AtomicPublishTestHooks hooks)
    { atomic_publish_test_hooks_=std::move(hooks); }
#endif
    static bool isSafeToOpenAutomatically(const QString& fileName);
    static QByteArray pairingKeyForCode(const QString& pairingCode);
    static QStringList tlsPskCipherNames();

    static bool sendFiles(const QString& host,
                          quint16 port,
                          const QStringList& files,
                          QString* errorMessage = nullptr,
                          ProgressCallback progressCallback = {},
                          CancelCallback cancelCallback = {},
                          const QString& pairingCode = {},
                          const QUuid& localUuid = {},
                          const QByteArray& preSharedKey = {},
                          bool resumeEnabled = false,
                          SendFailure* failureKind = nullptr,
                          quint64 bandwidthBytesPerSecond = 0,
                          bool conflictProtocolEnabled = false,
                          TransferSummary* summary = nullptr);
    static bool sendItems(const QString& host,
                          quint16 port,
                          const QList<TransferItem>& items,
                          QString* errorMessage = nullptr,
                          ProgressCallback progressCallback = {},
                          CancelCallback cancelCallback = {},
                          const QString& pairingCode = {},
                          const QUuid& localUuid = {},
                          const QByteArray& preSharedKey = {},
                          bool resumeEnabled = false,
                          SendFailure* failureKind = nullptr,
                          quint64 bandwidthBytesPerSecond = 0,
                          bool conflictProtocolEnabled = false,
                          TransferSummary* summary = nullptr);

Q_SIGNALS:
    void info(const QString& message);
    void error(const QString& message);
    void receivingStarted(const QString& fileName, quint64 bytesTotal);
    void receivingProgress(const QString& fileName, quint64 bytesDone, quint64 bytesTotal);
    // The UUID is taken from the authenticated TLS peer, never from discovery/UI state.
    void fileReceived(const QString& fileName, const QString& destinationPath, bool verified,
                      const QUuid& peerUuid, const QByteArray& transferId = {});
    void fileRejected(const QString& fileName, const QString& peerAddress,
                      const QByteArray& transferId = {});
    void publicationCompleted(const QString& fileName, const FileTransferService::PublicationOutcome& outcome);

private:
    void acceptConnection();
    void readIncoming(QTcpSocket* socket);
    QString uniqueDestinationPath(const QString& fileName) const;

    QTcpServer* server_;
    quint16 port_ = 0;
    QString receive_directory_;
    IncomingFileCallback incoming_file_callback_;
    PermissionCallback receive_permission_callback_;
    ConflictCallback conflict_callback_;
    ConflictResolutionPolicy conflict_policy_;
#ifdef INPUTLEAP_FILE_TRANSFER_TEST_HOOKS
    AtomicPublishTestHooks atomic_publish_test_hooks_;
#endif
    QSet<QByteArray> active_resume_ids_;
    ProtocolSecurityPolicy security_policy_{[] { return QDateTime::currentMSecsSinceEpoch(); }};
};

Q_DECLARE_METATYPE(FileTransferService::PublicationOutcome)
