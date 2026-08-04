/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#pragma once

#include "FileTransferCancellation.h"
#include "FileTransferService.h"

#include <QObject>
#include <QPointer>

class QThread;

class FileTransferController : public QObject
{
    Q_OBJECT

public:
    explicit FileTransferController(QObject* parent = nullptr);
    ~FileTransferController() override;

    bool start(const QString& host,
               quint16 port,
               const QList<FileTransferService::TransferItem>& items,
               const QString& pairingCode,
               const QUuid& localUuid = {},
               const QByteArray& preSharedKey = {},
               bool resumeEnabled = false,
               quint64 bandwidthBytesPerSecond = 0,
               bool conflictProtocolEnabled = false);
    bool isRunning() const { return running_; }

public slots:
    void cancel();
    void cancelAndWait();

signals:
    void started();
    void cancelRequested();
    void progress(const QString& fileName, quint64 bytesDone, quint64 bytesTotal);
    void finished(bool success, const QString& errorMessage, bool cancelled, bool terminalFailure,
                  quint32 transferred, quint32 deduplicated, quint32 skipped);

private:
    bool running_ = false;
    QPointer<QThread> thread_;
    FileTransferCancellation cancellation_;
};