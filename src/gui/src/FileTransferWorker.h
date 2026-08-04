/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#pragma once
#include "FileTransferCancellation.h"
#include "FileTransferService.h"

#include <QObject>

class FileTransferWorker : public QObject
{
    Q_OBJECT

public:
    FileTransferWorker(QString host, quint16 port, QList<FileTransferService::TransferItem> items, QString pairingCode,
                       QUuid localUuid = {}, QByteArray preSharedKey = {}, bool resumeEnabled = false,
                       quint64 bandwidthBytesPerSecond = 0, bool conflictProtocolEnabled = false,
                       FileTransferCancellation cancellation = {});
    ~FileTransferWorker() override;

public slots:
    void run();
    void cancel();

signals:
    void progress(const QString& fileName, quint64 bytesDone, quint64 bytesTotal);
    void finished(bool success, const QString& errorMessage, bool cancelled, bool terminalFailure,
                  quint32 transferred, quint32 deduplicated, quint32 skipped);

private:
    bool waitForRetryDelay(int milliseconds);
    void cleanseSecrets();

    QString host_;
    quint16 port_;
    QList<FileTransferService::TransferItem> items_;
    QString pairing_code_;
    QUuid local_uuid_;
    QByteArray pre_shared_key_;
    bool resume_enabled_=false;
    bool conflict_protocol_enabled_=false;
    quint64 bandwidth_bytes_per_second_=0;
    FileTransferCancellation cancellation_;
};
