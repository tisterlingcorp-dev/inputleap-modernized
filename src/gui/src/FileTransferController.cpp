/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "FileTransferController.h"

#include "FileTransferWorker.h"

#include <QThread>

FileTransferController::FileTransferController(QObject* parent) :
    QObject(parent)
{
}

FileTransferController::~FileTransferController()
{
    cancelAndWait();
}

bool FileTransferController::start(const QString& host,
                                   quint16 port,
                                   const QList<FileTransferService::TransferItem>& items,
                                   const QString& pairingCode,
                                   const QUuid& localUuid,
                                   const QByteArray& preSharedKey,
                                   bool resumeEnabled,
                                   quint64 bandwidthBytesPerSecond,
                                   bool conflictProtocolEnabled)
{
    if (running_ || thread_ != nullptr) {
        return false;
    }

    auto* thread = new QThread();
    cancellation_ = FileTransferCancellation();
    auto* worker = new FileTransferWorker(host, port, items, pairingCode,localUuid,preSharedKey,resumeEnabled,bandwidthBytesPerSecond,conflictProtocolEnabled,cancellation_);
    thread_ = thread;
    running_ = true;

    worker->moveToThread(thread);
    connect(thread, &QThread::started, worker, &FileTransferWorker::run);
    connect(worker, &FileTransferWorker::progress, this, &FileTransferController::progress);
    connect(worker, &FileTransferWorker::finished, worker, &QObject::deleteLater);
    connect(worker, &FileTransferWorker::finished, this,
            [this,thread](bool success,const QString& errorMessage,bool cancelled,bool terminalFailure,
                         quint32 transferred,quint32 deduplicated,quint32 skipped) {
        running_ = false;
        emit finished(success,errorMessage,cancelled,terminalFailure,transferred,deduplicated,skipped);
        thread->quit();
    });
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    connect(thread, &QThread::finished, this, [this, thread]() {
        if (thread_ == thread) {
            thread_ = nullptr;
        }
    });

    emit started();
    thread->start();
    return true;
}

void FileTransferController::cancel()
{
    emit cancelRequested();
    cancellation_.cancel();
}

void FileTransferController::cancelAndWait()
{
    QThread* thread = thread_.data();
    cancellation_.cancel();
    if (thread != nullptr) {
        disconnect(thread, nullptr, this, nullptr);
        thread->quit();
        thread->wait();
    }
    thread_ = nullptr;
    running_ = false;
}
