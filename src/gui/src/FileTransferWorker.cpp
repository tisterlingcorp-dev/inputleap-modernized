/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "FileTransferWorker.h"
#include <QThread>
#include <QUuid>
#include <openssl/crypto.h>

FileTransferWorker::FileTransferWorker(QString host, quint16 port, QList<FileTransferService::TransferItem> items, QString pairingCode,QUuid localUuid,QByteArray preSharedKey,bool resumeEnabled,quint64 bandwidthBytesPerSecond,bool conflictProtocolEnabled,FileTransferCancellation cancellation) :
    host_(std::move(host)),
    port_(port),
    items_(std::move(items)),
    pairing_code_(std::move(pairingCode)),local_uuid_(localUuid),pre_shared_key_(std::move(preSharedKey)),resume_enabled_(resumeEnabled),conflict_protocol_enabled_(conflictProtocolEnabled),bandwidth_bytes_per_second_(bandwidthBytesPerSecond),cancellation_(std::move(cancellation))
{
    pre_shared_key_.detach();
}

FileTransferWorker::~FileTransferWorker()
{
    cleanseSecrets();
}

bool FileTransferWorker::waitForRetryDelay(int milliseconds)
{
    constexpr int SliceMs = 25;
    for (int elapsed = 0; elapsed < milliseconds;) {
        if (cancellation_.isCancelled()) return false;
        const int duration = qMin(SliceMs, milliseconds - elapsed);
        QThread::msleep(static_cast<unsigned long>(duration));
        elapsed += duration;
    }
    return !cancellation_.isCancelled();
}

void FileTransferWorker::cleanseSecrets()
{
    pairing_code_.detach();
    if (!pairing_code_.isEmpty()) {
        OPENSSL_cleanse(pairing_code_.data(),
                        size_t(pairing_code_.size() * sizeof(QChar)));
        pairing_code_.clear();
    }
    pre_shared_key_.detach();
    if (!pre_shared_key_.isEmpty()) {
        OPENSSL_cleanse(pre_shared_key_.data(), size_t(pre_shared_key_.size()));
        pre_shared_key_.clear();
    }
}

void FileTransferWorker::run()
{
    QString errorMessage;
    bool success = false;
    FileTransferService::TransferSummary summary;
    FileTransferService::SendFailure lastFailure=FileTransferService::SendFailure::Terminal;
    for (auto& item : items_) {
        if (resume_enabled_ && item.transferId.isEmpty()) item.transferId = QUuid::createUuid().toRfc4122();
    }
    const int attempts = resume_enabled_ ? 3 : 1;
    for (int attempt = 0; attempt < attempts && !cancellation_.isCancelled(); ++attempt) {
        if (attempt > 0 && !waitForRetryDelay(500 * (1 << (attempt - 1)))) break;
        FileTransferService::SendFailure failure = FileTransferService::SendFailure::Terminal;
        success = FileTransferService::sendItems(host_, port_, items_, &errorMessage,
            [this](const QString& fileName,quint64 done,quint64 total){emit progress(fileName,done,total);},
            [this]{return cancellation_.isCancelled();},pairing_code_,local_uuid_,pre_shared_key_,resume_enabled_,&failure,
            bandwidth_bytes_per_second_,conflict_protocol_enabled_,&summary);
        lastFailure=failure;
        if (success || failure != FileTransferService::SendFailure::Transient) break;
    }

    cleanseSecrets();

    emit finished(success,errorMessage,cancellation_.isCancelled(),
        !success&&!cancellation_.isCancelled()&&lastFailure==FileTransferService::SendFailure::Terminal,
        summary.transferred,summary.deduplicated,summary.skipped);
}

void FileTransferWorker::cancel()
{
    cancellation_.cancel();
}
