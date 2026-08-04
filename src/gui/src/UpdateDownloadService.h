#pragma once

#include "UpdateService.h"

#include <QByteArray>
#include <QObject>
#include <QPointer>
#include <QString>

#include <functional>
#include <memory>

class QFile;
class QCryptographicHash;
class QLockFile;
class QNetworkAccessManager;
class QNetworkReply;
class QTimer;

class UpdateDownloadService final : public QObject
{
    Q_OBJECT

public:
    using WriteFunction = std::function<qint64(QFile&, const QByteArray&)>;

    explicit UpdateDownloadService(QNetworkAccessManager* network,
                                   QString stagingDirectory,
                                   QObject* parent = nullptr,
                                   WriteFunction writeFunction = {},
                                   int absoluteDeadlineMs = 30 * 60 * 1000);
    ~UpdateDownloadService() override;

    void start(const UpdateService::Release& release);
    void cancel();
    bool active() const noexcept;

Q_SIGNALS:
    void progress(qint64 received, qint64 total);
    void ready(const QString& path);
    void failed(const QString& reason);

private:
    struct PartialState {
        qint64 size = 0;
        QByteArray etag;
        QByteArray prefixSha256;
    };

    void resetActive(bool preservePartial);
    void fail(quint64 generation, const QString& reason, bool preservePartial);
    void consume(quint64 generation);
    void finish(quint64 generation);
    bool validateHeaders(quint64 generation, bool* restart);
    bool appendBytes(const QByteArray& bytes);
    bool loadPartial(PartialState* state);
    bool persistPartialMetadata();
    bool verifyFile(const QString& path, qint64 expectedSize,
                    const QByteArray& expectedSha256) const;
    void removePartial();
    QString baseName() const;

    QNetworkAccessManager* network_ = nullptr;
    QString stagingDirectory_;
    WriteFunction writeFunction_;
    QTimer* deadlineTimer_ = nullptr;
    int absoluteDeadlineMs_ = 0;
    QPointer<QNetworkReply> reply_;
    std::unique_ptr<QFile> file_;
    std::unique_ptr<QLockFile> lock_;
    std::unique_ptr<QCryptographicHash> hash_;
    UpdateService::Release release_;
    QString partPath_;
    QString metadataPath_;
    QString finalPath_;
    QByteArray etag_;
    qint64 received_ = 0;
    quint64 generation_ = 0;
    bool resume_ = false;
    bool headersValidated_ = false;
    bool restartUsed_ = false;
    bool terminal_ = true;
};
