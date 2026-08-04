#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QUuid>
#include <optional>

namespace FileTransferResume {
constexpr qsizetype MaxManifestBytes=64*1024;
constexpr quint64 MaxFileBytes=quint64(1)<<40; // 1 TiB policy bound
constexpr int MaxRelativePathUtf8=4096;
constexpr qint64 RetentionSeconds=24*60*60;

struct Manifest {
    QByteArray transferId;
    QUuid peerUuid;
    quint32 itemIndex=0;
    QString relativePath;
    quint64 expectedSize=0;
    QByteArray sha256;
    quint64 offset=0;
    QByteArray prefixSha256;
    QDateTime updatedAtUtc;
    QString publishedPath;
    QString recoveryPath;
    bool completed=false;
};

bool isSafeRelativePath(const QString& path);
bool constantTimeEqual(const QByteArray& a,const QByteArray& b);
QByteArray deriveContextKey(const QByteArray& sessionKey,const QByteArray& context);
QByteArray scopedStorageId(const QUuid& authenticatedPeer,const QByteArray& transferId);
QByteArray encodeManifest(const Manifest& manifest,const QByteArray& contextKey,QString* error=nullptr);
std::optional<Manifest> decodeManifest(const QByteArray& data,const QByteArray& contextKey,const QUuid& authenticatedPeer,QString* error=nullptr);
QString partPath(const QString& receiveRoot,const QByteArray& transferId);
QString manifestPath(const QString& receiveRoot,const QByteArray& transferId);
quint64 verifiedOffset(const Manifest& manifest,const QString& partFile,QString* error=nullptr);
bool saveManifestAtomic(const QString& path,const QByteArray& encoded,QString* error=nullptr);
}
