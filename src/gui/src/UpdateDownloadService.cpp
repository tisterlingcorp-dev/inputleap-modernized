#include "UpdateDownloadService.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QTimer>

#include <algorithm>
#include <limits>
#include <utility>

#if defined(Q_OS_WIN)
#define NOMINMAX
#include <Windows.h>
#endif

namespace {
constexpr qint64 kChunkBytes = 64 * 1024;
constexpr qsizetype kMaxMetadataBytes = 4096;
constexpr int kMetadataSchema = 1;
constexpr int kTransferStallTimeoutMs = 30 * 1000;
constexpr int kDownloadStaleLockTimeMs = 15 * 60 * 1000;

bool isStrongEtag(const QByteArray& value)
{
    if (value.size() < 2 || value.size() > 256 || value.startsWith("W/") ||
        value.front() != '"' || value.back() != '"') {
        return false;
    }
    for (qsizetype i = 1; i + 1 < value.size(); ++i) {
        const uchar character = uchar(value.at(i));
        if (character == '"' || character < 0x21 || character == 0x7f)
            return false;
    }
    return true;
}

bool isDecimal(const QByteArray& value)
{
    if (value.isEmpty() || value.size() > 20)
        return false;
    return std::all_of(value.cbegin(), value.cend(),
                       [](char value) { return value >= '0' && value <= '9'; });
}

QByteArray streamSha256(QFile& file)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(kChunkBytes);
        if (chunk.isEmpty() && !file.atEnd())
            return {};
        hash.addData(chunk);
    }
    return hash.result();
}

bool pathContainsReparsePoint(const QString& path)
{
#if defined(Q_OS_WIN)
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
#else
    Q_UNUSED(path);
#endif
    return false;
}
}

UpdateDownloadService::UpdateDownloadService(QNetworkAccessManager* network,
                                             QString stagingDirectory,
                                             QObject* parent,
                                             WriteFunction writeFunction,
                                             int absoluteDeadlineMs)
    : QObject(parent),
      network_(network),
      stagingDirectory_(std::move(stagingDirectory)),
      writeFunction_(std::move(writeFunction)),
      deadlineTimer_(new QTimer(this)),
      absoluteDeadlineMs_(absoluteDeadlineMs > 0 ? absoluteDeadlineMs
                                                 : 30 * 60 * 1000)
{
    deadlineTimer_->setSingleShot(true);
    connect(deadlineTimer_, &QTimer::timeout, this, [this] {
        if (!terminal_)
            fail(generation_, QStringLiteral("download absolute deadline exceeded"), true);
    });
    if (!writeFunction_) {
        writeFunction_ = [](QFile& file, const QByteArray& bytes) {
            return file.write(bytes);
        };
    }
}

UpdateDownloadService::~UpdateDownloadService()
{
    resetActive(true);
}

bool UpdateDownloadService::active() const noexcept
{
    return reply_ != nullptr;
}

QString UpdateDownloadService::baseName() const
{
    return QStringLiteral("update-%1-%2")
        .arg(release_.version, QString::fromLatin1(release_.sha256.toHex().left(16)));
}

void UpdateDownloadService::removePartial()
{
    if (!partPath_.isEmpty())
        QFile::remove(partPath_);
    if (!metadataPath_.isEmpty())
        QFile::remove(metadataPath_);
}

bool UpdateDownloadService::verifyFile(const QString& path, qint64 expectedSize,
                                       const QByteArray& expectedSha256) const
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() != expectedSize)
        return false;
    return streamSha256(file) == expectedSha256;
}

bool UpdateDownloadService::loadPartial(PartialState* state)
{
    QFile metadata(metadataPath_);
    if (!metadata.open(QIODevice::ReadOnly) || metadata.size() < 1 ||
        metadata.size() > kMaxMetadataBytes) {
        return false;
    }
    const QByteArray encoded = metadata.readAll();
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(encoded, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
        document.toJson(QJsonDocument::Compact) != encoded) {
        return false;
    }
    const QJsonObject object = document.object();
    if (object.size() != 9 || object.value(QStringLiteral("schema")).toInt(-1) != kMetadataSchema ||
        object.value(QStringLiteral("packageType")).toString() != QStringLiteral("windows-msi") ||
        object.value(QStringLiteral("url")).toString() != release_.packageUrl.toString(QUrl::FullyEncoded) ||
        object.value(QStringLiteral("version")).toString() != release_.version ||
        object.value(QStringLiteral("size")).toVariant().toULongLong() != release_.size ||
        object.value(QStringLiteral("sha256")).toString().toLatin1() != release_.sha256.toHex()) {
        return false;
    }

    bool sizeOk = false;
    const qint64 prefixSize = object.value(QStringLiteral("prefixSize")).toVariant().toLongLong(&sizeOk);
    const QByteArray prefixSha256 = QByteArray::fromHex(
        object.value(QStringLiteral("prefixSha256")).toString().toLatin1());
    const QByteArray etag = object.value(QStringLiteral("etag")).toString().toUtf8();
    if (!sizeOk || prefixSize <= 0 || quint64(prefixSize) > release_.size ||
        prefixSha256.size() != QCryptographicHash::hashLength(QCryptographicHash::Sha256) ||
        !isStrongEtag(etag)) {
        return false;
    }

    QFile partial(partPath_);
    if (!partial.open(QIODevice::ReadOnly) || partial.size() != prefixSize ||
        streamSha256(partial) != prefixSha256) {
        return false;
    }
    state->size = prefixSize;
    state->etag = etag;
    state->prefixSha256 = prefixSha256;
    return true;
}

bool UpdateDownloadService::persistPartialMetadata()
{
    if (received_ <= 0 || !hash_ || !isStrongEtag(etag_))
        return false;
    const QJsonObject object{
        {QStringLiteral("etag"), QString::fromUtf8(etag_)},
        {QStringLiteral("packageType"), QStringLiteral("windows-msi")},
        {QStringLiteral("prefixSha256"), QString::fromLatin1(hash_->result().toHex())},
        {QStringLiteral("prefixSize"), received_},
        {QStringLiteral("schema"), kMetadataSchema},
        {QStringLiteral("sha256"), QString::fromLatin1(release_.sha256.toHex())},
        {QStringLiteral("size"), qint64(release_.size)},
        {QStringLiteral("url"), release_.packageUrl.toString(QUrl::FullyEncoded)},
        {QStringLiteral("version"), release_.version},
    };
    const QByteArray encoded = QJsonDocument(object).toJson(QJsonDocument::Compact);
    if (pathContainsReparsePoint(stagingDirectory_) ||
        pathContainsReparsePoint(metadataPath_))
        return false;
    QSaveFile metadata(metadataPath_);
    if (!metadata.open(QIODevice::WriteOnly) || metadata.write(encoded) != encoded.size()) {
        metadata.cancelWriting();
        return false;
    }
    return metadata.commit();
}

void UpdateDownloadService::resetActive(bool preservePartial)
{
    deadlineTimer_->stop();
    if (reply_) {
        QObject::disconnect(reply_, nullptr, this, nullptr);
        reply_->abort();
        reply_->deleteLater();
        reply_.clear();
    }
    if (file_) {
        file_->flush();
        if (preservePartial && received_ > 0)
            persistPartialMetadata();
        file_->close();
    }
    if (!preservePartial)
        removePartial();
    file_.reset();
    hash_.reset();
    lock_.reset();
    headersValidated_ = false;
    resume_ = false;
    received_ = 0;
    etag_.clear();
    terminal_ = true;
}

void UpdateDownloadService::start(const UpdateService::Release& release)
{
    if (!terminal_)
        resetActive(true);
    ++generation_;
    terminal_ = true;
    release_ = release;
    restartUsed_ = false;

    const QUrl& url = release.packageUrl;
    if (!network_ || !release.installable ||
        release.packageType != UpdateService::PackageType::WindowsMsi ||
        release.size == 0 || release.size > UpdateService::MaxPackageBytes ||
        release.sha256.size() != QCryptographicHash::hashLength(QCryptographicHash::Sha256) ||
        !url.isValid() || url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0 ||
        url.host().isEmpty() || !url.userInfo().isEmpty() || !url.fragment().isEmpty() ||
        !url.path().endsWith(QStringLiteral(".msi"), Qt::CaseInsensitive)) {
        Q_EMIT failed(QStringLiteral("release is not an authenticated HTTPS Windows MSI"));
        return;
    }
    if (!QDir().mkpath(stagingDirectory_) || !QDir(stagingDirectory_).exists() ||
        QFileInfo(stagingDirectory_).isSymLink() ||
        pathContainsReparsePoint(stagingDirectory_)) {
        Q_EMIT failed(QStringLiteral("staging directory is unavailable"));
        return;
    }

    partPath_ = QDir(stagingDirectory_).filePath(baseName() + QStringLiteral(".part"));
    metadataPath_ = partPath_ + QStringLiteral(".json");
    finalPath_ = QDir(stagingDirectory_).filePath(baseName() + QStringLiteral(".msi"));
    lock_ = std::make_unique<QLockFile>(partPath_ + QStringLiteral(".lock"));
    lock_->setStaleLockTime(kDownloadStaleLockTimeMs);
    if (!lock_->tryLock(0)) {
        lock_.reset();
        Q_EMIT failed(QStringLiteral("download is already active"));
        return;
    }

    if (QFile::exists(finalPath_)) {
        if (verifyFile(finalPath_, qint64(release_.size), release_.sha256)) {
            lock_.reset();
            Q_EMIT ready(finalPath_);
            return;
        }
        QFile::remove(finalPath_);
    }

    PartialState partial;
    if (QFile::exists(partPath_) || QFile::exists(metadataPath_)) {
        if (!loadPartial(&partial))
            removePartial();
    }
    if (quint64(partial.size) == release_.size) {
        if (partial.prefixSha256 == release_.sha256 &&
            !pathContainsReparsePoint(stagingDirectory_) &&
            !pathContainsReparsePoint(partPath_) &&
            !pathContainsReparsePoint(finalPath_) &&
            QFile::rename(partPath_, finalPath_) &&
            verifyFile(finalPath_, qint64(release_.size), release_.sha256)) {
            QFile::remove(metadataPath_);
            lock_.reset();
            Q_EMIT ready(finalPath_);
            return;
        }
        QFile::remove(finalPath_);
        removePartial();
        partial = {};
    }
    resume_ = partial.size > 0;
    received_ = partial.size;
    etag_ = partial.etag;
    hash_ = std::make_unique<QCryptographicHash>(QCryptographicHash::Sha256);
    file_ = std::make_unique<QFile>(partPath_);
    if (!file_->open(QIODevice::ReadWrite) || !file_->seek(received_)) {
        terminal_ = false;
        fail(generation_, QStringLiteral("staging file is not writable"), false);
        return;
    }
    if (resume_) {
        QFile existing(partPath_);
        if (!existing.open(QIODevice::ReadOnly)) {
            terminal_ = false;
            fail(generation_, QStringLiteral("staged prefix cannot be reopened"), false);
            return;
        }
        while (!existing.atEnd()) {
            const QByteArray chunk = existing.read(kChunkBytes);
            if (chunk.isEmpty() && !existing.atEnd()) {
                terminal_ = false;
                fail(generation_, QStringLiteral("staged prefix cannot be read"), false);
                return;
            }
            hash_->addData(chunk);
        }
    }

    QNetworkRequest request(url);
    request.setTransferTimeout(kTransferStallTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setRawHeader("Accept", "application/x-msi, application/octet-stream");
    if (resume_) {
        request.setRawHeader("Range", QByteArrayLiteral("bytes=") +
                                      QByteArray::number(received_) + QByteArrayLiteral("-"));
        request.setRawHeader("If-Range", etag_);
    }

    headersValidated_ = false;
    terminal_ = false;
    const quint64 requestGeneration = generation_;
    reply_ = network_->get(request);
    if (!reply_) {
        fail(requestGeneration, QStringLiteral("download request could not be created"), true);
        return;
    }
    connect(reply_, &QNetworkReply::metaDataChanged, this,
            [this, requestGeneration] { consume(requestGeneration); });
    connect(reply_, &QNetworkReply::readyRead, this,
            [this, requestGeneration] { consume(requestGeneration); });
    connect(reply_, &QNetworkReply::finished, this,
            [this, requestGeneration] { finish(requestGeneration); });
    deadlineTimer_->start(absoluteDeadlineMs_);
}

bool UpdateDownloadService::validateHeaders(quint64 generation, bool* restart)
{
    if (generation != generation_ || !reply_ || terminal_)
        return false;
    *restart = false;
    if (reply_->attribute(QNetworkRequest::RedirectionTargetAttribute).isValid() ||
        reply_->url() != release_.packageUrl) {
        return false;
    }
    const int status = reply_->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString mime = reply_->header(QNetworkRequest::ContentTypeHeader)
                             .toString().section(QLatin1Char(';'), 0, 0).trimmed().toLower();
    if (mime != QStringLiteral("application/x-msi") &&
        mime != QStringLiteral("application/octet-stream")) {
        return false;
    }
    const QByteArray encodedLength = reply_->rawHeader("Content-Length").trimmed();
    if (!isDecimal(encodedLength))
        return false;
    bool lengthOk = false;
    const qulonglong contentLength = encodedLength.toULongLong(&lengthOk);
    if (!lengthOk || contentLength > UpdateService::MaxPackageBytes)
        return false;

    if (resume_ && status == 200 && !restartUsed_) {
        if (contentLength != release_.size)
            return false;
        restartUsed_ = true;
        *restart = true;
    }
    else {
        if ((!resume_ && status != 200) || (resume_ && status != 206) ||
            contentLength != release_.size - quint64(received_)) {
            return false;
        }
    }

    if (!*restart && resume_) {
        const QByteArray expected = QByteArrayLiteral("bytes ") + QByteArray::number(received_) +
                                    QByteArrayLiteral("-") + QByteArray::number(release_.size - 1) +
                                    QByteArrayLiteral("/") + QByteArray::number(release_.size);
        if (reply_->rawHeader("Content-Range") != expected)
            return false;
    }
    const QByteArray responseEtag = reply_->rawHeader("ETag");
    if (!isStrongEtag(responseEtag) || (resume_ && !*restart && responseEtag != etag_))
        return false;
    etag_ = responseEtag;
    return true;
}

bool UpdateDownloadService::appendBytes(const QByteArray& bytes)
{
    if (bytes.isEmpty() || !file_ || !hash_ ||
        quint64(bytes.size()) > release_.size - quint64(received_)) {
        return false;
    }
    if (writeFunction_(*file_, bytes) != bytes.size())
        return false;
    hash_->addData(bytes);
    received_ += bytes.size();
    if (!file_->flush() || !persistPartialMetadata())
        return false;
    Q_EMIT progress(received_, qint64(release_.size));
    return true;
}

void UpdateDownloadService::consume(quint64 generation)
{
    if (generation != generation_ || !reply_ || terminal_)
        return;
    if (!headersValidated_) {
        bool restart = false;
        if (!validateHeaders(generation, &restart)) {
            fail(generation, QStringLiteral("invalid package response"), false);
            return;
        }
        if (restart) {
            if (!file_->resize(0) || !file_->seek(0)) {
                fail(generation, QStringLiteral("staging restart failed"), false);
                return;
            }
            received_ = 0;
            resume_ = false;
            hash_ = std::make_unique<QCryptographicHash>(QCryptographicHash::Sha256);
            QFile::remove(metadataPath_);
        }
        headersValidated_ = true;
    }

    while (reply_ && reply_->bytesAvailable() > 0 && !terminal_) {
        const quint64 remaining = release_.size - quint64(received_);
        const qint64 requestBytes = qint64((std::min)(quint64(kChunkBytes), remaining + 1));
        const QByteArray chunk = reply_->read(requestBytes);
        if (chunk.isEmpty() || !appendBytes(chunk)) {
            fail(generation, QStringLiteral("package exceeds signed size or staging write failed"), false);
            return;
        }
    }
}

void UpdateDownloadService::finish(quint64 generation)
{
    if (generation != generation_ || !reply_ || terminal_)
        return;
    if (!headersValidated_) {
        bool restart = false;
        if (!validateHeaders(generation, &restart)) {
            fail(generation, QStringLiteral("invalid package response"), false);
            return;
        }
        if (restart) {
            if (!file_->resize(0) || !file_->seek(0)) {
                fail(generation, QStringLiteral("staging restart failed"), false);
                return;
            }
            received_ = 0;
            resume_ = false;
            hash_ = std::make_unique<QCryptographicHash>(QCryptographicHash::Sha256);
            QFile::remove(metadataPath_);
        }
        headersValidated_ = true;
    }
    consume(generation);
    if (terminal_)
        return;
    if (reply_->error() != QNetworkReply::NoError) {
        fail(generation, QStringLiteral("package download failed"), true);
        return;
    }
    if (received_ != qint64(release_.size) || hash_->result() != release_.sha256) {
        fail(generation, QStringLiteral("package size or SHA-256 does not match manifest"), false);
        return;
    }
    if (!file_->flush()) {
        fail(generation, QStringLiteral("staging flush failed"), false);
        return;
    }
    file_->close();
    if (pathContainsReparsePoint(stagingDirectory_) ||
        pathContainsReparsePoint(partPath_) || pathContainsReparsePoint(finalPath_) ||
        !verifyFile(partPath_, qint64(release_.size), release_.sha256) ||
        !QFile::rename(partPath_, finalPath_)) {
        fail(generation, QStringLiteral("atomic package promotion failed"), false);
        return;
    }
    QFile::remove(metadataPath_);
    if (!verifyFile(finalPath_, qint64(release_.size), release_.sha256)) {
        QFile::remove(finalPath_);
        fail(generation, QStringLiteral("promoted package failed readback"), false);
        return;
    }

    terminal_ = true;
    QObject::disconnect(reply_, nullptr, this, nullptr);
    reply_->deleteLater();
    reply_.clear();
    file_.reset();
    hash_.reset();
    lock_.reset();
    Q_EMIT ready(finalPath_);
}

void UpdateDownloadService::fail(quint64 generation, const QString& reason,
                                 bool preservePartial)
{
    if (generation != generation_ || terminal_)
        return;
    terminal_ = true;
    resetActive(preservePartial);
    Q_EMIT failed(reason);
}

void UpdateDownloadService::cancel()
{
    if (!terminal_)
        fail(generation_, QStringLiteral("download cancelled"), true);
}
