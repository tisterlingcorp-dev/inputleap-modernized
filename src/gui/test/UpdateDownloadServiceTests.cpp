#include "UpdateDownloadService.h"

#include <gtest/gtest.h>

#include <QCryptographicHash>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSaveFile>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTimer>

#include <cstring>
#include <optional>
#include <utility>

namespace {
struct Response {
    QByteArray body;
    int status = 200;
    QByteArray mime = QByteArrayLiteral("application/octet-stream");
    QByteArray etag = QByteArrayLiteral("\"release-v1\"");
    QByteArray contentRange;
    bool includeLength = true;
    std::optional<qint64> declaredLength;
    QUrl redirect;
    QUrl responseUrl;
    QNetworkReply::NetworkError error = QNetworkReply::NoError;
    bool autoFinish = true;
};

class Reply final : public QNetworkReply
{
public:
    Reply(const QNetworkRequest& request, Response response, QObject* parent)
        : QNetworkReply(parent), response_(std::move(response))
    {
        setRequest(request);
        setUrl(response_.responseUrl.isEmpty() ? request.url() : response_.responseUrl);
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, response_.status);
        setRawHeader("Content-Type", response_.mime);
        if (response_.includeLength) {
            setRawHeader("Content-Length", QByteArray::number(
                response_.declaredLength.value_or(response_.body.size())));
        }
        if (!response_.etag.isEmpty())
            setRawHeader("ETag", response_.etag);
        if (!response_.contentRange.isEmpty())
            setRawHeader("Content-Range", response_.contentRange);
        if (!response_.redirect.isEmpty())
            setAttribute(QNetworkRequest::RedirectionTargetAttribute, response_.redirect);
        open(QIODevice::ReadOnly);
        if (response_.autoFinish) {
            QTimer::singleShot(0, this, [this] {
                append(response_.body, true, response_.error);
            });
        }
    }

    void abort() override
    {
        if (!isFinished())
            setError(OperationCanceledError, QStringLiteral("cancelled"));
    }

    qint64 bytesAvailable() const override
    {
        return available_.size() - offset_ + QNetworkReply::bytesAvailable();
    }

    void append(const QByteArray& bytes, bool finish,
                QNetworkReply::NetworkError error = QNetworkReply::NoError)
    {
        available_.append(bytes);
        if (!bytes.isEmpty())
            Q_EMIT readyRead();
        if (finish) {
            if (error != QNetworkReply::NoError)
                setError(error, QStringLiteral("fixture network failure"));
            setFinished(true);
            Q_EMIT finished();
        }
    }

protected:
    qint64 readData(char* data, qint64 maximum) override
    {
        const qint64 count = qMin(maximum, qint64(available_.size()) - offset_);
        if (count <= 0)
            return -1;
        std::memcpy(data, available_.constData() + offset_, size_t(count));
        offset_ += count;
        return count;
    }

private:
    Response response_;
    QByteArray available_;
    qint64 offset_ = 0;
};

class Network final : public QNetworkAccessManager
{
public:
    QList<Response> responses;
    QList<QNetworkRequest> requests;
    QList<Reply*> replies;

protected:
    QNetworkReply* createRequest(Operation operation, const QNetworkRequest& request,
                                 QIODevice*) override
    {
        EXPECT_EQ(operation, GetOperation);
        requests.append(request);
        Response response;
        if (!responses.isEmpty())
            response = responses.takeFirst();
        auto* reply = new Reply(request, std::move(response), this);
        replies.append(reply);
        return reply;
    }
};

UpdateService::Release releaseFor(const QByteArray& body,
                                  QString version = QStringLiteral("4.0.0"))
{
    UpdateService::Release release;
    release.installable = true;
    release.packageType = UpdateService::PackageType::WindowsMsi;
    release.version = std::move(version);
    release.size = body.size();
    release.packageUrl = QUrl(QStringLiteral("https://updates.example/inputleap.msi"));
    release.sha256 = QCryptographicHash::hash(body, QCryptographicHash::Sha256);
    return release;
}

QString baseName(const UpdateService::Release& release)
{
    return QStringLiteral("update-%1-%2")
        .arg(release.version, QString::fromLatin1(release.sha256.toHex().left(16)));
}

QString partPath(const QString& directory, const UpdateService::Release& release)
{
    return QDir(directory).filePath(baseName(release) + QStringLiteral(".part"));
}

QString metadataPath(const QString& directory, const UpdateService::Release& release)
{
    return partPath(directory, release) + QStringLiteral(".json");
}

QString finalPath(const QString& directory, const UpdateService::Release& release)
{
    return QDir(directory).filePath(baseName(release) + QStringLiteral(".msi"));
}

void createPartial(const QString& directory, const UpdateService::Release& release,
                   const QByteArray& prefix, const QByteArray& etag,
                   bool validPrefixHash = true)
{
    QFile partial(partPath(directory, release));
    ASSERT_TRUE(partial.open(QIODevice::WriteOnly));
    ASSERT_EQ(partial.write(prefix), prefix.size());
    partial.close();
    QByteArray digest = QCryptographicHash::hash(prefix, QCryptographicHash::Sha256);
    if (!validPrefixHash)
        digest.fill('0');
    const QJsonObject object{
        {QStringLiteral("etag"), QString::fromUtf8(etag)},
        {QStringLiteral("packageType"), QStringLiteral("windows-msi")},
        {QStringLiteral("prefixSha256"), QString::fromLatin1(digest.toHex())},
        {QStringLiteral("prefixSize"), prefix.size()},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("sha256"), QString::fromLatin1(release.sha256.toHex())},
        {QStringLiteral("size"), qint64(release.size)},
        {QStringLiteral("url"), release.packageUrl.toString(QUrl::FullyEncoded)},
        {QStringLiteral("version"), release.version},
    };
    const QByteArray encoded = QJsonDocument(object).toJson(QJsonDocument::Compact);
    QFile metadata(metadataPath(directory, release));
    ASSERT_TRUE(metadata.open(QIODevice::WriteOnly));
    ASSERT_EQ(metadata.write(encoded), encoded.size());
}

QByteArray readAll(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return {};
    return file.readAll();
}
}

TEST(UpdateDownloadServiceTests, ExactHttpsMsiCompletesOnlyAfterHashAndReadback)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray body = QByteArrayLiteral("private-msi-fixture");
    Network network;
    network.responses.append(Response{.body = body});
    UpdateDownloadService service(&network, directory.path());
    QSignalSpy ready(&service, &UpdateDownloadService::ready);

    service.start(releaseFor(body));

    ASSERT_TRUE(ready.wait(1000));
    ASSERT_EQ(ready.count(), 1);
    EXPECT_EQ(readAll(ready.at(0).at(0).toString()), body);
    EXPECT_FALSE(QFile::exists(partPath(directory.path(), releaseFor(body))));
}

TEST(UpdateDownloadServiceTests, RejectsUnauthenticatedReleaseBeforeNetwork)
{
    const QByteArray body = QByteArrayLiteral("x");
    for (int mutation = 0; mutation < 7; ++mutation) {
        QTemporaryDir directory;
        Network network;
        UpdateDownloadService service(&network, directory.path());
        auto release = releaseFor(body);
        if (mutation == 0) release.installable = false;
        if (mutation == 1) release.packageType = UpdateService::PackageType::Unknown;
        if (mutation == 2) release.packageUrl.setScheme(QStringLiteral("http"));
        if (mutation == 3) release.packageUrl.setUserName(QStringLiteral("user"));
        if (mutation == 4) release.packageUrl.setFragment(QStringLiteral("fragment"));
        if (mutation == 5) release.packageUrl.setPath(QStringLiteral("/package.exe"));
        if (mutation == 6) release.sha256.clear();
        QSignalSpy failed(&service, &UpdateDownloadService::failed);
        service.start(release);
        EXPECT_EQ(failed.count(), 1) << mutation;
        EXPECT_TRUE(network.requests.isEmpty()) << mutation;
    }
}

TEST(UpdateDownloadServiceTests, ConfiguresBoundedTransferStallTimeout)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    Network network;
    UpdateDownloadService service(&network, directory.path());
    const QByteArray body = QByteArrayLiteral("signed-msi");

    service.start(releaseFor(body));

    ASSERT_EQ(network.requests.size(), 1);
    EXPECT_GE(network.requests.constFirst().transferTimeout(), 1000);
    EXPECT_LE(network.requests.constFirst().transferTimeout(), 120000);
    service.cancel();
}

TEST(UpdateDownloadServiceTests, AbsoluteDeadlineStopsPeriodicDripFeed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray body = QByteArrayLiteral("0123456789");
    Network network;
    network.responses.append(Response{.body = {},
                                      .declaredLength = body.size(),
                                      .autoFinish = false});
    UpdateDownloadService service(&network, directory.path(), nullptr, {}, 25);
    QSignalSpy failed(&service, &UpdateDownloadService::failed);

    service.start(releaseFor(body));
    ASSERT_EQ(network.replies.size(), 1);
    QTimer::singleShot(5, network.replies.first(), [reply = network.replies.first()] {
        reply->append(QByteArrayLiteral("0"), false);
    });
    QTimer::singleShot(10, network.replies.first(), [reply = network.replies.first()] {
        reply->append(QByteArrayLiteral("1"), false);
    });
    QTimer::singleShot(15, network.replies.first(), [reply = network.replies.first()] {
        reply->append(QByteArrayLiteral("2"), false);
    });

    ASSERT_TRUE(failed.wait(1000));
    EXPECT_FALSE(service.active());
    EXPECT_TRUE(QFile::exists(partPath(directory.path(), releaseFor(body))));
    EXPECT_TRUE(QFile::exists(metadataPath(directory.path(), releaseFor(body))));
}

TEST(UpdateDownloadServiceTests, RejectsStatusMimeLengthRedirectAndResponseUrl)
{
    const QByteArray body = QByteArrayLiteral("abcd");
    for (int mutation = 0; mutation < 6; ++mutation) {
        QTemporaryDir directory;
        Network network;
        Response response{.body = body};
        if (mutation == 0) response.status = 404;
        if (mutation == 1) response.mime = QByteArrayLiteral("text/html");
        if (mutation == 2) response.includeLength = false;
        if (mutation == 3) response.declaredLength = body.size() + 1;
        if (mutation == 4) response.redirect = QUrl(QStringLiteral("https://other.example/x.msi"));
        if (mutation == 5) response.responseUrl = QUrl(QStringLiteral("https://other.example/x.msi"));
        network.responses.append(response);
        UpdateDownloadService service(&network, directory.path());
        QSignalSpy failed(&service, &UpdateDownloadService::failed);
        service.start(releaseFor(body));
        ASSERT_TRUE(failed.wait(1000)) << mutation;
        EXPECT_FALSE(QFile::exists(finalPath(directory.path(), releaseFor(body)))) << mutation;
    }
}

TEST(UpdateDownloadServiceTests, RejectsBodyBeyondSignedSizeAndWrongHash)
{
    const QByteArray expected = QByteArrayLiteral("good");
    for (const QByteArray& responseBody : {QByteArrayLiteral("good-extra"),
                                           QByteArrayLiteral("evil")}) {
        QTemporaryDir directory;
        Network network;
        Response response{.body = responseBody};
        response.declaredLength = expected.size();
        network.responses.append(response);
        UpdateDownloadService service(&network, directory.path());
        QSignalSpy failed(&service, &UpdateDownloadService::failed);
        const auto release = releaseFor(expected);
        service.start(release);
        ASSERT_TRUE(failed.wait(1000));
        EXPECT_FALSE(QFile::exists(finalPath(directory.path(), release)));
        EXPECT_FALSE(QFile::exists(partPath(directory.path(), release)));
        EXPECT_FALSE(QFile::exists(metadataPath(directory.path(), release)));
    }
}

TEST(UpdateDownloadServiceTests, ResumeUsesExactRangeIfRangeAndContentRange)
{
    QTemporaryDir directory;
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    const QByteArray prefix = body.left(3);
    const QByteArray etag = QByteArrayLiteral("\"release-v1\"");
    const auto release = releaseFor(body);
    createPartial(directory.path(), release, prefix, etag);
    Network network;
    Response response{.body = body.mid(prefix.size()), .status = 206,
                      .etag = etag,
                      .contentRange = QByteArrayLiteral("bytes 3-9/10")};
    network.responses.append(response);
    UpdateDownloadService service(&network, directory.path());
    QSignalSpy ready(&service, &UpdateDownloadService::ready);

    service.start(release);

    ASSERT_TRUE(ready.wait(1000));
    ASSERT_EQ(network.requests.size(), 1);
    EXPECT_EQ(network.requests.first().rawHeader("Range"), QByteArrayLiteral("bytes=3-"));
    EXPECT_EQ(network.requests.first().rawHeader("If-Range"), etag);
    EXPECT_EQ(readAll(finalPath(directory.path(), release)), body);
}

TEST(UpdateDownloadServiceTests, FullResponseDuringResumeRestartsWithoutAppending)
{
    QTemporaryDir directory;
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    const auto release = releaseFor(body);
    createPartial(directory.path(), release, body.left(3), QByteArrayLiteral("\"old\""));
    Network network;
    network.responses.append(Response{.body = body, .status = 200,
                                      .etag = QByteArrayLiteral("\"new\"")});
    UpdateDownloadService service(&network, directory.path());
    QSignalSpy ready(&service, &UpdateDownloadService::ready);

    service.start(release);

    ASSERT_TRUE(ready.wait(1000));
    EXPECT_EQ(readAll(finalPath(directory.path(), release)), body);
}

TEST(UpdateDownloadServiceTests, InvalidResumeResponseRemovesUntrustedPartial)
{
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    for (int mutation = 0; mutation < 3; ++mutation) {
        QTemporaryDir directory;
        const auto release = releaseFor(body);
        createPartial(directory.path(), release, body.left(3), QByteArrayLiteral("\"v1\""));
        Response response{.body = body.mid(3), .status = 206,
                          .etag = QByteArrayLiteral("\"v1\""),
                          .contentRange = QByteArrayLiteral("bytes 3-9/10")};
        if (mutation == 0) response.contentRange = QByteArrayLiteral("bytes 2-9/10");
        if (mutation == 1) response.etag = QByteArrayLiteral("\"other\"");
        if (mutation == 2) response.etag = QByteArrayLiteral("W/\"v1\"");
        Network network;
        network.responses.append(response);
        UpdateDownloadService service(&network, directory.path());
        QSignalSpy failed(&service, &UpdateDownloadService::failed);
        service.start(release);
        ASSERT_TRUE(failed.wait(1000));
        EXPECT_FALSE(QFile::exists(partPath(directory.path(), release)));
        EXPECT_FALSE(QFile::exists(metadataPath(directory.path(), release)));
    }
}

TEST(UpdateDownloadServiceTests,
     RangeNotSatisfiableDiscardsPartialAndNeverPublishesArtifact)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    const auto release = releaseFor(body);
    createPartial(directory.path(), release, body.left(3),
                  QByteArrayLiteral("\"v1\""));
    Network network;
    network.responses.append(Response{.body = {}, .status = 416});
    UpdateDownloadService service(&network, directory.path());
    QSignalSpy ready(&service, &UpdateDownloadService::ready);
    QSignalSpy failed(&service, &UpdateDownloadService::failed);

    service.start(release);

    ASSERT_TRUE(failed.wait(1000));
    ASSERT_EQ(network.requests.size(), 1);
    EXPECT_EQ(network.requests.constFirst().rawHeader("Range"),
              QByteArrayLiteral("bytes=3-"));
    EXPECT_TRUE(ready.isEmpty());
    EXPECT_FALSE(QFile::exists(finalPath(directory.path(), release)));
    EXPECT_FALSE(QFile::exists(partPath(directory.path(), release)));
    EXPECT_FALSE(QFile::exists(metadataPath(directory.path(), release)));
}

TEST(UpdateDownloadServiceTests,
     CompleteVerifiedPartialIsPromotedWithoutAnotherNetworkRequest)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray body = QByteArrayLiteral("complete-after-crash");
    const auto release = releaseFor(body);
    createPartial(directory.path(), release, body, QByteArrayLiteral("\"v1\""));
    Network network;
    UpdateDownloadService service(&network, directory.path());
    QSignalSpy ready(&service, &UpdateDownloadService::ready);

    service.start(release);

    ASSERT_EQ(ready.count(), 1);
    EXPECT_TRUE(network.requests.isEmpty());
    EXPECT_EQ(readAll(finalPath(directory.path(), release)), body);
    EXPECT_FALSE(QFile::exists(partPath(directory.path(), release)));
    EXPECT_FALSE(QFile::exists(metadataPath(directory.path(), release)));
}

TEST(UpdateDownloadServiceTests, CorruptOrOversizedPartialRestartsFromZero)
{
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    for (int mutation = 0; mutation < 2; ++mutation) {
        QTemporaryDir directory;
        const auto release = releaseFor(body);
        if (mutation == 0)
            createPartial(directory.path(), release, body.left(3), QByteArrayLiteral("\"v1\""), false);
        else {
            QFile partial(partPath(directory.path(), release));
            ASSERT_TRUE(partial.open(QIODevice::WriteOnly));
            ASSERT_EQ(partial.write(body + QByteArrayLiteral("extra")), body.size() + 5);
        }
        Network network;
        network.responses.append(Response{.body = body});
        UpdateDownloadService service(&network, directory.path());
        QSignalSpy ready(&service, &UpdateDownloadService::ready);
        service.start(release);
        ASSERT_TRUE(ready.wait(1000));
        EXPECT_TRUE(network.requests.first().rawHeader("Range").isEmpty());
    }
}

TEST(UpdateDownloadServiceTests, ShortWriteFailsWithoutPublishableArtifact)
{
    QTemporaryDir directory;
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    const auto release = releaseFor(body);
    Network network;
    network.responses.append(Response{.body = body});
    UpdateDownloadService service(
        &network, directory.path(), nullptr,
        [](QFile& file, const QByteArray& bytes) {
            file.write(bytes);
            return qint64(bytes.size() - 1);
        });
    QSignalSpy failed(&service, &UpdateDownloadService::failed);

    service.start(release);

    ASSERT_TRUE(failed.wait(1000));
    EXPECT_FALSE(QFile::exists(finalPath(directory.path(), release)));
    EXPECT_FALSE(QFile::exists(partPath(directory.path(), release)));
}

TEST(UpdateDownloadServiceTests, CancellationPreservesVerifiedPrefixForResume)
{
    QTemporaryDir directory;
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    const auto release = releaseFor(body);
    Network firstNetwork;
    firstNetwork.responses.append(Response{.body = {},
                                           .declaredLength = body.size(),
                                           .autoFinish = false});
    UpdateDownloadService first(&firstNetwork, directory.path());
    QSignalSpy failed(&first, &UpdateDownloadService::failed);
    QSignalSpy progress(&first, &UpdateDownloadService::progress);
    first.start(release);
    ASSERT_EQ(firstNetwork.replies.size(), 1);
    firstNetwork.replies.first()->append(body.left(3), false);
    ASSERT_EQ(progress.count(), 1);
    first.cancel();
    ASSERT_EQ(failed.count(), 1);
    EXPECT_FALSE(QFile::exists(finalPath(directory.path(), release)));
    EXPECT_TRUE(QFile::exists(partPath(directory.path(), release)));

    Network secondNetwork;
    secondNetwork.responses.append(Response{
        .body = body.mid(3), .status = 206,
        .contentRange = QByteArrayLiteral("bytes 3-9/10")});
    UpdateDownloadService second(&secondNetwork, directory.path());
    QSignalSpy ready(&second, &UpdateDownloadService::ready);
    second.start(release);
    ASSERT_TRUE(ready.wait(1000));
    EXPECT_EQ(secondNetwork.requests.first().rawHeader("Range"), QByteArrayLiteral("bytes=3-"));
    EXPECT_EQ(readAll(finalPath(directory.path(), release)), body);
}

TEST(UpdateDownloadServiceTests, LockPreventsTwoWriters)
{
    QTemporaryDir directory;
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    const auto release = releaseFor(body);
    Network firstNetwork;
    firstNetwork.responses.append(Response{.body = {}, .autoFinish = false});
    UpdateDownloadService first(&firstNetwork, directory.path());
    first.start(release);

    Network secondNetwork;
    UpdateDownloadService second(&secondNetwork, directory.path());
    QSignalSpy failed(&second, &UpdateDownloadService::failed);
    second.start(release);

    EXPECT_EQ(failed.count(), 1);
    EXPECT_TRUE(secondNetwork.requests.isEmpty());
    first.cancel();
}

TEST(UpdateDownloadServiceTests, SupersededReplyCannotCompleteNewGeneration)
{
    QTemporaryDir directory;
    const QByteArray oldBody = QByteArrayLiteral("old-package");
    const QByteArray newBody = QByteArrayLiteral("new-package");
    Network network;
    network.responses.append(Response{.body = {}, .autoFinish = false});
    network.responses.append(Response{.body = newBody});
    UpdateDownloadService service(&network, directory.path());
    QSignalSpy ready(&service, &UpdateDownloadService::ready);
    service.start(releaseFor(oldBody, QStringLiteral("4.0.0")));
    ASSERT_EQ(network.replies.size(), 1);
    QPointer<Reply> stale = network.replies.first();

    service.start(releaseFor(newBody, QStringLiteral("4.0.1")));
    ASSERT_TRUE(ready.wait(1000));
    QCoreApplication::processEvents();

    EXPECT_EQ(ready.count(), 1);
    EXPECT_TRUE(stale.isNull());
    EXPECT_EQ(readAll(ready.at(0).at(0).toString()), newBody);
}

TEST(UpdateDownloadServiceTests, NetworkFailureKeepsPrefixButShortSuccessDoesNot)
{
    const QByteArray body = QByteArrayLiteral("abcdefghij");
    for (int mutation = 0; mutation < 2; ++mutation) {
        QTemporaryDir directory;
        const auto release = releaseFor(body);
        Network network;
        Response response{.body = body.left(3)};
        response.declaredLength = body.size();
        if (mutation == 0)
            response.error = QNetworkReply::RemoteHostClosedError;
        network.responses.append(response);
        UpdateDownloadService service(&network, directory.path());
        QSignalSpy failed(&service, &UpdateDownloadService::failed);
        service.start(release);
        ASSERT_TRUE(failed.wait(1000));
        EXPECT_FALSE(QFile::exists(finalPath(directory.path(), release)));
        EXPECT_EQ(QFile::exists(partPath(directory.path(), release)), mutation == 0);
    }
}
