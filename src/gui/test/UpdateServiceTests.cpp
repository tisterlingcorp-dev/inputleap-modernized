#include "UpdateService.h"
#include "UpdateTrustConfig.h"
#include "SecureCredentialStore.h"
#include "RecoveryArtifactAuthenticator.h"

#include <gtest/gtest.h>

#include <QDateTime>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSignalSpy>
#include <QSettings>
#include <QTemporaryDir>
#include <QTimer>

#include <cstring>
#include <functional>

#include <openssl/evp.h>

namespace {

SecureCredentialStore replayCredentialStore(QHash<QString, QByteArray>& credentials)
{
    return SecureCredentialStore(
        [&credentials](const QString& account) -> SecureCredentialStore::ReadResult {
            const auto found = credentials.constFind(account);
            return found == credentials.cend()
                ? SecureCredentialStore::ReadResult::notFound()
                : SecureCredentialStore::ReadResult::found(*found);
        },
        [&credentials](const QString& account, const QByteArray& value) {
            credentials.insert(account, value);
            return true;
        },
        [&credentials](const QString& account) {
            credentials.remove(account);
            return true;
        });
}

class FakeReply final : public QNetworkReply
{
public:
    FakeReply(const QNetworkRequest& request, QByteArray body, int status,
              QString contentType, QUrl finalUrl, qint64* bytesRead,
              bool finishReply, QNetworkReply::NetworkError networkError,
              QObject* parent)
        : QNetworkReply(parent), body_(std::move(body)), bytesRead_(bytesRead),
          finishReply_(finishReply)
    {
        setRequest(request);
        setUrl(finalUrl.isEmpty() ? request.url() : finalUrl);
        setAttribute(QNetworkRequest::HttpStatusCodeAttribute, status);
        setHeader(QNetworkRequest::ContentTypeHeader, contentType);
        if (networkError != QNetworkReply::NoError)
            setError(networkError, QStringLiteral("synthetic network error"));
        open(QIODevice::ReadOnly);
        QTimer::singleShot(0, this, [this] {
            Q_EMIT readyRead();
            if (finishReply_) {
                setFinished(true);
                Q_EMIT finished();
            }
        });
    }

    void abort() override { setError(OperationCanceledError, QStringLiteral("cancelled")); }
    qint64 bytesAvailable() const override
    {
        return body_.size() - offset_ + QNetworkReply::bytesAvailable();
    }

protected:
    qint64 readData(char* data, qint64 maxSize) override
    {
        const qint64 count = qMin(maxSize, qint64(body_.size() - offset_));
        if (count <= 0)
            return -1;
        std::memcpy(data, body_.constData() + offset_, size_t(count));
        offset_ += count;
        if (bytesRead_ != nullptr)
            *bytesRead_ += count;
        return count;
    }

private:
    QByteArray body_;
    qint64 offset_ = 0;
    qint64* bytesRead_ = nullptr;
    bool finishReply_ = true;
};

class FakeNetworkAccessManager final : public QNetworkAccessManager
{
public:
    QByteArray response;
    QNetworkRequest capturedRequest;
    int status = 200;
    QString contentType = QStringLiteral("application/json");
    QUrl finalUrl;
    qint64 bytesRead = 0;
    bool finishReply = true;
    QNetworkReply::NetworkError networkError = QNetworkReply::NoError;

protected:
    QNetworkReply* createRequest(Operation operation, const QNetworkRequest& request,
                                 QIODevice* outgoingData) override
    {
        Q_UNUSED(operation);
        Q_UNUSED(outgoingData);
        capturedRequest = request;
        return new FakeReply(request, response, status, contentType, finalUrl, &bytesRead,
                             finishReply, networkError, this);
    }
};

struct SigningKey
{
    QByteArray privateSeed;
    QByteArray publicKey;
};

SigningKey testSigningKey(int firstByte = 1)
{
    SigningKey key{QByteArray(32, Qt::Uninitialized), QByteArray(32, Qt::Uninitialized)};
    for (int i = 0; i < key.privateSeed.size(); ++i)
        key.privateSeed[i] = char(i + firstByte);
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(key.privateSeed.constData()),
        size_t(key.privateSeed.size()));
    EXPECT_NE(pkey, nullptr);
    size_t publicSize = size_t(key.publicKey.size());
    EXPECT_EQ(EVP_PKEY_get_raw_public_key(
                  pkey, reinterpret_cast<unsigned char*>(key.publicKey.data()), &publicSize),
              1);
    EXPECT_EQ(publicSize, size_t(32));
    EVP_PKEY_free(pkey);
    return key;
}

QByteArray sign(const QByteArray& payload, const QByteArray& privateSeed)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(privateSeed.constData()),
        size_t(privateSeed.size()));
    EXPECT_NE(pkey, nullptr);
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EXPECT_NE(context, nullptr);
    EXPECT_EQ(EVP_DigestSignInit(context, nullptr, nullptr, nullptr, pkey), 1);
    QByteArray signature(64, Qt::Uninitialized);
    size_t signatureSize = size_t(signature.size());
    EXPECT_EQ(EVP_DigestSign(context,
                             reinterpret_cast<unsigned char*>(signature.data()), &signatureSize,
                             reinterpret_cast<const unsigned char*>(payload.constData()),
                             size_t(payload.size())),
              1);
    signature.resize(qsizetype(signatureSize));
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(pkey);
    return signature;
}

QByteArray releasePayload()
{
    QJsonObject payload;
    payload.insert(QStringLiteral("schema"), 1);
    payload.insert(QStringLiteral("channel"), QStringLiteral("stable"));
    payload.insert(QStringLiteral("version"), QStringLiteral("3.2.0"));
    payload.insert(QStringLiteral("size"), 73400320);
    payload.insert(QStringLiteral("notes"), QStringLiteral("Atualização segura e melhorias de estabilidade."));
    payload.insert(QStringLiteral("packageUrl"),
                   QStringLiteral("https://updates.input-leap.example/stable/input-leap-3.2.0.exe"));
    payload.insert(QStringLiteral("sha256"),
                   QStringLiteral("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    payload.insert(QStringLiteral("issuedAtUtc"), QStringLiteral("2026-07-19T05:00:00Z"));
    payload.insert(QStringLiteral("expiresAtUtc"), QStringLiteral("2026-07-26T05:00:00Z"));
    return QJsonDocument(payload).toJson(QJsonDocument::Compact);
}

QByteArray releasePayloadWith(const std::function<void(QJsonObject&)>& mutation)
{
    QJsonObject payload = QJsonDocument::fromJson(releasePayload()).object();
    mutation(payload);
    return QJsonDocument(payload).toJson(QJsonDocument::Compact);
}

QByteArray releasePayloadSchema2()
{
    QJsonObject payload = QJsonDocument::fromJson(releasePayload()).object();
    payload.insert(QStringLiteral("packageType"), QStringLiteral("windows-msi"));
    payload.insert(QStringLiteral("authenticodeSignerSha256"),
                   QStringLiteral(
                       "abcdef0123456789abcdef0123456789"
                       "abcdef0123456789abcdef0123456789"));
    payload.insert(QStringLiteral("schema"), 2);
    payload.insert(QStringLiteral("packageUrl"),
                   QStringLiteral("https://updates.input-leap.example/stable/input-leap-3.2.0.msi"));
    return QJsonDocument(payload).toJson(QJsonDocument::Compact);
}

QByteArray releasePayloadSchema2With(
    const std::function<void(QJsonObject&)>& mutation)
{
    QJsonObject payload = QJsonDocument::fromJson(releasePayloadSchema2()).object();
    mutation(payload);
    return QJsonDocument(payload).toJson(QJsonDocument::Compact);
}

QByteArray envelope(const QByteArray& payload, const SigningKey& key)
{
    QJsonObject envelope;
    envelope.insert(QStringLiteral("schema"), 1);
    envelope.insert(QStringLiteral("keyId"), QStringLiteral("release-2026"));
    envelope.insert(QStringLiteral("payload"),
                    QString::fromLatin1(payload.toBase64(QByteArray::Base64UrlEncoding |
                                                         QByteArray::OmitTrailingEquals)));
    envelope.insert(QStringLiteral("signature"),
                    QString::fromLatin1(sign(payload, key.privateSeed)
                                            .toBase64(QByteArray::Base64UrlEncoding |
                                                      QByteArray::OmitTrailingEquals)));
    return QJsonDocument(envelope).toJson(QJsonDocument::Compact);
}

QByteArray thresholdEnvelope(
    const QByteArray& payload,
    const QList<QPair<QString, SigningKey>>& signers)
{
    QJsonArray signatures;
    for (const auto& signer : signers) {
        QJsonObject item;
        item.insert(QStringLiteral("keyId"), signer.first);
        item.insert(QStringLiteral("signature"),
                    QString::fromLatin1(sign(payload, signer.second.privateSeed)
                                            .toBase64(QByteArray::Base64UrlEncoding |
                                                      QByteArray::OmitTrailingEquals)));
        signatures.append(item);
    }
    QJsonObject outer;
    outer.insert(QStringLiteral("payload"),
                 QString::fromLatin1(payload.toBase64(QByteArray::Base64UrlEncoding |
                                                      QByteArray::OmitTrailingEquals)));
    outer.insert(QStringLiteral("schema"), 2);
    outer.insert(QStringLiteral("signatures"), signatures);
    return QJsonDocument(outer).toJson(QJsonDocument::Compact);
}

std::optional<UpdateService::Result> fetchResult(FakeNetworkAccessManager& network,
                                                 const SigningKey& key)
{
    UpdateService service(&network, {{QStringLiteral("release-2026"), key.publicKey}},
                          QStringLiteral("3.1.0-modernized"));
    QSignalSpy finished(&service, &UpdateService::checkFinished);
    service.check(
        QUrl(QStringLiteral("https://updates.input-leap.example/stable/manifest.json")),
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    if (!finished.wait(1000) || finished.count() != 1)
        return std::nullopt;
    return qvariant_cast<UpdateService::Result>(finished.at(0).at(0));
}

} // namespace

TEST(UpdateServiceTests, AcceptsPinnedSignedStableManifestAndReportsUpdateDetails)
{
    const SigningKey key = testSigningKey();
    const QByteArray payload = releasePayload();
    const auto result = UpdateService::evaluate(
        envelope(payload, key),
        QUrl(QStringLiteral("https://updates.input-leap.example/stable/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    ASSERT_EQ(result.error, UpdateService::Error::None);
    ASSERT_TRUE(result.release.has_value());
    EXPECT_TRUE(result.updateAvailable);
    EXPECT_EQ(result.release->channel, QStringLiteral("stable"));
    EXPECT_EQ(result.release->version, QStringLiteral("3.2.0"));
    EXPECT_EQ(result.release->size, quint64(73400320));
    EXPECT_EQ(result.release->notes,
              QStringLiteral("Atualização segura e melhorias de estabilidade."));
}

TEST(UpdateServiceTests, ThresholdPolicyRequiresTwoDistinctValidSignatures)
{
    const SigningKey first = testSigningKey(1);
    const SigningKey second = testSigningKey(41);
    const SigningKey third = testSigningKey(81);
    const UpdateService::TrustedKeys keys{
        {QStringLiteral("release-a"), first.publicKey},
        {QStringLiteral("release-b"), second.publicKey},
        {QStringLiteral("release-c"), third.publicKey}};
    const QByteArray payload = releasePayload();
    const QUrl source(QStringLiteral("https://updates.input-leap.example/manifest.json"));
    const QDateTime now = QDateTime::fromString(
        QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate);

    const auto insufficient = UpdateService::evaluate(
        thresholdEnvelope(payload, {{QStringLiteral("release-a"), first}}),
        source, QStringLiteral("3.1.0-modernized"), keys, now, 2);
    EXPECT_EQ(insufficient.error, UpdateService::Error::InvalidSignature);
    EXPECT_FALSE(insufficient.release.has_value());

    const auto accepted = UpdateService::evaluate(
        thresholdEnvelope(payload, {{QStringLiteral("release-a"), first},
                                    {QStringLiteral("release-b"), second}}),
        source, QStringLiteral("3.1.0-modernized"), keys, now, 2);
    EXPECT_EQ(accepted.error, UpdateService::Error::None);
    EXPECT_TRUE(accepted.release.has_value());
}

TEST(UpdateServiceTests, ThresholdIgnoresRevokedAndNotYetActiveKeys)
{
    const SigningKey first = testSigningKey(1);
    const SigningKey second = testSigningKey(41);
    const QByteArray signedByBoth = thresholdEnvelope(
        releasePayload(), {{QStringLiteral("release-a"), first},
                           {QStringLiteral("release-b"), second}});
    const QDateTime now = QDateTime::fromString(
        QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate);
    UpdateService::TrustedKey firstPolicy{first.publicKey};
    firstPolicy.notBeforeUtc = now.addDays(-1);
    firstPolicy.notAfterUtc = now.addDays(30);
    UpdateService::TrustedKey secondPolicy{second.publicKey};
    secondPolicy.notBeforeUtc = now.addDays(-1);
    secondPolicy.notAfterUtc = now.addDays(30);
    secondPolicy.revoked = true;
    UpdateService::TrustedKeys policies{
        {QStringLiteral("release-a"), firstPolicy},
        {QStringLiteral("release-b"), secondPolicy}};
    const QUrl source(QStringLiteral("https://updates.example/manifest.json"));

    const auto revoked = UpdateService::evaluate(
        signedByBoth, source, QStringLiteral("3.1.0-modernized"), policies, now, 2);
    EXPECT_EQ(revoked.error, UpdateService::Error::InvalidSignature);

    policies[QStringLiteral("release-b")].revoked = false;
    policies[QStringLiteral("release-b")].notBeforeUtc = now.addSecs(1);
    const auto future = UpdateService::evaluate(
        signedByBoth, source, QStringLiteral("3.1.0-modernized"), policies, now, 2);
    EXPECT_EQ(future.error, UpdateService::Error::InvalidSignature);

    policies[QStringLiteral("release-b")].notBeforeUtc = now.addDays(-1);
    const auto active = UpdateService::evaluate(
        signedByBoth, source, QStringLiteral("3.1.0-modernized"), policies, now, 2);
    EXPECT_EQ(active.error, UpdateService::Error::None);
}

TEST(UpdateServiceTests, RejectsSignedPayloadWithDuplicateJsonKeys)
{
    const SigningKey key = testSigningKey();
    const QByteArray ambiguousPayload = QByteArrayLiteral(
        "{\"channel\":\"stable\",\"expiresAtUtc\":\"2026-07-26T05:00:00Z\","
        "\"issuedAtUtc\":\"2026-07-19T05:00:00Z\",\"notes\":\"Correções.\","
        "\"packageUrl\":\"https://updates.input-leap.example/stable/input-leap.exe\","
        "\"schema\":1,\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\","
        "\"size\":73400320,\"version\":\"9.9.9\",\"version\":\"3.2.0\"}");

    const auto result = UpdateService::evaluate(
        envelope(ambiguousPayload, key),
        QUrl(QStringLiteral("https://updates.input-leap.example/stable/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    EXPECT_EQ(result.error, UpdateService::Error::InvalidManifest);
    EXPECT_FALSE(result.release.has_value());
}

TEST(UpdateServiceTests, FetchesManifestOnDemandWithSameOriginHttpsPolicy)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    UpdateService service(&network, {{QStringLiteral("release-2026"), key.publicKey}},
                          QStringLiteral("3.1.0-modernized"));
    QSignalSpy finished(&service, &UpdateService::checkFinished);
    const QUrl manifestUrl(QStringLiteral(
        "https://updates.input-leap.example/stable/manifest.json"));

    service.check(manifestUrl,
                  QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    ASSERT_TRUE(finished.wait(1000));
    ASSERT_EQ(finished.count(), 1);
    const auto result = qvariant_cast<UpdateService::Result>(finished.at(0).at(0));
    EXPECT_EQ(result.error, UpdateService::Error::None);
    EXPECT_TRUE(result.updateAvailable);
    EXPECT_EQ(network.capturedRequest.url(), manifestUrl);
    EXPECT_EQ(network.capturedRequest.attribute(QNetworkRequest::RedirectPolicyAttribute).toInt(),
              int(QNetworkRequest::SameOriginRedirectPolicy));
    EXPECT_EQ(network.capturedRequest.transferTimeout(), 15000);
    EXPECT_EQ(network.capturedRequest.rawHeader("Accept"), QByteArrayLiteral("application/json"));
}

TEST(UpdateServiceTests, AcceptsWindowsMsiSchemaTwoAndInstallsOnlyOnWindows)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayloadSchema2(), key),
        QUrl(QStringLiteral("https://updates.input-leap.example/stable/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    ASSERT_EQ(result.error, UpdateService::Error::None);
    ASSERT_TRUE(result.release.has_value());
    EXPECT_EQ(result.release->packageType, UpdateService::PackageType::WindowsMsi);
#if defined(Q_OS_WIN)
    EXPECT_TRUE(result.release->installable);
#else
    EXPECT_FALSE(result.release->installable);
#endif
    EXPECT_EQ(result.release->authenticodeSignerSha256,
              QByteArray::fromHex(QByteArrayLiteral(
                  "abcdef0123456789abcdef0123456789"
                  "abcdef0123456789abcdef0123456789")));
}

TEST(UpdateServiceTests, SchemaTwoMissingOrUnknownPackageTypeFailsClosed)
{
    const SigningKey key = testSigningKey();
    for (const QString& packageType : {QString(), QStringLiteral("windows-exe"),
                                       QStringLiteral("Windows-MSI")}) {
        const auto result = UpdateService::evaluate(
            envelope(releasePayloadSchema2With([&](QJsonObject& object) {
                if (!packageType.isEmpty())
                    object.insert(QStringLiteral("packageType"), packageType);
                else
                    object.remove(QStringLiteral("packageType"));
            }), key),
            QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
            QStringLiteral("3.1.0-modernized"),
            {{QStringLiteral("release-2026"), key.publicKey}},
            QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
        EXPECT_NE(result.error, UpdateService::Error::None);
        EXPECT_FALSE(result.release.has_value());
    }
}

TEST(UpdateServiceTests, SchemaTwoRequiresCanonicalSignerCertificateSha256)
{
    const SigningKey key = testSigningKey();
    const QList<QJsonValue> invalidValues{
        QJsonValue(QJsonValue::Undefined),
        QStringLiteral("abcdef"),
        QStringLiteral(
            "ABCDEF0123456789ABCDEF0123456789"
            "ABCDEF0123456789ABCDEF0123456789"),
        QStringLiteral(
            "gbcdef0123456789abcdef0123456789"
            "abcdef0123456789abcdef0123456789")};
    for (const QJsonValue& value : invalidValues) {
        const auto result = UpdateService::evaluate(
            envelope(releasePayloadSchema2With([&](QJsonObject& object) {
                if (value.isUndefined())
                    object.remove(QStringLiteral("authenticodeSignerSha256"));
                else
                    object.insert(QStringLiteral("authenticodeSignerSha256"), value);
            }), key),
            QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
            QStringLiteral("3.1.0-modernized"),
            {{QStringLiteral("release-2026"), key.publicKey}},
            QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"),
                                  Qt::ISODate));
        EXPECT_NE(result.error, UpdateService::Error::None);
        EXPECT_FALSE(result.release.has_value());
    }
}

TEST(UpdateServiceTests, SchemaOneReleaseRemainsDisplayOnly)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayload(), key),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    ASSERT_EQ(result.error, UpdateService::Error::None);
    ASSERT_TRUE(result.release.has_value());
    EXPECT_EQ(result.release->packageType, UpdateService::PackageType::Unknown);
    EXPECT_FALSE(result.release->installable);
}

TEST(UpdateServiceTests, AbsoluteDeadlineFailsClosedWhenReplyNeverFinishes)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    network.finishReply = false;
    UpdateService service(&network, {{QStringLiteral("release-2026"), key.publicKey}},
                          QStringLiteral("3.1.0-modernized"), nullptr, nullptr, 1, 20);
    QSignalSpy finished(&service, &UpdateService::checkFinished);

    service.check(QUrl(QStringLiteral("https://updates.example/manifest.json")),
                  QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    ASSERT_TRUE(finished.wait(250));
    ASSERT_EQ(finished.count(), 1);
    const auto result = qvariant_cast<UpdateService::Result>(finished.at(0).at(0));
    EXPECT_EQ(result.error, UpdateService::Error::NetworkFailure);
    EXPECT_FALSE(result.release.has_value());
    EXPECT_GT(network.bytesRead, 0);
}

TEST(UpdateServiceTests, SupersededLocalFailureCannotCompleteAfterNewHttpsCheck)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    UpdateService service(&network, {{QStringLiteral("release-2026"), key.publicKey}},
                          QStringLiteral("3.1.0-modernized"));
    QSignalSpy finished(&service, &UpdateService::checkFinished);
    const QDateTime now = QDateTime::fromString(
        QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate);

    service.check(QUrl(QStringLiteral("http://insecure.example/manifest.json")), now);
    service.check(QUrl(QStringLiteral(
        "https://updates.input-leap.example/stable/manifest.json")), now);
    QEventLoop loop;
    QTimer::singleShot(50, &loop, &QEventLoop::quit);
    loop.exec();

    ASSERT_EQ(finished.count(), 1);
    const auto result = qvariant_cast<UpdateService::Result>(finished.at(0).at(0));
    EXPECT_EQ(result.error, UpdateService::Error::None);
    EXPECT_TRUE(result.updateAvailable);
}

TEST(UpdateServiceTests, ProductionTrustAnchorIsPinnedToModernizedStableEndpoint)
{
    const UpdateTrustConfig config = UpdateTrustConfig::production();

    EXPECT_EQ(config.manifestUrl,
              QUrl(QStringLiteral("https://raw.githubusercontent.com/tisterlingcorp-dev/"
                                  "inputleap-modernized/master/updates/stable/manifest.json")));
    EXPECT_EQ(config.minimumValidSignatures, 2);
    ASSERT_EQ(config.trustedKeys.size(), 3);
    const auto key = config.trustedKeys.constFind(
        QStringLiteral("inputleap-modernized-release-2026-01"));
    ASSERT_NE(key, config.trustedKeys.constEnd());
    EXPECT_EQ(key->publicKey.size(), 32);
    EXPECT_EQ(key->publicKey.toHex(),
              QByteArrayLiteral("3bdcc40b918377b0e4468acac69df830b8f9f8e9f7701604202082d61cb7aca6"));
    EXPECT_EQ(config.trustedKeys.value(QStringLiteral("inputleap-modernized-release-2026-02")).publicKey.toHex(),
              QByteArrayLiteral("a0796391ac0378562fa81f24b35ed4bafbcd2b32e28b1018b6295ebc6776036e"));
    EXPECT_EQ(config.trustedKeys.value(QStringLiteral("inputleap-modernized-release-2026-03")).publicKey.toHex(),
              QByteArrayLiteral("f5a9f310b136d579b57d7a4c5540952f7012af94491e5925aa31126c423c2bd0"));
    EXPECT_FALSE(key->revoked);
    const QDateTime auditTime = QDateTime::fromString(
        QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate);
    int activeKeys = 0;
    for (const auto& trusted : config.trustedKeys) {
        if (!trusted.revoked && trusted.notBeforeUtc <= auditTime &&
            auditTime < trusted.notAfterUtc)
            ++activeKeys;
    }
    EXPECT_EQ(activeKeys, 3);
}

TEST(UpdateServiceTests, ProductionAnchorVerifiesOfflineSignerFixture)
{
    QFile fixture(QStringLiteral(UPDATE_TEST_FIXTURE_DIR "/signed-update-manifest-v2.json"));
    ASSERT_TRUE(fixture.open(QIODevice::ReadOnly));
    const UpdateTrustConfig config = UpdateTrustConfig::production();

    const auto result = UpdateService::evaluate(
        fixture.readAll(), config.manifestUrl, QStringLiteral("3.1.0-modernized"),
        config.trustedKeys,
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate),
        config.minimumValidSignatures);

    ASSERT_EQ(result.error, UpdateService::Error::None);
    ASSERT_TRUE(result.release.has_value());
    EXPECT_TRUE(result.updateAvailable);
    EXPECT_EQ(result.release->version, QStringLiteral("3.2.0"));
    EXPECT_EQ(result.release->size, quint64(32));
}

TEST(UpdateServiceTests, RejectsTamperedPayloadBeforeExposingRelease)
{
    const SigningKey key = testSigningKey();
    QJsonObject outer = QJsonDocument::fromJson(envelope(releasePayload(), key)).object();
    QByteArray payload = QByteArray::fromBase64(
        outer.value(QStringLiteral("payload")).toString().toLatin1(),
        QByteArray::Base64UrlEncoding);
    payload[payload.size() - 2] = payload.at(payload.size() - 2) == '0' ? '1' : '0';
    outer.insert(QStringLiteral("payload"), QString::fromLatin1(
        payload.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));

    const auto result = UpdateService::evaluate(
        QJsonDocument(outer).toJson(QJsonDocument::Compact),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    EXPECT_EQ(result.error, UpdateService::Error::InvalidSignature);
    EXPECT_FALSE(result.release.has_value());
}

TEST(UpdateServiceTests, RejectsNonCanonicalOuterEnvelope)
{
    const SigningKey key = testSigningKey();
    QByteArray nonCanonical = envelope(releasePayload(), key);
    nonCanonical.insert(1, ' ');

    const auto result = UpdateService::evaluate(
        nonCanonical,
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    EXPECT_EQ(result.error, UpdateService::Error::MalformedEnvelope);
    EXPECT_FALSE(result.release.has_value());
}

TEST(UpdateServiceTests, RejectsNonCanonicalBase64UrlSpelling)
{
    const SigningKey key = testSigningKey();
    QJsonDocument document = QJsonDocument::fromJson(envelope(releasePayload(), key));
    ASSERT_TRUE(document.isObject());
    QJsonObject object = document.object();
    object.insert(QStringLiteral("payload"),
                  object.value(QStringLiteral("payload")).toString() + QLatin1Char('='));
    const QByteArray alternative = QJsonDocument(object).toJson(QJsonDocument::Compact);

    const auto result = UpdateService::evaluate(
        alternative,
        QUrl(QStringLiteral("https://updates.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));

    EXPECT_EQ(result.error, UpdateService::Error::MalformedEnvelope);
    EXPECT_FALSE(result.release.has_value());
}

TEST(UpdateServiceTests, RejectsUnknownSigningKey)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayload(), key),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"), {},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    EXPECT_EQ(result.error, UpdateService::Error::UnknownSigningKey);
}

TEST(UpdateServiceTests, RejectsExpiredSignedManifest)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayload(), key),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-26T05:00:01Z"), Qt::ISODate));
    EXPECT_EQ(result.error, UpdateService::Error::ExpiredManifest);
}

TEST(UpdateServiceTests, RejectsSignedNonStableChannel)
{
    const SigningKey key = testSigningKey();
    const QByteArray payload = releasePayloadWith([](QJsonObject& object) {
        object.insert(QStringLiteral("channel"), QStringLiteral("beta"));
    });
    const auto result = UpdateService::evaluate(
        envelope(payload, key),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    EXPECT_EQ(result.error, UpdateService::Error::UnsupportedChannel);
}

TEST(UpdateServiceTests, RejectsHttpManifestSourceBeforeSignatureEvaluation)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayload(), key),
        QUrl(QStringLiteral("http://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.1.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    EXPECT_EQ(result.error, UpdateService::Error::InsecureSource);
}

TEST(UpdateServiceTests, EqualStableVersionDoesNotOfferAnUpdate)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayload(), key),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.2.0"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    EXPECT_EQ(result.error, UpdateService::Error::None);
    EXPECT_FALSE(result.updateAvailable);
}

TEST(UpdateServiceTests, MatchingStableVersionReplacesModernizedPrerelease)
{
    const SigningKey key = testSigningKey();
    const auto result = UpdateService::evaluate(
        envelope(releasePayload(), key),
        QUrl(QStringLiteral("https://updates.input-leap.example/manifest.json")),
        QStringLiteral("3.2.0-modernized"),
        {{QStringLiteral("release-2026"), key.publicKey}},
        QDateTime::fromString(QStringLiteral("2026-07-19T06:00:00Z"), Qt::ISODate));
    EXPECT_EQ(result.error, UpdateService::Error::None);
    EXPECT_TRUE(result.updateAvailable);
}

TEST(UpdateReplayStoreTests, PersistsNewestManifestAndRejectsOlderReplay)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    UpdateService::Release newest{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    UpdateService::Release older = newest;
    older.version = QStringLiteral("3.2.0");
    older.sha256 = QByteArray(32, '\x22');
    older.issuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-19T05:00:00Z"), Qt::ISODate);

    {
        UpdateReplayStore store(path, replayCredentialStore(credentials),
                            path + QStringLiteral(".anchor"));
        EXPECT_EQ(store.accept(newest), UpdateReplayStore::Decision::Accepted);
    }
    UpdateReplayStore reopened(path, replayCredentialStore(credentials),
                               path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(older), UpdateReplayStore::Decision::Replayed);
    EXPECT_EQ(reopened.accept(newest), UpdateReplayStore::Decision::Accepted);
}

TEST(UpdateReplayStoreTests, DeletedIniCannotResetCredentialBackedHighWaterMark)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    UpdateService::Release newest{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    UpdateService::Release older = newest;
    older.version = QStringLiteral("3.2.0");
    older.sha256 = QByteArray(32, '\x22');
    older.issuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-19T05:00:00Z"), Qt::ISODate);
    UpdateReplayStore store(path, replayCredentialStore(credentials),
                            path + QStringLiteral(".anchor"));
    ASSERT_EQ(store.accept(newest), UpdateReplayStore::Decision::Accepted);
    ASSERT_TRUE(QFile::remove(path));

    UpdateReplayStore reopened(path, replayCredentialStore(credentials),
                               path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(older), UpdateReplayStore::Decision::Replayed);
}

TEST(UpdateReplayStoreTests, MissingCredentialStateWithTombstoneFailsClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    UpdateService::Release release{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    UpdateReplayStore store(path, replayCredentialStore(credentials),
                            path + QStringLiteral(".anchor"));
    ASSERT_EQ(store.accept(release), UpdateReplayStore::Decision::Accepted);
    credentials.clear();

    UpdateReplayStore reopened(path, replayCredentialStore(credentials),
                               path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(release), UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateReplayStoreTests, FirstInitializationResumesAfterStateWriteFailure)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    bool failStateWrite = true;
    const auto makeStore = [&] {
        return SecureCredentialStore(
            [&credentials](const QString& account) -> SecureCredentialStore::ReadResult {
                const auto found = credentials.constFind(account);
                return found == credentials.cend()
                    ? SecureCredentialStore::ReadResult::notFound()
                    : SecureCredentialStore::ReadResult::found(*found);
            },
            [&credentials, &failStateWrite](const QString& account,
                                             const QByteArray& value) {
                if (failStateWrite && account.contains(QStringLiteral("/state/")))
                    return false;
                credentials.insert(account, value);
                return true;
            },
            [&credentials](const QString& account) {
                credentials.remove(account);
                return true;
            });
    };
    const UpdateService::Release release{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};

    UpdateReplayStore interrupted(path, makeStore(), path + QStringLiteral(".anchor"));
    EXPECT_EQ(interrupted.accept(release),
              UpdateReplayStore::Decision::PersistenceFailure);
    failStateWrite = false;

    UpdateReplayStore reopened(path, makeStore(), path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(release), UpdateReplayStore::Decision::Accepted);
}

TEST(UpdateReplayStoreTests, UnexpectedAnchorGroupsCannotBecomeFreshState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    const QString anchorPath = path + QStringLiteral(".anchor");
    QHash<QString, QByteArray> credentials;
    const UpdateService::Release release{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    UpdateReplayStore store(path, replayCredentialStore(credentials), anchorPath);
    ASSERT_EQ(store.accept(release), UpdateReplayStore::Decision::Accepted);
    credentials.clear();
    ASSERT_TRUE(QFile::remove(path));
    QSettings anchor(anchorPath, QSettings::IniFormat);
    anchor.beginGroup(QStringLiteral("SecureUpdateReplay/v3/unexpected"));
    anchor.setValue(QStringLiteral("residue"), true);
    anchor.endGroup();
    anchor.sync();
    ASSERT_EQ(anchor.status(), QSettings::NoError);
    UpdateReplayStore reopened(path, replayCredentialStore(credentials), anchorPath);
    EXPECT_EQ(reopened.accept(release), UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateReplayStoreTests, LegacyV2MarkerWithoutAuthenticatedStateFailsClosed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    const QString anchorPath = path + QStringLiteral(".anchor");
    QSettings anchor(anchorPath, QSettings::IniFormat);
    anchor.setValue(QStringLiteral("SecureUpdateReplay/v2/initialized"), true);
    anchor.sync();
    ASSERT_EQ(anchor.status(), QSettings::NoError);
    QHash<QString, QByteArray> credentials;
    const UpdateService::Release release{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    UpdateReplayStore store(path, replayCredentialStore(credentials), anchorPath);
    EXPECT_EQ(store.accept(release), UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateReplayStoreTests, AuthenticatedStateOneGenerationAheadRepairsLaggingAnchor)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    const QString anchorPath = path + QStringLiteral(".anchor");
    QHash<QString, QByteArray> credentials;
    UpdateService::Release first{
        QStringLiteral("stable"), QStringLiteral("3.2.0"), quint64(100),
        QStringLiteral("Primeira"), QUrl(QStringLiteral("https://updates.example/a.exe")),
        QByteArray(32, '\x22'),
        QDateTime::fromString(QStringLiteral("2026-07-19T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-26T05:00:00Z"), Qt::ISODate)};
    UpdateService::Release second = first;
    second.version = QStringLiteral("3.3.0");
    second.sha256 = QByteArray(32, '\x33');
    second.issuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate);
    second.expiresAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate);

    UpdateReplayStore store(path, replayCredentialStore(credentials), anchorPath);
    ASSERT_EQ(store.accept(first), UpdateReplayStore::Decision::Accepted);
    QString markerAccount;
    for (auto it = credentials.cbegin(); it != credentials.cend(); ++it) {
        if (it.key().contains(QStringLiteral("/init/"))) {
            markerAccount = it.key();
            break;
        }
    }
    ASSERT_FALSE(markerAccount.isEmpty());
    const QByteArray firstMarker = credentials.value(markerAccount);
    QFile anchorFile(anchorPath);
    ASSERT_TRUE(anchorFile.open(QIODevice::ReadOnly));
    const QByteArray firstAnchor = anchorFile.readAll();
    anchorFile.close();
    ASSERT_FALSE(firstAnchor.isEmpty());
    ASSERT_EQ(store.accept(second), UpdateReplayStore::Decision::Accepted);
    ASSERT_TRUE(anchorFile.open(QIODevice::WriteOnly | QIODevice::Truncate));
    ASSERT_EQ(anchorFile.write(firstAnchor), firstAnchor.size());
    anchorFile.close();
    credentials[markerAccount] = firstMarker;

    UpdateReplayStore reopened(path, replayCredentialStore(credentials), anchorPath);
    EXPECT_EQ(reopened.accept(second), UpdateReplayStore::Decision::Accepted);
}

TEST(UpdateReplayStoreTests, AuthenticatedStateRepairsPartiallyPublishedAnchor)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    const QString anchorPath = path + QStringLiteral(".anchor");
    QHash<QString, QByteArray> credentials;
    UpdateService::Release first{
        QStringLiteral("stable"), QStringLiteral("3.2.0"), quint64(100),
        QStringLiteral("Primeira"), QUrl(QStringLiteral("https://updates.example/a.exe")),
        QByteArray(32, '\x22'),
        QDateTime::fromString(QStringLiteral("2026-07-19T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-26T05:00:00Z"), Qt::ISODate)};
    UpdateService::Release second = first;
    second.version = QStringLiteral("3.3.0");
    second.sha256 = QByteArray(32, '\x33');
    second.issuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate);
    second.expiresAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate);

    UpdateReplayStore store(path, replayCredentialStore(credentials), anchorPath);
    ASSERT_EQ(store.accept(first), UpdateReplayStore::Decision::Accepted);
    QString markerAccount;
    for (auto it = credentials.cbegin(); it != credentials.cend(); ++it) {
        if (it.key().contains(QStringLiteral("/init/"))) {
            markerAccount = it.key();
            break;
        }
    }
    ASSERT_FALSE(markerAccount.isEmpty());
    const QString anchorGroup = QStringLiteral("SecureUpdateReplay/v3/%1")
                                    .arg(markerAccount.section(QLatin1Char('/'), -1));
    QSettings anchor(anchorPath, QSettings::IniFormat);
    anchor.beginGroup(anchorGroup);
    const QString firstDigest = anchor.value(QStringLiteral("stateSha256")).toString();
    anchor.endGroup();
    ASSERT_EQ(firstDigest.size(), 64);
    ASSERT_EQ(store.accept(second), UpdateReplayStore::Decision::Accepted);

    credentials[markerAccount] = QByteArrayLiteral("ILUR5:complete:1:") +
        firstDigest.toLatin1();
    anchor.beginGroup(anchorGroup);
    anchor.remove(QString());
    anchor.setValue(QStringLiteral("schema"), 4);
    anchor.endGroup();
    anchor.sync();
    ASSERT_EQ(anchor.status(), QSettings::NoError);

    UpdateReplayStore reopened(path, replayCredentialStore(credentials), anchorPath);
    ASSERT_EQ(reopened.accept(second), UpdateReplayStore::Decision::Accepted);

    // QSettings::NativeFormat publishes the fields separately.  A crash can
    // therefore leave a formally valid hybrid: the new generation was
    // written, while the old digest is still present.  The authenticated
    // marker and state constrain both endpoints of the interrupted N -> N+1
    // transition, so this exact hybrid must be repairable.
    credentials[markerAccount] = QByteArrayLiteral("ILUR5:complete:1:") +
        firstDigest.toLatin1();
    anchor.beginGroup(anchorGroup);
    anchor.remove(QString());
    anchor.setValue(QStringLiteral("generation"), qulonglong(2));
    anchor.setValue(QStringLiteral("initialized"), true);
    anchor.setValue(QStringLiteral("schema"), 4);
    anchor.setValue(QStringLiteral("stateSha256"), firstDigest);
    anchor.endGroup();
    anchor.sync();
    ASSERT_EQ(anchor.status(), QSettings::NoError);

    UpdateReplayStore hybrid(path, replayCredentialStore(credentials), anchorPath);
    ASSERT_EQ(hybrid.accept(second), UpdateReplayStore::Decision::Accepted);

    // The legacy marker contains no authenticated generation/digest endpoint,
    // so it cannot authorize a K-1 -> K repair from attacker-controlled
    // QSettings even when the restored K state has a valid HMAC.
    credentials[markerAccount] = QByteArrayLiteral("ILUR4:complete");
    anchor.beginGroup(anchorGroup);
    anchor.remove(QString());
    anchor.setValue(QStringLiteral("generation"), qulonglong(1));
    anchor.setValue(QStringLiteral("initialized"), true);
    anchor.setValue(QStringLiteral("schema"), 3);
    anchor.setValue(QStringLiteral("stateSha256"), QString(64, QLatin1Char('a')));
    anchor.endGroup();
    anchor.sync();
    ASSERT_EQ(anchor.status(), QSettings::NoError);

    UpdateReplayStore legacyRollback(path, replayCredentialStore(credentials), anchorPath);
    EXPECT_EQ(legacyRollback.accept(second),
              UpdateReplayStore::Decision::PersistenceFailure);

    anchor.beginGroup(anchorGroup);
    anchor.remove(QString());
    anchor.setValue(QStringLiteral("schema"), 4);
    anchor.endGroup();
    anchor.sync();
    ASSERT_EQ(anchor.status(), QSettings::NoError);

    UpdateReplayStore tampered(path, replayCredentialStore(credentials), anchorPath);
    EXPECT_EQ(tampered.accept(second),
              UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateReplayStoreTests, TamperedCredentialStateFailsAuthentication)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    UpdateService::Release release{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    UpdateReplayStore store(path, replayCredentialStore(credentials),
                            path + QStringLiteral(".anchor"));
    ASSERT_EQ(store.accept(release), UpdateReplayStore::Decision::Accepted);
    ASSERT_EQ(credentials.size(), 3);
    bool tamperedState = false;
    for (auto it = credentials.begin(); it != credentials.end(); ++it) {
        if (it.key().contains(QStringLiteral("/state/"))) {
            it.value().replace(0, 1, QByteArrayLiteral("X"));
            tamperedState = true;
        }
    }
    ASSERT_TRUE(tamperedState);

    UpdateReplayStore reopened(path, replayCredentialStore(credentials),
                               path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(release), UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateReplayStoreTests, AuthenticatedOldStateSnapshotCannotBeRestored)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    UpdateService::Release first{
        QStringLiteral("stable"), QStringLiteral("3.2.0"), quint64(100),
        QStringLiteral("Primeira"), QUrl(QStringLiteral("https://updates.example/a.exe")),
        QByteArray(32, '\x22'),
        QDateTime::fromString(QStringLiteral("2026-07-19T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-26T05:00:00Z"), Qt::ISODate)};
    UpdateService::Release second = first;
    second.version = QStringLiteral("3.3.0");
    second.sha256 = QByteArray(32, '\x33');
    second.issuedAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate);
    second.expiresAtUtc = QDateTime::fromString(
        QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate);
    UpdateReplayStore store(path, replayCredentialStore(credentials),
                            path + QStringLiteral(".anchor"));
    ASSERT_EQ(store.accept(first), UpdateReplayStore::Decision::Accepted);
    QByteArray oldState;
    QString stateAccount;
    for (auto it = credentials.cbegin(); it != credentials.cend(); ++it) {
        if (it.key().contains(QStringLiteral("/state/"))) {
            stateAccount = it.key();
            oldState = it.value();
        }
    }
    ASSERT_FALSE(stateAccount.isEmpty());
    ASSERT_EQ(store.accept(second), UpdateReplayStore::Decision::Accepted);
    credentials.insert(stateAccount, oldState);

    UpdateReplayStore reopened(path, replayCredentialStore(credentials),
                               path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(first), UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateReplayStoreTests, CredentialLossAndPrimaryIniDeletionCannotLookLikeFirstUse)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString path = directory.filePath(QStringLiteral("update-replay.ini"));
    QHash<QString, QByteArray> credentials;
    UpdateService::Release release{
        QStringLiteral("stable"), QStringLiteral("3.2.0"), quint64(100),
        QStringLiteral("Primeira"), QUrl(QStringLiteral("https://updates.example/a.exe")),
        QByteArray(32, '\x22'),
        QDateTime::fromString(QStringLiteral("2026-07-19T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-26T05:00:00Z"), Qt::ISODate)};
    UpdateReplayStore store(path, replayCredentialStore(credentials),
                            path + QStringLiteral(".anchor"));
    ASSERT_EQ(store.accept(release), UpdateReplayStore::Decision::Accepted);
    credentials.clear();
    ASSERT_TRUE(QFile::remove(path));

    UpdateReplayStore reopened(path, replayCredentialStore(credentials),
                               path + QStringLiteral(".anchor"));
    EXPECT_EQ(reopened.accept(release), UpdateReplayStore::Decision::PersistenceFailure);
}

TEST(UpdateServiceTests, PersistedNewerManifestBlocksOlderSignedNetworkReplay)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    QHash<QString, QByteArray> credentials;
    const QString replayPath = directory.filePath(QStringLiteral("update-replay.ini"));
    UpdateReplayStore store(replayPath, replayCredentialStore(credentials),
                            replayPath + QStringLiteral(".anchor"));
    UpdateService::Release newest{
        QStringLiteral("stable"), QStringLiteral("3.3.0"), quint64(100),
        QStringLiteral("Nova"), QUrl(QStringLiteral("https://updates.example/new.exe")),
        QByteArray(32, '\x33'),
        QDateTime::fromString(QStringLiteral("2026-07-20T05:00:00Z"), Qt::ISODate),
        QDateTime::fromString(QStringLiteral("2026-07-27T05:00:00Z"), Qt::ISODate)};
    ASSERT_EQ(store.accept(newest), UpdateReplayStore::Decision::Accepted);
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    UpdateService service(&network, {{QStringLiteral("release-2026"), key.publicKey}},
                          QStringLiteral("3.1.0-modernized"), nullptr, &store);
    QSignalSpy finished(&service, &UpdateService::checkFinished);

    service.check(QUrl(QStringLiteral(
                      "https://updates.input-leap.example/stable/manifest.json")),
                  QDateTime::fromString(QStringLiteral("2026-07-21T06:00:00Z"), Qt::ISODate));

    ASSERT_TRUE(finished.wait(1000));
    ASSERT_EQ(finished.count(), 1);
    const auto result = qvariant_cast<UpdateService::Result>(finished.at(0).at(0));
    EXPECT_EQ(result.error, UpdateService::Error::ReplayedManifest);
    EXPECT_FALSE(result.release.has_value());
}

TEST(UpdateServiceTests, RejectsUnexpectedHttpStatus)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    network.status = 503;
    const auto result = fetchResult(network, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->error, UpdateService::Error::HttpFailure);
}

TEST(UpdateServiceTests, ClassifiesHttpErrorBeforeQtNetworkError)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.status = 404;
    network.networkError = QNetworkReply::ContentNotFoundError;
    const auto notFound = fetchResult(network, key);
    ASSERT_TRUE(notFound.has_value());
    EXPECT_EQ(notFound->error, UpdateService::Error::HttpFailure);

    network.status = 0;
    network.networkError = QNetworkReply::HostNotFoundError;
    const auto offline = fetchResult(network, key);
    ASSERT_TRUE(offline.has_value());
    EXPECT_EQ(offline->error, UpdateService::Error::NetworkFailure);
}

TEST(UpdateServiceTests, RejectsUnexpectedManifestContentType)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    network.contentType = QStringLiteral("text/html");
    const auto result = fetchResult(network, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->error, UpdateService::Error::InvalidContentType);
}

TEST(UpdateServiceTests, RejectsRedirectedManifestFromAnotherOrigin)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = envelope(releasePayload(), key);
    network.finalUrl = QUrl(QStringLiteral("https://mirror.example/manifest.json"));
    const auto result = fetchResult(network, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->error, UpdateService::Error::InsecureSource);
}

TEST(UpdateServiceTests, AbortsManifestResponseAboveHardLimit)
{
    const SigningKey key = testSigningKey();
    FakeNetworkAccessManager network;
    network.response = QByteArray(UpdateService::MaxEnvelopeBytes * 4, 'x');
    const auto result = fetchResult(network, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->error, UpdateService::Error::ResponseTooLarge);
    EXPECT_LE(network.bytesRead, UpdateService::MaxEnvelopeBytes + 1);
}
