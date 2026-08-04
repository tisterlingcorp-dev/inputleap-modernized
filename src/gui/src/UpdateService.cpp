#include "UpdateService.h"
#include "RecoveryArtifactAuthenticator.h"

#include <QCryptographicHash>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>
#include <QSettings>
#include <QTimer>

#include <openssl/evp.h>

#include <array>
#include <cmath>
#include <memory>
#include <utility>

namespace {

UpdateService::Result failure(UpdateService::Error error, const QString& detail)
{
    UpdateService::Result result;
    result.error = error;
    result.detail = detail;
    return result;
}

bool isHttpsUrl(const QUrl& url)
{
    return url.isValid() && url.scheme() == QStringLiteral("https") && !url.host().isEmpty() &&
           url.userInfo().isEmpty() && url.fragment().isEmpty();
}

std::optional<QByteArray> decodeBase64Url(const QJsonValue& value)
{
    if (!value.isString())
        return std::nullopt;
    const QByteArray encoded = value.toString().toLatin1();
    if (encoded.isEmpty() || encoded.contains('='))
        return std::nullopt;
    const auto decoded = QByteArray::fromBase64Encoding(
        encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded)
        return std::nullopt;
    if (decoded.decoded.toBase64(QByteArray::Base64UrlEncoding |
                                 QByteArray::OmitTrailingEquals) != encoded)
        return std::nullopt;
    return decoded.decoded;
}

bool verifyEd25519(const QByteArray& publicKey, const QByteArray& payload,
                   const QByteArray& signature)
{
    if (publicKey.size() != 32 || signature.size() != 64)
        return false;
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(publicKey.constData()),
        size_t(publicKey.size()));
    if (key == nullptr)
        return false;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const bool valid = context != nullptr &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
        EVP_DigestVerify(context,
                         reinterpret_cast<const unsigned char*>(signature.constData()),
                         size_t(signature.size()),
                         reinterpret_cast<const unsigned char*>(payload.constData()),
                         size_t(payload.size())) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return valid;
}

bool isTrustedKeyActive(const UpdateService::TrustedKey& key, const QDateTime& nowUtc)
{
    return key.publicKey.size() == 32 && !key.revoked &&
           (!key.notBeforeUtc.isValid() || nowUtc >= key.notBeforeUtc.toUTC()) &&
           (!key.notAfterUtc.isValid() || nowUtc < key.notAfterUtc.toUTC());
}

std::optional<std::array<quint32, 3>> parseVersion(const QString& value, bool stableOnly)
{
    static const QRegularExpression stable(
        QStringLiteral("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"));
    static const QRegularExpression local(
        QStringLiteral("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$"));
    const auto match = (stableOnly ? stable : local).match(value);
    if (!match.hasMatch())
        return std::nullopt;
    std::array<quint32, 3> version{};
    for (int index = 0; index < 3; ++index) {
        bool ok = false;
        const quint64 component = match.captured(index + 1).toULongLong(&ok);
        if (!ok || component > 999999)
            return std::nullopt;
        version[size_t(index)] = quint32(component);
    }
    return version;
}

bool containsUnsafeText(const QString& text)
{
    for (const QChar character : text) {
        const ushort value = character.unicode();
        if ((value < 0x20 && value != '\n' && value != '\r' && value != '\t') || value == 0x7f)
            return true;
    }
    return false;
}

std::optional<QDateTime> strictUtcTime(const QJsonValue& value)
{
    if (!value.isString())
        return std::nullopt;
    static const QRegularExpression format(
        QStringLiteral("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"));
    const QString text = value.toString();
    if (!format.match(text).hasMatch())
        return std::nullopt;
    const QDateTime parsed = QDateTime::fromString(text, Qt::ISODate);
    if (!parsed.isValid() || parsed.timeSpec() != Qt::UTC)
        return std::nullopt;
    return parsed;
}

} // namespace

UpdateService::Result UpdateService::evaluate(const QByteArray& envelope,
                                              const QUrl& manifestUrl,
                                              const QString& currentVersion,
                                              const TrustedKeys& trustedKeys,
                                              const QDateTime& nowUtc,
                                              int minimumValidSignatures)
{
    if (!isHttpsUrl(manifestUrl))
        return failure(Error::InsecureSource, QStringLiteral("manifest source must be HTTPS"));
    if (envelope.isEmpty() || envelope.size() > MaxEnvelopeBytes)
        return failure(Error::EnvelopeTooLarge, QStringLiteral("manifest envelope size is invalid"));

    QJsonParseError envelopeParse;
    const QJsonDocument envelopeDocument = QJsonDocument::fromJson(envelope, &envelopeParse);
    if (envelopeParse.error != QJsonParseError::NoError || !envelopeDocument.isObject())
        return failure(Error::MalformedEnvelope, QStringLiteral("manifest envelope is not valid JSON"));
    const QJsonObject outer = envelopeDocument.object();
    if (QJsonDocument(outer).toJson(QJsonDocument::Compact) != envelope)
        return failure(Error::MalformedEnvelope,
                       QStringLiteral("manifest envelope is not canonical"));
    if (!outer.value(QStringLiteral("schema")).isDouble() || minimumValidSignatures < 1)
        return failure(Error::UnsupportedSchema, QStringLiteral("manifest envelope schema is unsupported"));

    static const QRegularExpression keyIdFormat(QStringLiteral("^[A-Za-z0-9._-]{1,64}$"));
    const auto payload = decodeBase64Url(outer.value(QStringLiteral("payload")));
    if (!payload || payload->isEmpty() || payload->size() > MaxPayloadBytes)
        return failure(Error::MalformedEnvelope, QStringLiteral("signed manifest encoding is invalid"));

    const int envelopeSchema = outer.value(QStringLiteral("schema")).toInt(-1);
    int validSignatures = 0;
    if (envelopeSchema == 1) {
        if (minimumValidSignatures != 1 || outer.size() != 4 ||
            !outer.value(QStringLiteral("keyId")).isString())
            return failure(Error::UnsupportedSchema, QStringLiteral("manifest envelope schema is unsupported"));
        const QString keyId = outer.value(QStringLiteral("keyId")).toString();
        if (!keyIdFormat.match(keyId).hasMatch())
            return failure(Error::MalformedEnvelope, QStringLiteral("signing key id is invalid"));
        const auto key = trustedKeys.constFind(keyId);
        if (key == trustedKeys.constEnd() || !isTrustedKeyActive(*key, nowUtc))
            return failure(Error::UnknownSigningKey, QStringLiteral("manifest signing key is not trusted"));
        const auto signature = decodeBase64Url(outer.value(QStringLiteral("signature")));
        if (!signature || signature->size() != 64)
            return failure(Error::MalformedEnvelope, QStringLiteral("signed manifest encoding is invalid"));
        validSignatures = verifyEd25519(key->publicKey, *payload, *signature) ? 1 : 0;
    }
    else if (envelopeSchema == 2) {
        if (outer.size() != 3 || !outer.value(QStringLiteral("signatures")).isArray())
            return failure(Error::UnsupportedSchema, QStringLiteral("manifest envelope schema is unsupported"));
        const QJsonArray signatures = outer.value(QStringLiteral("signatures")).toArray();
        if (signatures.isEmpty() || signatures.size() > 16)
            return failure(Error::MalformedEnvelope, QStringLiteral("manifest signature set is invalid"));
        QString previousKeyId;
        for (const QJsonValue& value : signatures) {
            if (!value.isObject())
                return failure(Error::MalformedEnvelope, QStringLiteral("manifest signature set is invalid"));
            const QJsonObject item = value.toObject();
            if (item.size() != 2 || !item.value(QStringLiteral("keyId")).isString())
                return failure(Error::MalformedEnvelope, QStringLiteral("manifest signature set is invalid"));
            const QString keyId = item.value(QStringLiteral("keyId")).toString();
            if (!keyIdFormat.match(keyId).hasMatch() ||
                (!previousKeyId.isEmpty() && keyId <= previousKeyId))
                return failure(Error::MalformedEnvelope, QStringLiteral("manifest signature ids are invalid"));
            previousKeyId = keyId;
            const auto signature = decodeBase64Url(item.value(QStringLiteral("signature")));
            if (!signature || signature->size() != 64)
                return failure(Error::MalformedEnvelope, QStringLiteral("manifest signature encoding is invalid"));
            const auto key = trustedKeys.constFind(keyId);
            if (key != trustedKeys.constEnd() && isTrustedKeyActive(*key, nowUtc) &&
                verifyEd25519(key->publicKey, *payload, *signature))
                ++validSignatures;
        }
    }
    else {
        return failure(Error::UnsupportedSchema, QStringLiteral("manifest envelope schema is unsupported"));
    }
    if (validSignatures < minimumValidSignatures)
        return failure(Error::InvalidSignature, QStringLiteral("manifest signature threshold was not met"));

    QJsonParseError payloadParse;
    const QJsonDocument payloadDocument = QJsonDocument::fromJson(*payload, &payloadParse);
    if (payloadParse.error != QJsonParseError::NoError || !payloadDocument.isObject())
        return failure(Error::InvalidManifest, QStringLiteral("signed manifest payload is invalid"));
    const QJsonObject object = payloadDocument.object();
    if (QJsonDocument(object).toJson(QJsonDocument::Compact) != *payload)
        return failure(Error::InvalidManifest,
                       QStringLiteral("signed manifest payload is not canonical"));
    if (!object.value(QStringLiteral("schema")).isDouble())
        return failure(Error::UnsupportedSchema, QStringLiteral("signed manifest schema is unsupported"));
    const int payloadSchema = object.value(QStringLiteral("schema")).toInt(-1);
    if ((payloadSchema != 1 && payloadSchema != 2) ||
        object.size() != (payloadSchema == 1 ? 9 : 11))
        return failure(Error::UnsupportedSchema, QStringLiteral("signed manifest schema is unsupported"));

    Release release;
    if (payloadSchema == 2) {
        if (!object.value(QStringLiteral("packageType")).isString() ||
            object.value(QStringLiteral("packageType")).toString() != QStringLiteral("windows-msi"))
            return failure(Error::InvalidManifest, QStringLiteral("release package type is invalid"));
        release.packageType = PackageType::WindowsMsi;
#if defined(Q_OS_WIN)
        release.installable = true;
#else
        release.installable = false;
#endif
        if (!object.value(QStringLiteral("authenticodeSignerSha256")).isString())
            return failure(Error::InvalidManifest,
                           QStringLiteral("Authenticode signer digest is invalid"));
        const QByteArray signerHex = object.value(
            QStringLiteral("authenticodeSignerSha256")).toString().toLatin1();
        static const QRegularExpression signerDigestFormat(
            QStringLiteral("^[0-9a-f]{64}$"));
        if (!signerDigestFormat.match(QString::fromLatin1(signerHex)).hasMatch())
            return failure(Error::InvalidManifest,
                           QStringLiteral("Authenticode signer digest is invalid"));
        release.authenticodeSignerSha256 = QByteArray::fromHex(signerHex);
    }
    if (!object.value(QStringLiteral("channel")).isString())
        return failure(Error::InvalidManifest, QStringLiteral("release channel is invalid"));
    release.channel = object.value(QStringLiteral("channel")).toString();
    if (release.channel != QStringLiteral("stable"))
        return failure(Error::UnsupportedChannel, QStringLiteral("only the stable channel is accepted"));

    if (!object.value(QStringLiteral("version")).isString())
        return failure(Error::InvalidManifest, QStringLiteral("release version is invalid"));
    release.version = object.value(QStringLiteral("version")).toString();
    const auto remoteVersion = parseVersion(release.version, true);
    const auto installedVersion = parseVersion(currentVersion, false);
    if (!remoteVersion)
        return failure(Error::InvalidManifest, QStringLiteral("release version is invalid"));
    if (!installedVersion)
        return failure(Error::InvalidCurrentVersion, QStringLiteral("installed version is invalid"));

    const QJsonValue sizeValue = object.value(QStringLiteral("size"));
    if (!sizeValue.isDouble() || !std::isfinite(sizeValue.toDouble()) ||
        std::floor(sizeValue.toDouble()) != sizeValue.toDouble() || sizeValue.toDouble() < 1.0 ||
        sizeValue.toDouble() > double(MaxPackageBytes))
        return failure(Error::InvalidManifest, QStringLiteral("release size is invalid"));
    release.size = quint64(sizeValue.toDouble());

    if (!object.value(QStringLiteral("notes")).isString())
        return failure(Error::InvalidManifest, QStringLiteral("release notes are invalid"));
    release.notes = object.value(QStringLiteral("notes")).toString();
    if (release.notes.isEmpty() || release.notes.size() > 16384 ||
        release.notes.toUtf8().size() > 32768 || containsUnsafeText(release.notes))
        return failure(Error::InvalidManifest, QStringLiteral("release notes are invalid"));

    if (!object.value(QStringLiteral("packageUrl")).isString())
        return failure(Error::InvalidManifest, QStringLiteral("package URL is invalid"));
    release.packageUrl = QUrl(object.value(QStringLiteral("packageUrl")).toString(), QUrl::StrictMode);
    if (!isHttpsUrl(release.packageUrl) || release.packageUrl.toString().size() > 2048)
        return failure(Error::InvalidManifest, QStringLiteral("package URL is invalid"));
    if (payloadSchema == 2 && !release.packageUrl.path().endsWith(QStringLiteral(".msi"), Qt::CaseInsensitive))
        return failure(Error::InvalidManifest, QStringLiteral("Windows MSI package URL is invalid"));

    if (!object.value(QStringLiteral("sha256")).isString())
        return failure(Error::InvalidManifest, QStringLiteral("package digest is invalid"));
    const QByteArray digestHex = object.value(QStringLiteral("sha256")).toString().toLatin1();
    static const QRegularExpression digestFormat(QStringLiteral("^[0-9a-f]{64}$"));
    if (!digestFormat.match(QString::fromLatin1(digestHex)).hasMatch())
        return failure(Error::InvalidManifest, QStringLiteral("package digest is invalid"));
    release.sha256 = QByteArray::fromHex(digestHex);

    const auto issued = strictUtcTime(object.value(QStringLiteral("issuedAtUtc")));
    const auto expires = strictUtcTime(object.value(QStringLiteral("expiresAtUtc")));
    const QDateTime effectiveNow = nowUtc.toUTC();
    if (!effectiveNow.isValid() || !issued || !expires || *expires <= *issued ||
        issued->secsTo(*expires) > 30 * 24 * 60 * 60)
        return failure(Error::InvalidManifest, QStringLiteral("manifest validity interval is invalid"));
    if (*issued > effectiveNow.addSecs(5 * 60) || *expires <= effectiveNow)
        return failure(Error::ExpiredManifest, QStringLiteral("manifest is not currently valid"));
    release.issuedAtUtc = *issued;
    release.expiresAtUtc = *expires;

    Result result;
    result.release = release;
    result.signedEnvelope = envelope;
    result.updateAvailable = *remoteVersion > *installedVersion ||
        (*remoteVersion == *installedVersion && currentVersion.contains(QLatin1Char('-')));
    return result;
}

UpdateService::UpdateService(QNetworkAccessManager* network,
                             TrustedKeys trustedKeys,
                             QString currentVersion,
                             QObject* parent,
                             UpdateReplayStore* replayStore,
                             int minimumValidSignatures,
                             int absoluteDeadlineMs)
    : QObject(parent),
      network_(network),
      replayStore_(replayStore),
      minimumValidSignatures_(minimumValidSignatures),
      absoluteDeadlineMs_(qMax(1, absoluteDeadlineMs)),
      trustedKeys_(std::move(trustedKeys)),
      currentVersion_(std::move(currentVersion))
{
    qRegisterMetaType<UpdateService::Result>();
    absoluteDeadline_.setSingleShot(true);
    connect(&absoluteDeadline_, &QTimer::timeout, this, [this] {
        QNetworkReply* const expired = reply_;
        if (expired == nullptr)
            return;
        disconnect(expired, nullptr, this, nullptr);
        reply_.clear();
        expired->abort();
        expired->deleteLater();
        response_.clear();
        responseTooLarge_ = false;
        Q_EMIT checkFinished(failure(
            Error::NetworkFailure, QStringLiteral("manifest request exceeded absolute deadline")));
    });
}

void UpdateService::check(const QUrl& manifestUrl, const QDateTime& nowUtc)
{
    const quint64 generation = ++generation_;
    absoluteDeadline_.stop();
    if (reply_) {
        disconnect(reply_, nullptr, this, nullptr);
        reply_->abort();
        reply_->deleteLater();
        reply_.clear();
    }
    response_.clear();
    responseTooLarge_ = false;
    manifestUrl_ = manifestUrl;
    evaluationTimeUtc_ = nowUtc;

    if (network_ == nullptr || !isHttpsUrl(manifestUrl)) {
        const Result result = failure(Error::InsecureSource,
                                      QStringLiteral("manifest source must be HTTPS"));
        QTimer::singleShot(0, this, [this, result, generation] {
            if (generation == generation_)
                Q_EMIT checkFinished(result);
        });
        return;
    }

    QNetworkRequest request(manifestUrl);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::SameOriginRedirectPolicy);
    request.setMaximumRedirectsAllowed(3);
    request.setTransferTimeout(15000);
    request.setRawHeader("Accept", "application/json");
    request.setRawHeader("User-Agent", "InputLeap-Secure-Update/1");
    reply_ = network_->get(request);
    absoluteDeadline_.start(absoluteDeadlineMs_);
    QNetworkReply* const current = reply_;
    connect(current, &QIODevice::readyRead, this, [this, current] {
        if (reply_ != current)
            return;
        readResponse(current);
    });
    connect(current, &QNetworkReply::finished, this,
            [this, current] { finishRequest(current); });
}

void UpdateService::readResponse(QNetworkReply* reply)
{
    if (responseTooLarge_ || reply_ != reply)
        return;
    const qsizetype remaining = MaxEnvelopeBytes - response_.size();
    response_.append(reply->read(remaining + 1));
    if (response_.size() > MaxEnvelopeBytes) {
        responseTooLarge_ = true;
        reply->abort();
    }
}

void UpdateService::finishRequest(QNetworkReply* reply)
{
    if (reply_ != reply)
        return;
    absoluteDeadline_.stop();
    readResponse(reply);

    Result result;
    if (responseTooLarge_ || response_.size() > MaxEnvelopeBytes) {
        result = failure(Error::ResponseTooLarge, QStringLiteral("manifest response is too large"));
    }
    else if (const int status = reply->attribute(
                 QNetworkRequest::HttpStatusCodeAttribute).toInt();
             status != 0 && status != 200) {
        result = failure(Error::HttpFailure,
                         QStringLiteral("manifest server returned HTTP %1").arg(status));
    }
    else if (reply->error() != QNetworkReply::NoError) {
        result = failure(Error::NetworkFailure, QStringLiteral("manifest request failed"));
    }
    else {
        const QString contentType = reply->header(QNetworkRequest::ContentTypeHeader)
                                        .toString().section(QLatin1Char(';'), 0, 0).trimmed().toLower();
        const QUrl finalUrl = reply->url();
        const bool sameOrigin = finalUrl.scheme() == manifestUrl_.scheme() &&
            finalUrl.host() == manifestUrl_.host() &&
            finalUrl.port(443) == manifestUrl_.port(443);
        if (!sameOrigin || !isHttpsUrl(finalUrl))
            result = failure(Error::InsecureSource,
                             QStringLiteral("manifest redirect changed origin"));
        else if (contentType != QStringLiteral("application/json"))
            result = failure(Error::InvalidContentType,
                             QStringLiteral("manifest response is not JSON"));
        else
            result = evaluate(response_, finalUrl, currentVersion_, trustedKeys_, evaluationTimeUtc_,
                              minimumValidSignatures_);
    }

    if (result.error == Error::None && result.release && replayStore_ != nullptr) {
        const auto decision = replayStore_->accept(*result.release);
        if (decision == UpdateReplayStore::Decision::Replayed)
            result = failure(Error::ReplayedManifest,
                             QStringLiteral("manifest is older than trusted update state"));
        else if (decision == UpdateReplayStore::Decision::PersistenceFailure)
            result = failure(Error::ReplayStateFailure,
                             QStringLiteral("trusted update state could not be verified"));
    }

    reply_.clear();
    reply->deleteLater();
    response_.clear();
    Q_EMIT checkFinished(result);
}

UpdateReplayStore::UpdateReplayStore(QString settingsPath,
                                     SecureCredentialStore credentialStore,
                                     QString anchorPath)
    : settingsPath_(std::move(settingsPath)),
      anchorPath_(std::move(anchorPath)),
      credentialStore_(std::move(credentialStore))
{
}

UpdateReplayStore::Decision UpdateReplayStore::accept(const UpdateService::Release& release)
{
    QLockFile lock(settingsPath_ + QStringLiteral(".update-replay.lock"));
    if (!lock.tryLock(5000) || !credentialStore_.available())
        return Decision::PersistenceFailure;

    const QByteArray scope = QCryptographicHash::hash(
        QFileInfo(settingsPath_).absoluteFilePath().toUtf8(),
        QCryptographicHash::Sha256).toHex();
    const QString keyAccount = QStringLiteral("InputLeap/secure-update-replay/v2/key/%1")
                                   .arg(QString::fromLatin1(scope));
    const QString stateAccount = QStringLiteral("InputLeap/secure-update-replay/v2/state/%1")
                                     .arg(QString::fromLatin1(scope));
    const QString markerAccount = QStringLiteral("InputLeap/secure-update-replay/v2/init/%1")
                                      .arg(QString::fromLatin1(scope));
    const QByteArray pendingMarker = QByteArrayLiteral("ILUR4:pending");
    const QByteArray completeMarker = QByteArrayLiteral("ILUR4:complete");

    std::unique_ptr<QSettings> anchorOwner;
    if (anchorPath_.isEmpty()) {
        anchorOwner = std::make_unique<QSettings>(
            QSettings::NativeFormat, QSettings::UserScope,
            QStringLiteral("InputLeap"), QStringLiteral("SecureUpdateReplay"));
    }
    else {
        anchorOwner = std::make_unique<QSettings>(anchorPath_, QSettings::IniFormat);
    }
    QSettings& anchor = *anchorOwner;
    anchor.sync();
    if (anchor.status() != QSettings::NoError)
        return Decision::PersistenceFailure;
    anchor.beginGroup(QStringLiteral("SecureUpdateReplay/v2"));
    const bool legacyMarkerPresent = anchor.contains(QStringLiteral("initialized")) ||
        !anchor.childGroups().isEmpty() || !anchor.childKeys().isEmpty();
    anchor.endGroup();
    const QString anchorGroup = QStringLiteral("SecureUpdateReplay/v3/%1")
                                    .arg(QString::fromLatin1(scope));
    anchor.beginGroup(QStringLiteral("SecureUpdateReplay/v3"));
    const QStringList v3GroupList = anchor.childGroups();
    const QSet<QString> v3Groups(v3GroupList.cbegin(), v3GroupList.cend());
    const bool unexpectedV3Groups = std::any_of(
        v3Groups.cbegin(), v3Groups.cend(), [&scope](const QString& group) {
            return group != QString::fromLatin1(scope);
        });
    anchor.endGroup();
    anchor.beginGroup(anchorGroup);
    const QStringList anchorKeys = anchor.childKeys();
    const QStringList anchorGroups = anchor.childGroups();
    const bool anchorMissing = anchorKeys.isEmpty() && anchorGroups.isEmpty() &&
        !unexpectedV3Groups;
    bool anchorMalformed = false;
    bool anchorValid = false;
    quint64 anchoredGeneration = 0;
    int anchoredSchema = 0;
    QByteArray anchoredStateDigest;
    if (!anchorMissing) {
        static const QSet<QString> expectedAnchorKeys{
            QStringLiteral("generation"), QStringLiteral("initialized"),
            QStringLiteral("schema"), QStringLiteral("stateSha256")};
        bool generationOk = false;
        bool schemaOk = false;
        anchoredGeneration = anchor.value(QStringLiteral("generation")).toULongLong(&generationOk);
        anchoredSchema = anchor.value(QStringLiteral("schema")).toInt(&schemaOk);
        const QString digestHex = anchor.value(QStringLiteral("stateSha256")).toString();
        static const QRegularExpression anchorDigestFormat(QStringLiteral("^[0-9a-f]{64}$"));
        if (unexpectedV3Groups || !anchorGroups.isEmpty() ||
            QSet<QString>(anchorKeys.cbegin(), anchorKeys.cend()) != expectedAnchorKeys ||
            !anchor.value(QStringLiteral("initialized")).toBool() ||
            !schemaOk || (anchoredSchema != 3 && anchoredSchema != 4) ||
            !generationOk || anchoredGeneration == 0 ||
            !anchorDigestFormat.match(digestHex).hasMatch()) {
            anchorMalformed = true;
        }
        else {
            anchoredStateDigest = QByteArray::fromHex(digestHex.toLatin1());
            anchorValid = true;
        }
    }
    anchor.endGroup();

    auto keyResult = credentialStore_.read(keyAccount);
    auto stateResult = credentialStore_.read(stateAccount);
    auto markerResult = credentialStore_.read(markerAccount);
    using Status = SecureCredentialStore::ReadResult::Status;
    if (keyResult.status == Status::Error || stateResult.status == Status::Error ||
        markerResult.status == Status::Error)
        return Decision::PersistenceFailure;
    const bool keyMissing = keyResult.status == Status::NotFound;
    const bool stateMissing = stateResult.status == Status::NotFound;
    bool markerMissing = markerResult.status == Status::NotFound;
    bool markerPending = markerResult.status == Status::Found &&
        markerResult->securelyEquals(QByteArrayView(pendingMarker));
    const bool markerLegacyComplete = markerResult.status == Status::Found &&
        markerResult->securelyEquals(QByteArrayView(completeMarker));
    quint64 markerGeneration = 0;
    QByteArray markerStateDigest;
    bool markerDynamicComplete = false;
    if (markerResult.status == Status::Found && !markerPending && !markerLegacyComplete) {
        const QString encoded = QString::fromLatin1(
            markerResult->bytes().data(), markerResult->bytes().size());
        static const QRegularExpression markerFormat(
            QStringLiteral("^ILUR5:complete:([1-9][0-9]{0,15}):([0-9a-f]{64})$"));
        const auto match = markerFormat.match(encoded);
        bool generationOk = false;
        markerGeneration = match.captured(1).toULongLong(&generationOk);
        if (match.hasMatch() && generationOk &&
            markerGeneration <= 9007199254740991ULL) {
            markerStateDigest = QByteArray::fromHex(match.captured(2).toLatin1());
            markerDynamicComplete = true;
        }
    }
    bool markerComplete = markerLegacyComplete || markerDynamicComplete;
    if (!markerMissing && !markerPending && !markerComplete)
        return Decision::PersistenceFailure;

    const bool freshStore = keyMissing && stateMissing && anchorMissing && markerMissing &&
        !legacyMarkerPresent;
    if (keyMissing && stateMissing && anchorMissing && markerMissing && legacyMarkerPresent)
        return Decision::PersistenceFailure;
    const bool legacyStore = !keyMissing && !stateMissing && anchorValid &&
        markerMissing && anchoredSchema == 3;
    if (freshStore) {
        if (!credentialStore_.write(markerAccount, pendingMarker))
            return Decision::PersistenceFailure;
        anchor.beginGroup(QStringLiteral("SecureUpdateReplay/v2"));
        anchor.setValue(QStringLiteral("initialized"), true);
        anchor.endGroup();
        anchor.sync();
        if (anchor.status() != QSettings::NoError)
            return Decision::PersistenceFailure;
        markerMissing = false;
        markerPending = true;
    }
    else if (markerMissing && !legacyStore) {
        return Decision::PersistenceFailure;
    }
    if (markerComplete && (keyMissing || stateMissing))
        return Decision::PersistenceFailure;
    if (markerPending && ((stateMissing && (!anchorMissing || anchorMalformed)) ||
                          (!stateMissing && keyMissing)))
        return Decision::PersistenceFailure;

    std::optional<SensitiveBytes> key;
    quint64 storedGeneration = 0;
    if (!keyMissing) {
        if (keyResult->size() != RecoveryArtifactAuthenticator::KeySize)
            return Decision::PersistenceFailure;
        key.emplace(std::move(keyResult.value));
    }
    else {
        if (!markerPending || !stateMissing || !anchorMissing)
            return Decision::PersistenceFailure;
        key = RecoveryArtifactAuthenticator::loadOrCreateKey(credentialStore_, keyAccount);
        if (!key)
            return Decision::PersistenceFailure;
    }

    const auto publishAnchor = [&](quint64 generation, const QByteArray& digest) {
        anchor.beginGroup(anchorGroup);
        anchor.remove(QString());
        anchor.setValue(QStringLiteral("generation"), qulonglong(generation));
        anchor.setValue(QStringLiteral("initialized"), true);
        anchor.setValue(QStringLiteral("schema"), 4);
        anchor.setValue(QStringLiteral("stateSha256"), QString::fromLatin1(digest.toHex()));
        anchor.endGroup();
        anchor.sync();
        if (anchor.status() != QSettings::NoError)
            return false;
        anchor.beginGroup(anchorGroup);
        const QStringList keys = anchor.childKeys();
        bool generationOk = false;
        bool schemaOk = false;
        const quint64 readGeneration = anchor.value(
            QStringLiteral("generation")).toULongLong(&generationOk);
        const int readSchema = anchor.value(QStringLiteral("schema")).toInt(&schemaOk);
        const bool verified =
            QSet<QString>(keys.cbegin(), keys.cend()) ==
                QSet<QString>{QStringLiteral("generation"), QStringLiteral("initialized"),
                              QStringLiteral("schema"), QStringLiteral("stateSha256")} &&
            generationOk && readGeneration == generation &&
            schemaOk && readSchema == 4 &&
            anchor.value(QStringLiteral("initialized")).toBool() &&
            anchor.value(QStringLiteral("stateSha256")).toString() ==
                QString::fromLatin1(digest.toHex());
        anchor.endGroup();
        return verified;
    };
    const auto writeCompleteMarker = [&](quint64 generation, const QByteArray& digest) {
        const QByteArray encoded = QByteArrayLiteral("ILUR5:complete:") +
            QByteArray::number(generation) + ':' + digest.toHex();
        return credentialStore_.write(markerAccount, encoded);
    };

    if (!stateMissing) {
        const QByteArray record(stateResult->bytes().data(), stateResult->bytes().size());
        const QByteArray storedRecordDigest = QCryptographicHash::hash(
            record, QCryptographicHash::Sha256);
        const qsizetype separator = record.indexOf('\n');
        if (separator <= 0 || separator != record.lastIndexOf('\n'))
            return Decision::PersistenceFailure;
        const QByteArray payload = record.left(separator);
        const QByteArray encodedTag = record.mid(separator + 1);
        static const QRegularExpression tagFormat(QStringLiteral("^[0-9a-f]{64}$"));
        if (!tagFormat.match(QString::fromLatin1(encodedTag)).hasMatch())
            return Decision::PersistenceFailure;
        const QByteArray tag = QByteArray::fromHex(encodedTag);
        if (!RecoveryArtifactAuthenticator::verify(
                key->bytes(), QByteArrayView("InputLeap secure update replay v3"),
                {QByteArrayView(payload)}, QByteArrayView(tag)))
            return Decision::PersistenceFailure;

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
            document.toJson(QJsonDocument::Compact) != payload)
            return Decision::PersistenceFailure;
        const QJsonObject object = document.object();
        if (object.size() != 5 || object.value(QStringLiteral("schema")).toInt(-1) != 3)
            return Decision::PersistenceFailure;
        const QJsonValue generationValue = object.value(QStringLiteral("generation"));
        if (!generationValue.isDouble() || !std::isfinite(generationValue.toDouble()) ||
            std::floor(generationValue.toDouble()) != generationValue.toDouble() ||
            generationValue.toDouble() < 1.0 ||
            generationValue.toDouble() > 9007199254740991.0)
            return Decision::PersistenceFailure;
        storedGeneration = quint64(generationValue.toDouble());
        const bool anchorMatchesStored = anchorValid &&
            storedGeneration == anchoredGeneration &&
            storedRecordDigest == anchoredStateDigest;
        if (markerPending) {
            if (storedGeneration != 1 || (anchorValid && !anchorMatchesStored) ||
                (!anchorMatchesStored &&
                 !publishAnchor(storedGeneration, storedRecordDigest)) ||
                !writeCompleteMarker(storedGeneration, storedRecordDigest))
                return Decision::PersistenceFailure;
        }
        else if (markerDynamicComplete) {
            const bool markerMatchesStored = markerGeneration == storedGeneration &&
                markerStateDigest == storedRecordDigest;
            const bool markerPrecedesStored = markerGeneration < 9007199254740991ULL &&
                storedGeneration == markerGeneration + 1;
            if (markerMatchesStored) {
                if (!anchorMatchesStored)
                    return Decision::PersistenceFailure;
            }
            else if (markerPrecedesStored) {
                const bool anchorMatchesMarker = anchorValid &&
                    anchoredGeneration == markerGeneration &&
                    anchoredStateDigest == markerStateDigest;
                const bool anchorIsInterruptedTransition = anchorValid &&
                    (anchoredGeneration == markerGeneration ||
                     anchoredGeneration == storedGeneration) &&
                    (anchoredStateDigest == markerStateDigest ||
                     anchoredStateDigest == storedRecordDigest);
                if ((anchorValid && !anchorMatchesStored && !anchorMatchesMarker &&
                     !anchorIsInterruptedTransition) ||
                    (!anchorMatchesStored &&
                     !publishAnchor(storedGeneration, storedRecordDigest)) ||
                    !writeCompleteMarker(storedGeneration, storedRecordDigest))
                    return Decision::PersistenceFailure;
            }
            else {
                return Decision::PersistenceFailure;
            }
        }
        else if (markerLegacyComplete || legacyStore) {
            // Legacy completion markers do not authenticate a generation or
            // digest.  They may migrate only when the anchor already matches
            // the authenticated state; otherwise rollback is indistinguishable
            // from an interrupted legacy write and must fail closed.
            if (!anchorValid || !anchorMatchesStored) {
                return Decision::PersistenceFailure;
            }
            if (!writeCompleteMarker(storedGeneration, storedRecordDigest))
                return Decision::PersistenceFailure;
        }
        else {
            return Decision::PersistenceFailure;
        }
        const QString issuedText = object.value(QStringLiteral("issuedAtUtc")).toString();
        const QString storedVersion = object.value(QStringLiteral("version")).toString();
        const QString digestHex = object.value(QStringLiteral("sha256")).toString();
        const QDateTime storedIssued = QDateTime::fromString(issuedText, Qt::ISODate);
        static const QRegularExpression utcFormat(
            QStringLiteral("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"));
        static const QRegularExpression digestFormat(QStringLiteral("^[0-9a-f]{64}$"));
        if (!utcFormat.match(issuedText).hasMatch() || !storedIssued.isValid() ||
            storedIssued.timeSpec() != Qt::UTC || !parseVersion(storedVersion, true) ||
            !digestFormat.match(digestHex).hasMatch())
            return Decision::PersistenceFailure;
        const QByteArray storedDigest = QByteArray::fromHex(digestHex.toLatin1());
        if (release.issuedAtUtc < storedIssued)
            return Decision::Replayed;
        if (release.issuedAtUtc == storedIssued)
            return release.version == storedVersion && release.sha256 == storedDigest
                ? Decision::Accepted : Decision::Replayed;
    }

    QJsonObject state;
    const quint64 nextGeneration = stateMissing ? 1 : storedGeneration + 1;
    if (nextGeneration == 0 || nextGeneration > 9007199254740991ULL)
        return Decision::PersistenceFailure;
    state.insert(QStringLiteral("generation"), double(nextGeneration));
    state.insert(QStringLiteral("issuedAtUtc"),
                 release.issuedAtUtc.toUTC().toString(QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")));
    state.insert(QStringLiteral("schema"), 3);
    state.insert(QStringLiteral("sha256"), QString::fromLatin1(release.sha256.toHex()));
    state.insert(QStringLiteral("version"), release.version);
    const QByteArray payload = QJsonDocument(state).toJson(QJsonDocument::Compact);
    const QByteArray tag = RecoveryArtifactAuthenticator::authenticate(
        key->bytes(), QByteArrayView("InputLeap secure update replay v3"),
        {QByteArrayView(payload)});
    const QByteArray record = payload + '\n' + tag.toHex();
    if (tag.size() != 32 || !credentialStore_.write(stateAccount, record))
        return Decision::PersistenceFailure;

    const QByteArray nextRecordDigest = QCryptographicHash::hash(
        record, QCryptographicHash::Sha256);
    if (!publishAnchor(nextGeneration, nextRecordDigest))
        return Decision::PersistenceFailure;
    if (!writeCompleteMarker(nextGeneration, nextRecordDigest))
        return Decision::PersistenceFailure;

    QSettings compatibilityMarker(settingsPath_, QSettings::IniFormat);
    compatibilityMarker.beginGroup(QStringLiteral("SecureUpdateReplay/v2"));
    compatibilityMarker.remove(QString());
    compatibilityMarker.setValue(QStringLiteral("initialized"), true);
    compatibilityMarker.setValue(QStringLiteral("schema"), 2);
    compatibilityMarker.endGroup();
    compatibilityMarker.sync();
    return compatibilityMarker.status() == QSettings::NoError
        ? Decision::Accepted : Decision::PersistenceFailure;
}
