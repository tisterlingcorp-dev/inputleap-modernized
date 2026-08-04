#pragma once

#include "SecureCredentialStore.h"

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QObject>
#include <QPointer>
#include <QTimer>
#include <QString>
#include <QUrl>

#include <optional>
#include <utility>

class QNetworkAccessManager;
class QNetworkReply;
class UpdateReplayStore;

class UpdateService : public QObject
{
    Q_OBJECT

public:
    enum class Error {
        None,
        InsecureSource,
        EnvelopeTooLarge,
        MalformedEnvelope,
        UnsupportedSchema,
        UnknownSigningKey,
        InvalidSignature,
        InvalidManifest,
        UnsupportedChannel,
        ExpiredManifest,
        InvalidCurrentVersion,
        NetworkFailure,
        HttpFailure,
        InvalidContentType,
        ResponseTooLarge,
        ReplayedManifest,
        ReplayStateFailure
    };

    struct Release {
        enum class PackageType {
            Unknown,
            WindowsMsi
        };

        QString channel;
        QString version;
        quint64 size = 0;
        QString notes;
        QUrl packageUrl;
        QByteArray sha256;
        QDateTime issuedAtUtc;
        QDateTime expiresAtUtc;
        PackageType packageType = PackageType::Unknown;
        bool installable = false;
        QByteArray authenticodeSignerSha256;
    };

    using PackageType = Release::PackageType;

    struct Result {
        Error error = Error::None;
        QString detail;
        std::optional<Release> release;
        QByteArray signedEnvelope;
        bool updateAvailable = false;
    };

    struct TrustedKey {
        QByteArray publicKey;
        QDateTime notBeforeUtc;
        QDateTime notAfterUtc;
        bool revoked = false;

        TrustedKey() = default;
        TrustedKey(QByteArray key) : publicKey(std::move(key)) {}
    };
    using TrustedKeys = QHash<QString, TrustedKey>;

    static constexpr qsizetype MaxEnvelopeBytes = 128 * 1024;
    static constexpr qsizetype MaxPayloadBytes = 64 * 1024;
    static constexpr quint64 MaxPackageBytes = 8ULL * 1024 * 1024 * 1024;

    static Result evaluate(const QByteArray& envelope,
                           const QUrl& manifestUrl,
                           const QString& currentVersion,
                           const TrustedKeys& trustedKeys,
                           const QDateTime& nowUtc = QDateTime::currentDateTimeUtc(),
                           int minimumValidSignatures = 1);

    explicit UpdateService(QNetworkAccessManager* network,
                           TrustedKeys trustedKeys,
                           QString currentVersion,
                           QObject* parent = nullptr,
                           UpdateReplayStore* replayStore = nullptr,
                           int minimumValidSignatures = 1,
                           int absoluteDeadlineMs = 30000);
    void check(const QUrl& manifestUrl,
               const QDateTime& nowUtc = QDateTime::currentDateTimeUtc());

Q_SIGNALS:
    void checkFinished(const UpdateService::Result& result);

private:
    void readResponse(QNetworkReply* reply);
    void finishRequest(QNetworkReply* reply);

    QNetworkAccessManager* network_ = nullptr;
    UpdateReplayStore* replayStore_ = nullptr;
    int minimumValidSignatures_ = 1;
    int absoluteDeadlineMs_ = 30000;
    TrustedKeys trustedKeys_;
    QString currentVersion_;
    QPointer<QNetworkReply> reply_;
    QByteArray response_;
    QUrl manifestUrl_;
    QDateTime evaluationTimeUtc_;
    bool responseTooLarge_ = false;
    QTimer absoluteDeadline_;
    quint64 generation_ = 0;
};

class UpdateReplayStore final
{
public:
    enum class Decision { Accepted, Replayed, PersistenceFailure };

    explicit UpdateReplayStore(
        QString settingsPath,
        SecureCredentialStore credentialStore = SecureCredentialStore(),
        QString anchorPath = {});
    Decision accept(const UpdateService::Release& release);

private:
    QString settingsPath_;
    QString anchorPath_;
    SecureCredentialStore credentialStore_;
};

Q_DECLARE_METATYPE(UpdateService::Result)
