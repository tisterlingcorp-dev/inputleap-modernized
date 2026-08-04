#pragma once

#include "SensitiveBytes.h"
#include "UpdateInstallPolicy.h"
#include "UpdateService.h"

#include <QByteArray>
#include <QByteArrayView>
#include <QDateTime>
#include <QString>

#include <functional>
#include <optional>

struct UpdateHelperInstruction {
    quint32 parentPid = 0;
    QString parentPath;
    QByteArray parentSha256;
    QString msiPath;
    quint64 msiSize = 0;
    QByteArray msiSha256;
    QString appPath;
    QByteArray appSha256;
    QString resultPath;
    QString readyPath;
    QByteArray readyNonce;
    QByteArray manifestEnvelope;
};

struct UpdateHelperResult {
    UpdateInstallPolicy::MsiOutcome outcome =
        UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall;
    quint32 msiExitCode = 0;
    bool relaunchVerified = false;
    QByteArray nonce;
    QString version;
    QByteArray msiSha256;
    QDateTime completedAtUtc;
    QByteArray authenticationTag;
};

class UpdateHelperProtocol final
{
public:
    static constexpr qsizetype MaxInstructionBytes = 192 * 1024;
    static constexpr qsizetype MaxResultBytes = 4096;
    static QString installMutexName();
    static QString suppressAutomaticStartArgument();
    static QString resultAuthenticationAccount();

    static QByteArray serializeInstruction(const UpdateHelperInstruction& instruction);
    static std::optional<UpdateHelperInstruction> parseInstruction(
        const QByteArray& encoded, QString* error = nullptr);
    static QByteArray serializeResult(UpdateInstallPolicy::MsiOutcome outcome,
                                      quint32 exitCode, bool relaunchVerified,
                                      const QByteArray& nonce,
                                      const QString& version,
                                      const QByteArray& msiSha256,
                                      QByteArrayView authenticationKey = {},
                                      QDateTime completedAtUtc = {});
    static std::optional<UpdateHelperResult> parseResult(
        const QByteArray& encoded, QString* error = nullptr);
    static bool verifyResultAuthentication(
        const UpdateHelperResult& result, QByteArrayView authenticationKey);
};

class UpdateHelperAdapter
{
public:
    virtual ~UpdateHelperAdapter() = default;
    virtual bool bindExactParent(quint32 pid, const QString& path,
                                 const QByteArray& sha256) = 0;
    virtual bool waitForBoundParent() = 0;
    virtual bool verifyMsi(const QString& path,
                           const UpdateService::Release& release) = 0;
    virtual std::optional<quint32> installMsi(const QString& path) = 0;
    virtual bool relaunchAndVerify(const QString& appPath,
                                   const QByteArray& expectedSha256,
                                   bool requireExpectedHash,
                                   bool suppressAutomaticStart) = 0;
};

class UpdateHelperEngine final
{
public:
    using EnvelopeVerifier = std::function<UpdateService::Result(const QByteArray&)>;

    explicit UpdateHelperEngine(EnvelopeVerifier verifier,
                                SensitiveBytes resultAuthenticationKey = {});
    bool execute(const QByteArray& encodedInstruction,
                 const QString& helperPath,
                 UpdateHelperAdapter& adapter,
                 QString* error = nullptr) const;

private:
    EnvelopeVerifier verifier_;
    SensitiveBytes resultAuthenticationKey_;
};
