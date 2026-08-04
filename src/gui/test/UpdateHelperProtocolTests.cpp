#include "UpdateHelperProtocol.h"

#include <gtest/gtest.h>

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

namespace {
QByteArray sha(const QByteArray& value)
{
    return QCryptographicHash::hash(value, QCryptographicHash::Sha256);
}

QByteArray testAuthenticationKey()
{
    return QByteArray(32, '\x7a');
}

void writeFile(const QString& path, const QByteArray& value)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write(value), value.size());
}

struct Fixture {
    QTemporaryDir directory;
    QString appPath;
    QString helperPath;
    QString msiPath;
    QString resultPath;
    QString readyPath;
    QByteArray appBody = QByteArrayLiteral("old-application");
    QByteArray msiBody = QByteArrayLiteral("signed-msi");
    QByteArray envelope = QByteArrayLiteral("signed-envelope");
    UpdateService::Release release;
    UpdateHelperInstruction instruction;

    Fixture()
    {
        appPath = QDir::cleanPath(directory.filePath(QStringLiteral("input-leap.exe")));
        helperPath = QDir::cleanPath(directory.filePath(
            QStringLiteral("input-leap-update-helper.exe")));
        msiPath = QDir::cleanPath(directory.filePath(QStringLiteral("inputleap.msi")));
        resultPath = QDir::cleanPath(directory.filePath(QStringLiteral("install.result.json")));
        readyPath = QDir::cleanPath(directory.filePath(QStringLiteral("install.ready.json")));
        writeFile(appPath, appBody);
        writeFile(helperPath, QByteArrayLiteral("helper"));
        writeFile(msiPath, msiBody);
        release.installable = true;
        release.packageType = UpdateService::PackageType::WindowsMsi;
        release.version = QStringLiteral("4.0.0");
        release.size = msiBody.size();
        release.sha256 = sha(msiBody);
        release.packageUrl = QUrl(QStringLiteral("https://updates.example/inputleap.msi"));
        instruction = {
            1234, appPath, sha(appBody), msiPath, quint64(msiBody.size()),
            sha(msiBody), appPath, sha(appBody), resultPath, readyPath,
            QByteArray(16, '\x5a'), envelope,
        };
    }

    UpdateService::Result verified() const
    {
        UpdateService::Result result;
        result.release = release;
        result.signedEnvelope = envelope;
        result.updateAvailable = true;
        return result;
    }
};

class Adapter final : public UpdateHelperAdapter
{
public:
    bool parentResult = true;
    bool waitParentResult = true;
    bool msiResult = true;
    QList<bool> msiResults;
    std::optional<quint32> exitCode = 0;
    bool relaunchResult = true;
    QStringList calls;
    bool requireHash = false;
    bool suppressAutoStart = false;
    std::function<void()> beforeInstall;
    std::function<void()> beforeRelaunch;

    bool bindExactParent(quint32, const QString&, const QByteArray&) override
    {
        calls.append(QStringLiteral("bind-parent"));
        return parentResult;
    }
    bool waitForBoundParent() override
    {
        calls.append(QStringLiteral("wait-parent"));
        return waitParentResult;
    }
    bool verifyMsi(const QString&, const UpdateService::Release&) override
    {
        calls.append(QStringLiteral("verify-msi"));
        if (!msiResults.isEmpty())
            return msiResults.takeFirst();
        return msiResult;
    }
    std::optional<quint32> installMsi(const QString&) override
    {
        calls.append(QStringLiteral("install"));
        if (beforeInstall)
            beforeInstall();
        return exitCode;
    }
    bool relaunchAndVerify(const QString&, const QByteArray&,
                           bool requireExpectedHash,
                           bool suppressAutomaticStart) override
    {
        calls.append(QStringLiteral("relaunch"));
        if (beforeRelaunch)
            beforeRelaunch();
        requireHash = requireExpectedHash;
        suppressAutoStart = suppressAutomaticStart;
        return relaunchResult;
    }
};
}

TEST(UpdateHelperProtocolTests, CanonicalInstructionRoundTripsAllBoundFields)
{
    Fixture fixture;
    const QByteArray encoded = UpdateHelperProtocol::serializeInstruction(fixture.instruction);
    QString error;
    const auto parsed = UpdateHelperProtocol::parseInstruction(encoded, &error);
    ASSERT_TRUE(parsed.has_value()) << error.toStdString();
    EXPECT_EQ(parsed->parentPid, fixture.instruction.parentPid);
    EXPECT_EQ(parsed->parentPath, fixture.appPath);
    EXPECT_EQ(parsed->parentSha256, sha(fixture.appBody));
    EXPECT_EQ(parsed->msiPath, fixture.msiPath);
    EXPECT_EQ(parsed->msiSize, quint64(fixture.msiBody.size()));
    EXPECT_EQ(parsed->msiSha256, sha(fixture.msiBody));
    EXPECT_EQ(parsed->readyPath, fixture.readyPath);
    EXPECT_EQ(parsed->readyNonce, QByteArray(16, '\x5a'));
    EXPECT_EQ(parsed->manifestEnvelope, fixture.envelope);
    EXPECT_EQ(UpdateHelperProtocol::serializeInstruction(*parsed), encoded);
}

TEST(UpdateHelperProtocolTests, InstallMutexCoordinatesAcrossWindowsSessions)
{
    const QString name = UpdateHelperProtocol::installMutexName();
    EXPECT_TRUE(name.startsWith(QStringLiteral("Global\\")));
    EXPECT_FALSE(name.startsWith(QStringLiteral("Local\\")));
}

TEST(UpdateHelperProtocolTests, RelaunchSuppressesAutomaticStartOnlyOnce)
{
    EXPECT_EQ(UpdateHelperProtocol::suppressAutomaticStartArgument(),
              QStringLiteral("--no-autostart-once"));
    EXPECT_NE(UpdateHelperProtocol::suppressAutomaticStartArgument(),
              QStringLiteral("--no-auto-start"));
}

TEST(UpdateHelperProtocolTests, RejectsNonCanonicalUnknownMalformedAndUnboundPaths)
{
    Fixture fixture;
    const QByteArray canonical = UpdateHelperProtocol::serializeInstruction(fixture.instruction);
    QList<QByteArray> invalid{
        canonical + QByteArrayLiteral("\n"),
        QByteArrayLiteral("{}"),
        QByteArray(UpdateHelperProtocol::MaxInstructionBytes + 1, 'x'),
    };
    QJsonObject unknown = QJsonDocument::fromJson(canonical).object();
    unknown.insert(QStringLiteral("unknown"), true);
    invalid.append(QJsonDocument(unknown).toJson(QJsonDocument::Compact));
    QJsonObject relative = QJsonDocument::fromJson(canonical).object();
    relative.insert(QStringLiteral("msiPath"), QStringLiteral("relative.msi"));
    invalid.append(QJsonDocument(relative).toJson(QJsonDocument::Compact));
    QJsonObject mismatchedResult = QJsonDocument::fromJson(canonical).object();
    mismatchedResult.insert(QStringLiteral("resultPath"),
                            QDir::cleanPath(QDir(QDir::tempPath()).filePath(
                                QStringLiteral("elsewhere.result.json"))));
    invalid.append(QJsonDocument(mismatchedResult).toJson(QJsonDocument::Compact));

    for (const QByteArray& value : invalid)
        EXPECT_FALSE(UpdateHelperProtocol::parseInstruction(value).has_value());
}

TEST(UpdateHelperProtocolTests, CanonicalResultRoundTripsAllBoundFields)
{
    const QByteArray nonce(16, '\x6b');
    const QByteArray msiSha256(32, '\x4d');
    const QByteArray encoded = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired, 3010, true,
        nonce, QStringLiteral("4.0.0"), msiSha256);

    QString error;
    const auto parsed = UpdateHelperProtocol::parseResult(encoded, &error);

    ASSERT_TRUE(parsed.has_value()) << error.toStdString();
    EXPECT_EQ(parsed->outcome,
              UpdateInstallPolicy::MsiOutcome::SuccessRestartRequired);
    EXPECT_EQ(parsed->msiExitCode, quint32(3010));
    EXPECT_TRUE(parsed->relaunchVerified);
    EXPECT_EQ(parsed->nonce, nonce);
    EXPECT_EQ(parsed->version, QStringLiteral("4.0.0"));
    EXPECT_EQ(parsed->msiSha256, msiSha256);
    EXPECT_TRUE(parsed->completedAtUtc.isValid());
    EXPECT_EQ(parsed->completedAtUtc.timeSpec(), Qt::UTC);
    EXPECT_EQ(QJsonDocument::fromJson(encoded).toJson(QJsonDocument::Compact),
              encoded);
}

TEST(UpdateHelperProtocolTests,
     RejectsMalformedTruncatedOversizedAndInvalidBoundResultFields)
{
    const QByteArray canonical = UpdateHelperProtocol::serializeResult(
        UpdateInstallPolicy::MsiOutcome::Success, 0, true,
        QByteArray(16, '\x6b'), QStringLiteral("4.0.0"),
        QByteArray(32, '\x4d'));
    QList<QByteArray> invalid{
        canonical + QByteArrayLiteral("\n"),
        canonical.left(canonical.size() - 1),
        QByteArray(UpdateHelperProtocol::MaxResultBytes + 1, 'x'),
    };
    const auto mutate = [&](const QString& key, const QJsonValue& value) {
        QJsonObject object = QJsonDocument::fromJson(canonical).object();
        object.insert(key, value);
        invalid.append(QJsonDocument(object).toJson(QJsonDocument::Compact));
    };
    mutate(QStringLiteral("nonce"), QStringLiteral("aw"));
    mutate(QStringLiteral("version"), QStringLiteral("4.0.0\nforged"));
    mutate(QStringLiteral("msiSha256"), QString(64, QLatin1Char('A')));
    mutate(QStringLiteral("schema"), 2);
    mutate(QStringLiteral("msiExitCode"), 1603);
    QJsonObject unknown = QJsonDocument::fromJson(canonical).object();
    unknown.insert(QStringLiteral("unknown"), true);
    invalid.append(QJsonDocument(unknown).toJson(QJsonDocument::Compact));

    for (const QByteArray& value : invalid)
        EXPECT_FALSE(UpdateHelperProtocol::parseResult(value).has_value());
}

TEST(UpdateHelperEngineTests, ExecutesOnlyAfterParentAndMsiVerificationThenPersistsResult)
{
    Fixture fixture;
    Adapter adapter;
    const QByteArray authenticationKey = testAuthenticationKey();
    UpdateHelperEngine engine([&](const QByteArray& envelope) {
        EXPECT_EQ(envelope, fixture.envelope);
        return fixture.verified();
    }, SensitiveBytes(authenticationKey));
    QString error;

    ASSERT_TRUE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter, &error)) << error.toStdString();

    EXPECT_EQ(adapter.calls,
              (QStringList{QStringLiteral("bind-parent"), QStringLiteral("wait-parent"),
                           QStringLiteral("verify-msi"), QStringLiteral("verify-msi"),
                           QStringLiteral("install"), QStringLiteral("relaunch")}));
    EXPECT_FALSE(adapter.requireHash);
    EXPECT_TRUE(adapter.suppressAutoStart);
    QFile result(fixture.resultPath);
    ASSERT_TRUE(result.open(QIODevice::ReadOnly));
    const QByteArray encoded = result.readAll();
    const QJsonDocument document = QJsonDocument::fromJson(encoded);
    ASSERT_TRUE(document.isObject());
    EXPECT_EQ(document.toJson(QJsonDocument::Compact), encoded);
    EXPECT_EQ(document.object().value(QStringLiteral("outcome")).toString(),
              QStringLiteral("success"));
    EXPECT_EQ(document.object().value(QStringLiteral("schema")).toInt(), 2);
    EXPECT_FALSE(document.object().value(QStringLiteral("relaunchVerified")).toBool(true));
    const auto parsedResult = UpdateHelperProtocol::parseResult(encoded);
    ASSERT_TRUE(parsedResult.has_value());
    EXPECT_TRUE(UpdateHelperProtocol::verifyResultAuthentication(
        *parsedResult, authenticationKey));
}

TEST(UpdateHelperEngineTests, ReservesResultChannelBeforeStartingMsi)
{
    Fixture fixture;
    Adapter adapter;
    bool lateCreationBlocked = false;
    bool reservationPublishedInProgress = false;
    adapter.beforeInstall = [&] {
        QFile lateResult(fixture.resultPath);
        lateCreationBlocked = !lateResult.open(
            QIODevice::WriteOnly | QIODevice::NewOnly);
        QFile reservedResult(fixture.resultPath);
        if (reservedResult.open(QIODevice::ReadOnly)) {
            reservationPublishedInProgress =
                QJsonDocument::fromJson(reservedResult.readAll()).object().value(
                    QStringLiteral("outcome")).toString() ==
                QStringLiteral("installing");
        }
    };
    UpdateHelperEngine engine([&](const QByteArray&) { return fixture.verified(); },
                              SensitiveBytes(testAuthenticationKey()));
    QString error;

    ASSERT_TRUE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter, &error)) << error.toStdString();
    EXPECT_TRUE(lateCreationBlocked);
    EXPECT_TRUE(reservationPublishedInProgress);
}

TEST(UpdateHelperEngineTests, CommitsPreliminaryResultBeforeRelaunch)
{
    Fixture fixture;
    Adapter adapter;
    bool observedCommittedResult = false;
    adapter.beforeRelaunch = [&] {
        QFile result(fixture.resultPath);
        if (!result.open(QIODevice::ReadOnly))
            return;
        const auto parsed = UpdateHelperProtocol::parseResult(result.readAll());
        observedCommittedResult = parsed.has_value() &&
            !parsed->relaunchVerified &&
            parsed->nonce == fixture.instruction.readyNonce &&
            parsed->version == fixture.release.version &&
            parsed->msiSha256 == fixture.release.sha256;
    };
    UpdateHelperEngine engine([&](const QByteArray&) { return fixture.verified(); },
                              SensitiveBytes(testAuthenticationKey()));

    ASSERT_TRUE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));

    EXPECT_TRUE(observedCommittedResult);
}

TEST(UpdateHelperEngineTests, SignedEnvelopeMustMatchExplicitMsiHashAndSize)
{
    Fixture fixture;
    Adapter adapter;
    auto mismatched = fixture.verified();
    mismatched.release->sha256.fill('x');
    UpdateHelperEngine engine([&](const QByteArray&) { return mismatched; });

    EXPECT_FALSE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));
    EXPECT_TRUE(adapter.calls.isEmpty());
    EXPECT_FALSE(QFile::exists(fixture.resultPath));
}

TEST(UpdateHelperEngineTests, ParentFailureAndMsiSwapStopBeforeInstallation)
{
    for (int failure = 0; failure < 2; ++failure) {
        Fixture fixture;
        Adapter adapter;
        adapter.parentResult = failure != 0;
        adapter.msiResult = failure != 1;
        UpdateHelperEngine engine([&](const QByteArray&) { return fixture.verified(); },
                              SensitiveBytes(testAuthenticationKey()));

        EXPECT_FALSE(engine.execute(
            UpdateHelperProtocol::serializeInstruction(fixture.instruction),
            fixture.helperPath, adapter));
        EXPECT_FALSE(adapter.calls.contains(QStringLiteral("install")));
        EXPECT_EQ(adapter.calls.contains(QStringLiteral("relaunch")), failure == 1);
        EXPECT_EQ(QFile::exists(fixture.resultPath), failure == 1);
    }
}

TEST(UpdateHelperEngineTests, MsiSwapBetweenVerificationsStopsBeforeInstallation)
{
    Fixture fixture;
    Adapter adapter;
    adapter.msiResults = {true, false};
    const QByteArray authenticationKey(32, '\x7a');
    UpdateHelperEngine engine(
        [&](const QByteArray&) { return fixture.verified(); },
        SensitiveBytes(authenticationKey));

    EXPECT_FALSE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));
    EXPECT_EQ(adapter.calls.count(QStringLiteral("verify-msi")), 2);
    EXPECT_FALSE(adapter.calls.contains(QStringLiteral("install")));
    EXPECT_TRUE(adapter.calls.contains(QStringLiteral("relaunch")));

    QFile resultFile(fixture.resultPath);
    ASSERT_TRUE(resultFile.open(QIODevice::ReadOnly));
    const auto result = UpdateHelperProtocol::parseResult(resultFile.readAll());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->outcome,
              UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall);
    EXPECT_TRUE(UpdateHelperProtocol::verifyResultAuthentication(
        *result, authenticationKey));
}

TEST(UpdateHelperEngineTests, ParentWaitFailureCommitsTerminalAuthenticatedResult)
{
    Fixture fixture;
    Adapter adapter;
    adapter.waitParentResult = false;
    const QByteArray authenticationKey(32, '\x7a');
    UpdateHelperEngine engine(
        [&](const QByteArray&) { return fixture.verified(); },
        SensitiveBytes(authenticationKey));

    EXPECT_FALSE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));
    EXPECT_FALSE(adapter.calls.contains(QStringLiteral("install")));
    EXPECT_FALSE(adapter.calls.contains(QStringLiteral("relaunch")));

    QFile resultFile(fixture.resultPath);
    ASSERT_TRUE(resultFile.open(QIODevice::ReadOnly));
    const auto result = UpdateHelperProtocol::parseResult(resultFile.readAll());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->outcome,
              UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall);
    EXPECT_TRUE(UpdateHelperProtocol::verifyResultAuthentication(
        *result, authenticationKey));
}

TEST(UpdateHelperEngineTests, ReadyPublishFailureCommitsTerminalAuthenticatedResult)
{
    Fixture fixture;
    ASSERT_TRUE(QDir().mkpath(fixture.readyPath));
    Adapter adapter;
    const QByteArray authenticationKey(32, '\x7a');
    UpdateHelperEngine engine(
        [&](const QByteArray&) { return fixture.verified(); },
        SensitiveBytes(authenticationKey));

    EXPECT_FALSE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));
    EXPECT_FALSE(adapter.calls.contains(QStringLiteral("wait-parent")));
    EXPECT_FALSE(adapter.calls.contains(QStringLiteral("install")));

    QFile resultFile(fixture.resultPath);
    ASSERT_TRUE(resultFile.open(QIODevice::ReadOnly));
    const auto result = UpdateHelperProtocol::parseResult(resultFile.readAll());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->outcome,
              UpdateInstallPolicy::MsiOutcome::FailedBeforeInstall);
    EXPECT_TRUE(UpdateHelperProtocol::verifyResultAuthentication(
        *result, authenticationKey));
}

TEST(UpdateHelperEngineTests, InstallerLaunchFailureRelaunchesAndRecordsPreInstallFailure)
{
    Fixture fixture;
    Adapter adapter;
    adapter.exitCode = std::nullopt;
    UpdateHelperEngine engine([&](const QByteArray&) { return fixture.verified(); },
                              SensitiveBytes(testAuthenticationKey()));

    EXPECT_FALSE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));
    EXPECT_TRUE(adapter.calls.contains(QStringLiteral("relaunch")));
    EXPECT_TRUE(adapter.requireHash);
    QFile result(fixture.resultPath);
    ASSERT_TRUE(result.open(QIODevice::ReadOnly));
    EXPECT_EQ(QJsonDocument::fromJson(result.readAll()).object()
                  .value(QStringLiteral("outcome")).toString(),
              QStringLiteral("failed-before-install"));
}

TEST(UpdateHelperEngineTests, FailureAndCancellationRequireOldApplicationHash)
{
    for (const quint32 code : {quint32(1602), quint32(1603)}) {
        Fixture fixture;
        Adapter adapter;
        adapter.exitCode = code;
        UpdateHelperEngine engine([&](const QByteArray&) { return fixture.verified(); },
                              SensitiveBytes(testAuthenticationKey()));

        ASSERT_TRUE(engine.execute(
            UpdateHelperProtocol::serializeInstruction(fixture.instruction),
            fixture.helperPath, adapter));
        EXPECT_TRUE(adapter.requireHash);
        QFile result(fixture.resultPath);
        ASSERT_TRUE(result.open(QIODevice::ReadOnly));
        const QString outcome = QJsonDocument::fromJson(result.readAll()).object()
                                    .value(QStringLiteral("outcome")).toString();
        EXPECT_EQ(outcome, code == 1602 ? QStringLiteral("cancelled")
                                       : QStringLiteral("failed"));
    }
}

TEST(UpdateHelperEngineTests, RelaunchFailureIsRecordedAndFailsTheEngine)
{
    Fixture fixture;
    Adapter adapter;
    adapter.exitCode = 1603;
    adapter.relaunchResult = false;
    UpdateHelperEngine engine([&](const QByteArray&) { return fixture.verified(); },
                              SensitiveBytes(testAuthenticationKey()));

    EXPECT_FALSE(engine.execute(
        UpdateHelperProtocol::serializeInstruction(fixture.instruction),
        fixture.helperPath, adapter));
    QFile result(fixture.resultPath);
    ASSERT_TRUE(result.open(QIODevice::ReadOnly));
    const QJsonObject persisted = QJsonDocument::fromJson(result.readAll()).object();
    EXPECT_FALSE(persisted.value(QStringLiteral("relaunchVerified")).toBool(true));
    EXPECT_EQ(persisted.value(QStringLiteral("outcome")).toString(),
              QStringLiteral("failed"));
}
