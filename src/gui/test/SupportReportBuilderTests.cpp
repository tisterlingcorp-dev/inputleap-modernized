#include "SupportReportBuilder.h"
#include <gtest/gtest.h>

namespace {
SupportReportSnapshot snapshot()
{
    SupportReportSnapshot s;
    s.appVersion = QStringLiteral("3.1.0");
    s.osProductType = QStringLiteral("windows");
    s.osProductVersion = QStringLiteral("10");
    s.cpuArchitecture = QStringLiteral("x86_64");
    s.mode = SupportReportMode::Server;
    s.endpoint = QStringLiteral("peer.example.local:24800");
    s.deviceDisplayName = QStringLiteral("Notebook da Ana");
    s.peerUuid = QUuid(QStringLiteral("{12345678-1234-1234-1234-123456789abc}"));
    s.coreState = QStringLiteral("Conectado");
    s.peerState = QStringLiteral("Disponível");
    s.diagnostics.checks = {{QStringLiteral("dns-ip"), DiagnosticSeverity::Ok,
                             QStringLiteral("Resolvido para 192.168.1.20:24800"),
                             QStringLiteral("fe80::1%12 e host peer.example.local")}};
    s.firewall = {FirewallDetectionStatus::Present, QStringLiteral("regra em C:\\Users\\ana\\InputLeap.exe")};
    s.recentErrors = {QStringLiteral("token=SENTINEL-TOKEN em \\\\server\\share\\arquivo; Authorization: Bearer SECRET")};
    return s;
}
SupportReportBuilder builder()
{
    return SupportReportBuilder([] { return QDateTime::fromString(QStringLiteral("2026-07-11T12:34:56Z"), Qt::ISODate); });
}
}

TEST(SupportReportBuilder, ProducesDeterministicPortugueseV1Report)
{
    const auto text = builder().build(snapshot(), SupportReportPolicy{true});
    EXPECT_TRUE(text.startsWith(QStringLiteral("InputLeap Support Report v1\nGerado em (UTC): 2026-07-11T12:34:56Z\n")));
    EXPECT_TRUE(text.contains(QStringLiteral("[Aplicativo e sistema]")));
    EXPECT_TRUE(text.contains(QStringLiteral("Modo: Servidor")));
    EXPECT_TRUE(text.contains(QStringLiteral("[Diagnóstico]")));
    EXPECT_TRUE(text.endsWith(QLatin1Char('\n')));
}

TEST(SupportReportBuilder, PrivateModeRemovesNetworkDeviceAndPathIdentifiers)
{
    auto s = snapshot();
    s.endpoint += QStringLiteral("; [fe80::abcd%Ethernet]:24810; 00:11:22:33:44:55");
    const auto text = builder().build(s, SupportReportPolicy{true});
    EXPECT_FALSE(text.contains(QStringLiteral("192.168")));
    EXPECT_FALSE(text.contains(QStringLiteral("fe80"), Qt::CaseInsensitive));
    EXPECT_FALSE(text.contains(QStringLiteral("peer.example")));
    EXPECT_FALSE(text.contains(QStringLiteral("Notebook da Ana")));
    EXPECT_FALSE(text.contains(QStringLiteral("12345678")));
    EXPECT_FALSE(text.contains(QStringLiteral("00:11:22")));
    EXPECT_FALSE(text.contains(QStringLiteral("ana"), Qt::CaseInsensitive));
    EXPECT_FALSE(text.contains(QStringLiteral("\\\\server"), Qt::CaseInsensitive));
    EXPECT_TRUE(text.contains(QStringLiteral("[ENDEREÇO REMOVIDO]")));
    EXPECT_TRUE(text.contains(QStringLiteral("[DISPOSITIVO REMOVIDO]")));
    EXPECT_TRUE(text.contains(QStringLiteral("[CAMINHO REMOVIDO]")));
    EXPECT_TRUE(text.contains(QStringLiteral(":24800")));
}

TEST(SupportReportBuilder, StandardModeStillRedactsSecretsAndUserPaths)
{
    auto s = snapshot();
    s.recentErrors << QStringLiteral("PIN: 654321 password=hunter2 cookie=session-secret psk=abc private key WIF=5HueCG");
    const auto text = builder().build(s, SupportReportPolicy{false});
    EXPECT_TRUE(text.contains(QStringLiteral("peer.example.local")));
    EXPECT_TRUE(text.contains(QStringLiteral("Notebook da Ana")));
    for (const auto &secret : {"SENTINEL-TOKEN", "SECRET", "654321", "hunter2", "session-secret", "5HueCG"})
        EXPECT_FALSE(text.contains(QString::fromLatin1(secret)));
    EXPECT_FALSE(text.contains(QStringLiteral("C:\\Users\\ana"), Qt::CaseInsensitive));
    EXPECT_FALSE(text.contains(QStringLiteral("\\\\server\\share"), Qt::CaseInsensitive));
}

TEST(SupportReportBuilder, NormalizesControlsAnsiBidiAndDoesNotMutateSource)
{
    auto s = snapshot();
    s.recentErrors = {QStringLiteral("linha1\r\nlinha2\u001b[31m\u202Eevil\u0001")};
    const auto original = s.recentErrors;
    const auto text = builder().build(s, SupportReportPolicy{false});
    EXPECT_EQ(s.recentErrors, original);
    EXPECT_FALSE(text.contains(QLatin1Char('\r')));
    EXPECT_FALSE(text.contains(QChar(0x1b)));
    EXPECT_FALSE(text.contains(QChar(0x202e)));
    EXPECT_FALSE(text.contains(QChar(1)));
}

TEST(SupportReportBuilder, PrivateModeRedactsBareEndpointAndStandaloneWif)
{
    auto s = snapshot();
    s.endpoint = QStringLiteral("DESKTOP-SEGREDO:24800");
    s.recentErrors = {QStringLiteral("5HueCGU8rMjxEXxiPuD5BDuRaKxyBiL2pED6NA8zN3Ky3sV4Z1x")};
    const auto text = builder().build(s, SupportReportPolicy{true});
    EXPECT_FALSE(text.contains(QStringLiteral("DESKTOP-SEGREDO")));
    EXPECT_FALSE(text.contains(QStringLiteral("5HueCGU8")));
    EXPECT_TRUE(text.contains(QStringLiteral("Endereço: [ENDEREÇO REMOVIDO]:24800")));
}

TEST(SupportReportBuilder, RedactsBasicAuthorizationAndUnicodeLineControls)
{
    auto s = snapshot();
    s.recentErrors = {QStringLiteral("Authorization: Basic dXNlcjpwYXNzd29yZA==\u0085[Firewall]\u2028x\u2029\u061c\u200e\u200f")};
    const auto text = builder().build(s, SupportReportPolicy{false});
    EXPECT_FALSE(text.contains(QStringLiteral("dXNlcjpwYXNzd29yZA")));
    for (const ushort value : {ushort(0x85), ushort(0x2028), ushort(0x2029), ushort(0x061c), ushort(0x200e), ushort(0x200f)})
        EXPECT_FALSE(text.contains(QChar(value)));
}

TEST(SupportReportBuilder, BoundsErrorsFieldsAndUtf8TotalSize)
{
    auto s = snapshot();
    s.appVersion = QString(20000, QChar(0x00e7));
    s.recentErrors.clear();
    for (int i=0; i<200; ++i) s.recentErrors << QString(4000, QLatin1Char('x'));
    const auto text = builder().build(s, SupportReportPolicy{false});
    EXPECT_LE(text.toUtf8().size(), SupportReportPolicy::MaxUtf8Bytes);
    EXPECT_TRUE(text.contains(QStringLiteral("[TRUNCADO]")));
}
