#include "ConfigurationPortablePreferences.h"

#include <gtest/gtest.h>

#include <QJsonObject>

#include <utility>

namespace {
using Codec = ConfigurationPortablePreferencesCodec;
using Error = Codec::Error;

ConfigurationPortablePreferences validPreferences()
{
    return *ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("pt-BR"), true, true, true, false, true);
}

TEST(ConfigurationPortablePreferencesTests, FactoryPreservesAllInvariants)
{
    EXPECT_FALSE(ConfigurationPortablePreferences::create(
        0, 3, QStringLiteral("pt-BR"), true, false, false, false, false));
    EXPECT_FALSE(ConfigurationPortablePreferences::create(
        24800, 7, QStringLiteral("pt-BR"), true, false, false, false, false));
    EXPECT_FALSE(ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("en-00"), true, false, false, false, false));
    EXPECT_FALSE(ConfigurationPortablePreferences::create(
        24800, 3, QStringLiteral("pt-BR"), false, true, false, false, false));
}

TEST(ConfigurationPortablePreferencesTests, MoveConstructionAndAssignmentPreserveSourceInvariants)
{
    auto source = validPreferences();
    const auto expected = source;
    auto moved = std::move(source);
    EXPECT_EQ(source, expected);
    EXPECT_EQ(moved, expected);
    EXPECT_EQ(Codec::decode(Codec::encode(source)).error, Error::None);

    ConfigurationPortablePreferences assigned;
    assigned = std::move(moved);
    EXPECT_EQ(moved, expected);
    EXPECT_EQ(assigned, expected);
    EXPECT_EQ(Codec::decode(Codec::encode(moved)).error, Error::None);
}

TEST(ConfigurationPortablePreferencesTests, ExactWhitelistedPreferencesRoundTrip)
{
    const auto expected = validPreferences();
    const QJsonObject encoded = Codec::encode(expected);
    const auto decoded = Codec::decode(encoded);

    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.preferences.has_value());
    EXPECT_EQ(*decoded.preferences, expected);
    EXPECT_EQ(encoded.keys(), (QStringList{
        QStringLiteral("autoHide"), QStringLiteral("autoStart"),
        QStringLiteral("cryptoEnabled"), QStringLiteral("language"),
        QStringLiteral("logLevel"), QStringLiteral("minimizeToTray"),
        QStringLiteral("port"), QStringLiteral("requireClientCertificate")}));
}

TEST(ConfigurationPortablePreferencesTests, TypeCannotRepresentSecretsPathsNetworkOrLocalIdentity)
{
    QJsonObject encoded = Codec::encode(validPreferences());
    const QStringList forbidden = {
        QStringLiteral("fileTransferPairingCode"), QStringLiteral("preSharedKey"),
        QStringLiteral("screenName"), QStringLiteral("interface"),
        QStringLiteral("networkInterface"), QStringLiteral("logFilename"),
        QStringLiteral("receiveDirectory"), QStringLiteral("certificate"),
        QStringLiteral("privateKey"), QStringLiteral("capabilities"),
        QStringLiteral("trustState"), QStringLiteral("ipAddress")};

    for (const QString& key : forbidden)
        EXPECT_FALSE(encoded.contains(key)) << key.toStdString();

    encoded.insert(QStringLiteral("fileTransferPairingCode"), QStringLiteral("PLAINTEXT_SECRET"));
    EXPECT_EQ(Codec::decode(encoded).error, Error::UnknownField);
}

TEST(ConfigurationPortablePreferencesTests, RejectsMissingFieldsAndWrongTypes)
{
    const QJsonObject valid = Codec::encode(validPreferences());
    for (const QString& key : valid.keys()) {
        QJsonObject missing = valid;
        missing.remove(key);
        EXPECT_EQ(Codec::decode(missing).error, Error::MissingField) << key.toStdString();
    }

    QJsonObject wrongPort = valid;
    wrongPort.insert(QStringLiteral("port"), QStringLiteral("24800"));
    EXPECT_EQ(Codec::decode(wrongPort).error, Error::InvalidType);
    QJsonObject wrongBoolean = valid;
    wrongBoolean.insert(QStringLiteral("cryptoEnabled"), 1);
    EXPECT_EQ(Codec::decode(wrongBoolean).error, Error::InvalidType);
    QJsonObject wrongLanguage = valid;
    wrongLanguage.insert(QStringLiteral("language"), QJsonObject{});
    EXPECT_EQ(Codec::decode(wrongLanguage).error, Error::InvalidType);
}

TEST(ConfigurationPortablePreferencesTests, RejectsOutOfRangeAndInconsistentValues)
{
    const QJsonObject valid = Codec::encode(validPreferences());
    const auto with = [&valid](const QString& key, const QJsonValue& value) {
        QJsonObject changed = valid;
        changed.insert(key, value);
        return Codec::decode(changed).error;
    };

    EXPECT_EQ(with(QStringLiteral("port"), 0), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("port"), 65536), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("port"), 24800.5), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("logLevel"), -1), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("logLevel"), 7), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("language"), QString()), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("language"), QString(33, QLatin1Char('a'))), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("language"), QStringLiteral("pt_BR")), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("language"), QStringLiteral("en-00")), Error::InvalidValue);
    EXPECT_EQ(with(QStringLiteral("language"), QStringLiteral("xx-YY")), Error::InvalidValue);

    QJsonObject inconsistent = valid;
    inconsistent.insert(QStringLiteral("cryptoEnabled"), false);
    inconsistent.insert(QStringLiteral("requireClientCertificate"), true);
    EXPECT_EQ(Codec::decode(inconsistent).error, Error::InconsistentSecurity);
}

} // namespace
