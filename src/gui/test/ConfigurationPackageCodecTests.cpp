#include "ConfigurationPackageCodec.h"

#include <gtest/gtest.h>

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

namespace {
using Error = ConfigurationPackageCodec::Error;

TEST(ConfigurationPackageCodecTests, CanonicalPublicPackageRoundTrips)
{
    ConfigurationPackageCodec::Package package;
    package.publicData.insert(QStringLiteral("mode"), QStringLiteral("desktop"));

    const QByteArray encoded = ConfigurationPackageCodec::encode(package);
    const auto decoded = ConfigurationPackageCodec::decode(encoded);

    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.package.has_value());
    EXPECT_EQ(decoded.package->sourceSchemaVersion,
              ConfigurationPackageCodec::OldestSupportedSchemaVersion);
    EXPECT_EQ(decoded.package->publicData, package.publicData);
    EXPECT_FALSE(decoded.package->sensitive.has_value());
    const QJsonObject root = QJsonDocument::fromJson(encoded).object();
    EXPECT_EQ(root.value(QStringLiteral("format")).toString(), QStringLiteral("inputleap-configuration"));
    EXPECT_EQ(root.value(QStringLiteral("schemaVersion")).toInt(), 1);
    EXPECT_EQ(root.keys(), (QStringList{QStringLiteral("format"), QStringLiteral("public"),
                                        QStringLiteral("schemaVersion")}));
}

TEST(ConfigurationPackageCodecTests, LiteralSchemaOneFixtureRemainsSupportedAndUnchanged)
{
    const QByteArray fixture = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"marker":"v1-fixture"}})json");
    QByteArray input = fixture;
    const auto decoded = ConfigurationPackageCodec::decode(input);
    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.package.has_value());
    EXPECT_EQ(decoded.package->sourceSchemaVersion,
              ConfigurationPackageCodec::OldestSupportedSchemaVersion);
    EXPECT_EQ(decoded.package->publicData.value(QStringLiteral("marker")).toString(),
              QStringLiteral("v1-fixture"));
    EXPECT_EQ(input, fixture);
}

TEST(ConfigurationPackageCodecTests, OptionalSensitiveObjectRoundTripsWithoutInterpretation)
{
    ConfigurationPackageCodec::Package package;
    package.publicData.insert(QStringLiteral("profiles"), QJsonObject{});
    package.sensitive = QJsonObject{{QStringLiteral("ciphertext"), QStringLiteral("AA==")}};

    const auto decoded = ConfigurationPackageCodec::decode(ConfigurationPackageCodec::encode(package));

    ASSERT_EQ(decoded.error, Error::None);
    ASSERT_TRUE(decoded.package.has_value());
    ASSERT_TRUE(decoded.package->sensitive.has_value());
    EXPECT_EQ(*decoded.package->sensitive, *package.sensitive);
}

TEST(ConfigurationPackageCodecTests, RejectsMalformedNonObjectAndOversizedInput)
{
    EXPECT_EQ(ConfigurationPackageCodec::decode(QByteArrayLiteral("{")).error, Error::MalformedJson);
    EXPECT_EQ(ConfigurationPackageCodec::decode(QByteArrayLiteral("[]")).error, Error::RootNotObject);
    EXPECT_EQ(ConfigurationPackageCodec::decode(
                  QByteArray(ConfigurationPackageCodec::MaxPackageBytes + 1, 'x')).error,
              Error::TooLarge);
}

TEST(ConfigurationPackageCodecTests, RejectsMissingWrongTypeAndUnknownRootFields)
{
    const auto decodeObject = [](const QJsonObject& object) {
        return ConfigurationPackageCodec::decode(QJsonDocument(object).toJson(QJsonDocument::Compact)).error;
    };
    const QJsonObject valid{{QStringLiteral("format"), QStringLiteral("inputleap-configuration")},
                            {QStringLiteral("schemaVersion"), 1},
                            {QStringLiteral("public"), QJsonObject{}}};

    for (const QString& required : {QStringLiteral("format"), QStringLiteral("schemaVersion"),
                                    QStringLiteral("public")}) {
        QJsonObject missing = valid;
        missing.remove(required);
        EXPECT_EQ(decodeObject(missing), Error::MissingField) << required.toStdString();
    }
    QJsonObject unknown = valid;
    unknown.insert(QStringLiteral("secret"), QStringLiteral("plaintext"));
    EXPECT_EQ(decodeObject(unknown), Error::UnknownField);
    QJsonObject publicArray = valid;
    publicArray.insert(QStringLiteral("public"), QJsonArray{});
    EXPECT_EQ(decodeObject(publicArray), Error::InvalidSection);
    QJsonObject sensitiveString = valid;
    sensitiveString.insert(QStringLiteral("sensitive"), QStringLiteral("plaintext"));
    EXPECT_EQ(decodeObject(sensitiveString), Error::InvalidSection);
}

TEST(ConfigurationPackageCodecTests, RejectsDuplicateRootFieldsIncludingEscapedAliases)
{
    const QByteArray duplicate = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","format":"other","schemaVersion":1,"public":{}})json");
    const QByteArray escapedDuplicate = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","fo\u0072mat":"other","schemaVersion":1,"public":{}})json");

    EXPECT_EQ(ConfigurationPackageCodec::decode(duplicate).error, Error::DuplicateField);
    EXPECT_EQ(ConfigurationPackageCodec::decode(escapedDuplicate).error, Error::DuplicateField);
}

TEST(ConfigurationPackageCodecTests, RejectsDuplicateFieldsAnywhereInJsonTree)
{
    const QByteArray nestedPublic = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"preferences":{"port":24800,"port":24801}}})json");
    const QByteArray nestedArray = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"profiles":[{"kind":"home","ki\u006ed":"work"}]}})json");
    const QByteArray nestedSensitive = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{},"sensitive":{"tag":"AA==","tag":"BB=="}})json");

    EXPECT_EQ(ConfigurationPackageCodec::decode(nestedPublic).error, Error::DuplicateField);
    EXPECT_EQ(ConfigurationPackageCodec::decode(nestedArray).error, Error::DuplicateField);
    EXPECT_EQ(ConfigurationPackageCodec::decode(nestedSensitive).error, Error::DuplicateField);
}

TEST(ConfigurationPackageCodecTests, RejectsWrongFormatFractionalAndFutureVersions)
{
    struct InvalidFixture {
        QByteArray bytes;
        Error expected;
    };
    const QList<InvalidFixture> fixtures{
        {QByteArrayLiteral(R"json({"format":"other","schemaVersion":1,"public":{}})json"),
         Error::UnsupportedFormat},
        {QByteArrayLiteral(R"json({"format":7,"schemaVersion":1,"public":{}})json"),
         Error::UnsupportedFormat},
        {QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1.5,"public":{}})json"),
         Error::InvalidVersion},
        {QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":0,"public":{}})json"),
         Error::InvalidVersion},
        {QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":2,"public":{}})json"),
         Error::UnsupportedVersion},
        {QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":"1","public":{}})json"),
         Error::InvalidVersion},
        {QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1.0000000000000001,"public":{}})json"),
         Error::InvalidVersion},
        {QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1e0,"public":{}})json"),
         Error::InvalidVersion}
    };

    for (const auto& fixture : fixtures) {
        QByteArray input = fixture.bytes;
        const auto decoded = ConfigurationPackageCodec::decode(input);
        EXPECT_EQ(decoded.error, fixture.expected);
        EXPECT_FALSE(decoded.package.has_value());
        EXPECT_EQ(input, fixture.bytes);
    }
}

TEST(ConfigurationPackageCodecTests, RejectsMalformedCorpusWithoutPartialPackage)
{
    QList<QByteArray> malformed{
        QByteArray{},
        QByteArrayLiteral("   \r\n\t"),
        QByteArrayLiteral("null"),
        QByteArrayLiteral("true"),
        QByteArrayLiteral("1"),
        QByteArrayLiteral("\"text\""),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{}} trailing)json"),
        QByteArrayLiteral(R"json({/*comment*/"format":"inputleap-configuration","schemaVersion":1,"public":{}})json"),
        QByteArrayLiteral(R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{},})json")
    };
    QByteArray nul = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{}})json");
    nul.insert(10, '\0');
    malformed.push_back(nul);
    QByteArray invalidUtf8 = QByteArrayLiteral(
        R"json({"format":"inputleap-configuration","schemaVersion":1,"public":{"value":")json");
    invalidUtf8.push_back(char(0xff));
    invalidUtf8.append(QByteArrayLiteral(R"json("}})json"));
    malformed.push_back(invalidUtf8);

    for (const QByteArray& input : malformed) {
        QByteArray unchanged = input;
        const auto decoded = ConfigurationPackageCodec::decode(unchanged);
        EXPECT_NE(decoded.error, Error::None);
        EXPECT_FALSE(decoded.package.has_value());
        EXPECT_EQ(unchanged, input);
    }
}

TEST(ConfigurationPackageCodecTests, RejectsAdditionalInvalidVersionTypes)
{
    const auto decode = [](const QJsonValue& version) {
        const QJsonObject root{
            {QStringLiteral("format"), QStringLiteral("inputleap-configuration")},
            {QStringLiteral("schemaVersion"), version},
            {QStringLiteral("public"), QJsonObject{}}};
        return ConfigurationPackageCodec::decode(
            QJsonDocument(root).toJson(QJsonDocument::Compact));
    };
    const QList<QJsonValue> invalid{
        QJsonValue::Null,
        true,
        QStringLiteral("1"),
        QJsonArray{},
        QJsonObject{},
        -1,
        9007199254740991.0
    };
    for (const QJsonValue& version : invalid) {
        const auto result = decode(version);
        EXPECT_NE(result.error, Error::None);
        EXPECT_FALSE(result.package.has_value());
    }
}

TEST(ConfigurationPackageCodecTests, EncodeIsDeterministicAndDecodeDoesNotMutateInput)
{
    ConfigurationPackageCodec::Package package;
    package.publicData.insert(QStringLiteral("z"), 1);
    package.publicData.insert(QStringLiteral("a"), 2);
    const QByteArray first = ConfigurationPackageCodec::encode(package);
    const QByteArray second = ConfigurationPackageCodec::encode(package);
    QByteArray input = first;

    EXPECT_EQ(first, second);
    ASSERT_EQ(ConfigurationPackageCodec::decode(input).error, Error::None);
    EXPECT_EQ(input, first);
}

TEST(ConfigurationPackageCodecTests, EncodeCanonicalizesObjectKeysRecursively)
{
    ConfigurationPackageCodec::Package first;
    QJsonObject firstInner;
    firstInner.insert(QStringLiteral("y"), 2);
    firstInner.insert(QStringLiteral("b"), 3);
    QJsonObject firstNested;
    firstNested.insert(QStringLiteral("z"), 1);
    firstNested.insert(QStringLiteral("a"), firstInner);
    first.publicData.insert(QStringLiteral("z"), firstNested);
    first.publicData.insert(QStringLiteral("a"), 4);

    ConfigurationPackageCodec::Package second;
    QJsonObject secondInner;
    secondInner.insert(QStringLiteral("b"), 3);
    secondInner.insert(QStringLiteral("y"), 2);
    QJsonObject secondNested;
    secondNested.insert(QStringLiteral("a"), secondInner);
    secondNested.insert(QStringLiteral("z"), 1);
    second.publicData.insert(QStringLiteral("a"), 4);
    second.publicData.insert(QStringLiteral("z"), secondNested);

    EXPECT_EQ(ConfigurationPackageCodec::encode(first), ConfigurationPackageCodec::encode(second));
}

} // namespace
