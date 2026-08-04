#include "ConfigurationSensitiveEnvelope.h"
#include "ConfigurationSensitivePayload.h"
#include "SensitiveBytes.h"

#include <gtest/gtest.h>

#include <QJsonDocument>

#include <type_traits>

namespace {
using Envelope = ConfigurationSensitiveEnvelope;
using Error = Envelope::Error;
const QByteArray PublicDigest(32, 'd');

static_assert(!std::is_copy_constructible_v<SensitiveBytes>);
static_assert(!std::is_copy_assignable_v<SensitiveBytes>);
static_assert(std::is_move_constructible_v<SensitiveBytes>);
static_assert(std::is_move_assignable_v<SensitiveBytes>);

TEST(SensitiveBytesTests, MoveTransfersOwnershipAndEmptiesSource)
{
    SensitiveBytes source(QByteArrayLiteral("secret"));
    SensitiveBytes destination(std::move(source));

    EXPECT_TRUE(source.isEmpty());
    EXPECT_EQ(destination.bytes(), QByteArrayLiteral("secret"));
}

TEST(ConfigurationSensitivePayloadTests, RoundTripsAuthoritativeAbsentAndPresentStates)
{
    ConfigurationSensitivePayload::Snapshot absent;
    auto absentBytes = ConfigurationSensitivePayload::encode(absent);
    auto absentDecoded = ConfigurationSensitivePayload::decode(absentBytes);
    ASSERT_EQ(absentDecoded.error, ConfigurationSensitivePayload::Error::None);
    ASSERT_TRUE(absentDecoded.snapshot);
    EXPECT_FALSE(absentDecoded.snapshot->pairingCode);

    ConfigurationSensitivePayload::Snapshot present;
    present.pairingCode.emplace(QByteArray::fromHex("63c3b36469676f"));
    auto presentBytes = ConfigurationSensitivePayload::encode(present);
    auto presentDecoded = ConfigurationSensitivePayload::decode(presentBytes);
    ASSERT_EQ(presentDecoded.error, ConfigurationSensitivePayload::Error::None);
    ASSERT_TRUE(presentDecoded.snapshot && presentDecoded.snapshot->pairingCode);
    EXPECT_EQ(presentDecoded.snapshot->pairingCode->bytes(),
              QByteArray::fromHex("63c3b36469676f"));
}

TEST(ConfigurationSensitivePayloadTests, RejectsInvalidUtf8WithoutMaterializingQString)
{
    QByteArray malformed = QByteArray::fromHex("494c5350010100000002c328");
    SensitiveBytes bytes(std::move(malformed));
    EXPECT_EQ(ConfigurationSensitivePayload::decode(bytes).error,
              ConfigurationSensitivePayload::Error::InvalidUtf8);
}

TEST(ConfigurationSensitivePayloadTests, CanonicalizesOuterWhitespaceAndRejectsWhitespaceOnlyCode)
{
    SensitiveBytes padded(QByteArray::fromHex("494c535001010000000620434f444520"));
    auto decoded = ConfigurationSensitivePayload::decode(padded);
    ASSERT_EQ(decoded.error, ConfigurationSensitivePayload::Error::None);
    ASSERT_TRUE(decoded.snapshot && decoded.snapshot->pairingCode);
    EXPECT_EQ(decoded.snapshot->pairingCode->bytes(), QByteArrayLiteral("CODE"));

    SensitiveBytes whitespaceOnly(QByteArray::fromHex("494c5350010100000003202020"));
    EXPECT_EQ(ConfigurationSensitivePayload::decode(whitespaceOnly).error,
              ConfigurationSensitivePayload::Error::Malformed);
}

QByteArray binarySecret()
{
    const char bytes[] = "PAIRING_CODE\0BINARY";
    return QByteArray(bytes, static_cast<qsizetype>(sizeof(bytes) - 1));
}

TEST(ConfigurationSensitiveEnvelopeTests, BinaryPlaintextRoundTripsWithFixedAlgorithms)
{
    const QByteArray plaintext = binarySecret();
    const auto encrypted = Envelope::encrypt(
        plaintext, SensitiveBytes(QByteArrayLiteral("senha forte de backup")), PublicDigest);

    ASSERT_EQ(encrypted.error, Error::None);
    ASSERT_TRUE(encrypted.envelope.has_value());
    EXPECT_EQ(encrypted.envelope->value(QStringLiteral("cipher")), QStringLiteral("AES-256-GCM"));
    EXPECT_EQ(encrypted.envelope->value(QStringLiteral("kdf")), QStringLiteral("PBKDF2-HMAC-SHA256"));
    EXPECT_EQ(encrypted.envelope->value(QStringLiteral("iterations")).toInt(), Envelope::KdfIterations);
    const auto decrypted = Envelope::decrypt(
        *encrypted.envelope, SensitiveBytes(QByteArrayLiteral("senha forte de backup")), PublicDigest);
    ASSERT_EQ(decrypted.error, Error::None);
    ASSERT_TRUE(decrypted.plaintext.has_value());
    EXPECT_EQ(decrypted.plaintext->bytes(), plaintext);
}

TEST(ConfigurationSensitiveEnvelopeTests, SaltAndNonceAreRandomAndPlaintextNeverAppears)
{
    const QByteArray plaintext = binarySecret();
    const auto first = Envelope::encrypt(plaintext, SensitiveBytes(QByteArrayLiteral("same-password")), PublicDigest);
    const auto second = Envelope::encrypt(plaintext, SensitiveBytes(QByteArrayLiteral("same-password")), PublicDigest);
    ASSERT_EQ(first.error, Error::None);
    ASSERT_EQ(second.error, Error::None);
    ASSERT_TRUE(first.envelope && second.envelope);

    EXPECT_NE(first.envelope->value(QStringLiteral("salt")),
              second.envelope->value(QStringLiteral("salt")));
    EXPECT_NE(first.envelope->value(QStringLiteral("nonce")),
              second.envelope->value(QStringLiteral("nonce")));
    EXPECT_NE(first.envelope->value(QStringLiteral("ciphertext")),
              second.envelope->value(QStringLiteral("ciphertext")));
    EXPECT_FALSE(QJsonDocument(*first.envelope).toJson(QJsonDocument::Compact).contains(plaintext));
}

TEST(ConfigurationSensitiveEnvelopeTests, WrongPasswordAndTamperingFailWithSameAuthenticationError)
{
    const auto encrypted = Envelope::encrypt(
        binarySecret(), SensitiveBytes(QByteArrayLiteral("correct-password")), PublicDigest);
    ASSERT_TRUE(encrypted.envelope);
    EXPECT_EQ(Envelope::decrypt(
                  *encrypted.envelope, SensitiveBytes(QByteArrayLiteral("wrong-password")), PublicDigest).error,
              Error::AuthenticationFailed);
    QByteArray wrongDigest = PublicDigest;
    wrongDigest[0] ^= 1;
    EXPECT_EQ(Envelope::decrypt(
                  *encrypted.envelope, SensitiveBytes(QByteArrayLiteral("correct-password")), wrongDigest).error,
              Error::AuthenticationFailed);

    for (const QString& field : {QStringLiteral("ciphertext"), QStringLiteral("tag"),
                                 QStringLiteral("nonce"), QStringLiteral("salt")}) {
        QJsonObject tampered = *encrypted.envelope;
        QByteArray bytes = QByteArray::fromBase64(tampered.value(field).toString().toLatin1());
        ASSERT_FALSE(bytes.isEmpty());
        bytes[0] = static_cast<char>(bytes[0] ^ 0x01);
        tampered.insert(field, QString::fromLatin1(bytes.toBase64()));
        EXPECT_EQ(Envelope::decrypt(
                      tampered, SensitiveBytes(QByteArrayLiteral("correct-password")), PublicDigest).error,
                  Error::AuthenticationFailed) << field.toStdString();
    }
}

TEST(ConfigurationSensitiveEnvelopeTests, RejectsEmptyPasswordOversizeAndUnsupportedParameters)
{
    EXPECT_EQ(Envelope::encrypt(binarySecret(), SensitiveBytes(), PublicDigest).error,
              Error::PasswordRequired);
    EXPECT_EQ(Envelope::encrypt(binarySecret(), SensitiveBytes(QByteArrayLiteral("password")), QByteArray(31, 'x')).error,
              Error::InvalidAssociatedData);
    EXPECT_EQ(Envelope::encrypt(QByteArray(Envelope::MaxPlaintextBytes + 1, 'x'),
                                SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::TooLarge);

    const auto encrypted = Envelope::encrypt(
        binarySecret(), SensitiveBytes(QByteArrayLiteral("password")), PublicDigest);
    ASSERT_TRUE(encrypted.envelope);
    QJsonObject changed = *encrypted.envelope;
    changed.insert(QStringLiteral("cipher"), QStringLiteral("AES-256-CBC"));
    EXPECT_EQ(Envelope::decrypt(changed, SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::UnsupportedParameters);
    changed = *encrypted.envelope;
    changed.insert(QStringLiteral("iterations"), Envelope::KdfIterations - 1);
    EXPECT_EQ(Envelope::decrypt(changed, SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::UnsupportedParameters);
}

TEST(ConfigurationSensitiveEnvelopeTests, RejectsUnknownMissingMalformedAndNonCanonicalBase64)
{
    const auto encrypted = Envelope::encrypt(
        binarySecret(), SensitiveBytes(QByteArrayLiteral("password")), PublicDigest);
    ASSERT_TRUE(encrypted.envelope);

    QJsonObject changed = *encrypted.envelope;
    changed.insert(QStringLiteral("plaintext"), QStringLiteral("secret"));
    EXPECT_EQ(Envelope::decrypt(changed, SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::UnknownField);
    changed = *encrypted.envelope;
    changed.remove(QStringLiteral("tag"));
    EXPECT_EQ(Envelope::decrypt(changed, SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::MissingField);
    changed = *encrypted.envelope;
    changed.insert(QStringLiteral("nonce"), QStringLiteral("%%%"));
    EXPECT_EQ(Envelope::decrypt(changed, SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::InvalidEncoding);
    changed = *encrypted.envelope;
    changed.insert(QStringLiteral("tag"), 7);
    EXPECT_EQ(Envelope::decrypt(changed, SensitiveBytes(QByteArrayLiteral("password")), PublicDigest).error,
              Error::InvalidType);
}

} // namespace
