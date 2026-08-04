#include "PairingService.h"
#include <gtest/gtest.h>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <vector>

namespace {
const QUuid alice("{11111111-1111-4111-8111-111111111111}");
const QUuid bob("{22222222-2222-4222-8222-222222222222}");
struct Rng { quint32 n=1; std::vector<qsizetype> calls; QByteArray operator()(qsizetype s) { calls.push_back(s); QByteArray b(s,0); quint32 v=n++; for(int i=0;i<4 && i<s;++i)b[s-1-i]=char(v>>(8*i)); return b; } };
struct Peers { qint64 now=1800000000000LL; Rng ri,rc; PairingService inviter{[this]{return now;},[this](qsizetype n){return ri(n);}}; PairingService client{[this]{return now;},[this](qsizetype n){return rc(n);}}; };
struct Exchange { PairingService::CreatedInvite made; PairingService::ClientHello hello; PairingService::ServerChallenge challenge; PairingService::ClientProof m1; PairingService::ServerProof m2; PairingService::FinalAck m3; };
Exchange throughM3(Peers& p, QByteArray code={}) { Exchange x; x.made=*p.inviter.createInvite(alice,bob); if(code.isEmpty())code=x.made.displayCode; x.hello=*p.client.beginPairing(x.made.publicInvite,code,bob,alice); x.challenge=*p.inviter.respondToClient(x.made.publicInvite,x.hello); x.m1=*p.client.answerChallenge(x.challenge); x.m2=*p.inviter.verifyClientProof(x.m1); x.m3=*p.client.verifyServerProof(x.m2); return x; }

std::optional<QByteArray> strictKatHex(const QJsonValue& value, qsizetype expectedSize)
{
    if (!value.isString() || expectedSize < 0 ||
        expectedSize > (std::numeric_limits<qsizetype>::max)() / 2) {
        return std::nullopt;
    }
    const QString text = value.toString();
    if (text.size() != expectedSize * 2) {
        return std::nullopt;
    }
    for (const QChar character : text) {
        const ushort code = character.unicode();
        if (!((code >= '0' && code <= '9') || (code >= 'a' && code <= 'f'))) {
            return std::nullopt;
        }
    }
    const QByteArray encoded = text.toLatin1();
    const QByteArray decoded = QByteArray::fromHex(encoded);
    if (decoded.size() != expectedSize || decoded.toHex() != encoded) {
        return std::nullopt;
    }
    return decoded;
}

std::optional<QByteArray> canonicalSourceSha256(QByteArray source)
{
    for (qsizetype index = 0; index < source.size(); ++index) {
        if (source.at(index) == '\r' &&
            (index + 1 >= source.size() || source.at(index + 1) != '\n')) {
            return std::nullopt;
        }
    }
    source.replace("\r\n", "\n");
    return QCryptographicHash::hash(source, QCryptographicHash::Sha256);
}

std::optional<QByteArray> sha256File(const QString& path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return std::nullopt;
    }
    return canonicalSourceSha256(file.readAll());
}
}
TEST(PairingServiceTests, MutualConfirmationCommitsOnlyAfterM3) { Peers p; auto x=throughM3(p); EXPECT_FALSE(p.inviter.pairKey(bob)); ASSERT_TRUE(p.client.pairKey(alice)); ASSERT_EQ(p.inviter.finalize(x.m3),PairingService::Status::Accepted); ASSERT_TRUE(p.inviter.pairKey(bob)); EXPECT_EQ(*p.inviter.pairKey(bob),*p.client.pairKey(alice)); EXPECT_EQ(p.inviter.finalize(x.m3),PairingService::Status::AlreadyUsed); }
TEST(PairingServiceTests, PublicDtosContainNoCodeVerifierOrKey) { Peers p; auto m=*p.inviter.createInvite(alice,bob); auto j=QJsonDocument(m.publicInvite.toJson()).toJson(); EXPECT_FALSE(j.contains("code")); EXPECT_FALSE(j.contains("verifier")); EXPECT_FALSE(j.contains("key")); EXPECT_EQ(m.publicInvite.salt.size(),16); EXPECT_TRUE(m.publicInvite.toJson().value("generation").isString()); }
TEST(PairingServiceTests, WrongPinProofsReachFiveAttemptCap) { Peers p; auto m=*p.inviter.createInvite(alice,bob); for(int i=0;i<5;i++){ auto h=*p.client.beginPairing(m.publicInvite,"000000",bob,alice); auto c=p.inviter.respondToClient(m.publicInvite,h); ASSERT_TRUE(c); auto proof=p.client.answerChallenge(*c); ASSERT_TRUE(proof); EXPECT_FALSE(p.inviter.verifyClientProof(*proof)); } auto h=*p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); EXPECT_FALSE(p.inviter.respondToClient(m.publicInvite,h)); EXPECT_EQ(p.inviter.lastStatus(),PairingService::Status::AttemptLimitReached); EXPECT_FALSE(p.inviter.pairKey(bob)); }
TEST(PairingServiceTests, TamperingEveryFlightFailsClosed) { Peers p; auto m=*p.inviter.createInvite(alice,bob); auto h=*p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); auto badA=h; badA.A.fill(0); EXPECT_FALSE(p.inviter.respondToClient(m.publicInvite,badA)); auto c=*p.inviter.respondToClient(m.publicInvite,h); auto badB=c; badB.B.fill(0); EXPECT_FALSE(p.client.answerChallenge(badB)); auto proof=*p.client.answerChallenge(c); auto badM1=proof; badM1.M1[0]^=1; EXPECT_FALSE(p.inviter.verifyClientProof(badM1)); auto h2=*p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); auto c2=*p.inviter.respondToClient(m.publicInvite,h2); auto proof2=*p.client.answerChallenge(c2); auto m2=*p.inviter.verifyClientProof(proof2); auto badM2=m2; badM2.M2[0]^=1; EXPECT_FALSE(p.client.verifyServerProof(badM2)); }
TEST(PairingServiceTests, TamperedFinalAckAndCrossServiceReplayFail) { Peers p; auto x=throughM3(p); auto bad=x.m3; bad.M3[0]^=1; EXPECT_EQ(p.inviter.finalize(bad),PairingService::Status::InvalidProof); EXPECT_FALSE(p.inviter.pairKey(bob)); Peers q; EXPECT_EQ(q.inviter.finalize(x.m3),PairingService::Status::UnknownSession); }
TEST(PairingServiceTests, ExpiryIdentityRevokeAndRotation) { Peers p; auto m=*p.inviter.createInvite(alice,bob,1); p.now=m.publicInvite.expiresAtMs; EXPECT_FALSE(p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice)); p.now=m.publicInvite.createdAtMs; auto wrong=p.client.beginPairing(m.publicInvite,m.displayCode,alice,bob); EXPECT_FALSE(wrong); p.inviter.revoke(bob); auto h=p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); ASSERT_TRUE(h); EXPECT_FALSE(p.inviter.respondToClient(m.publicInvite,*h)); auto g=p.inviter.rotate(bob); auto fresh=*p.inviter.createInvite(alice,bob); EXPECT_EQ(fresh.publicInvite.generation,g); }
TEST(PairingServiceTests, OneActiveInvitePerRemoteAndRngFailures) { Peers p; EXPECT_TRUE(p.inviter.createInvite(alice,bob)); EXPECT_FALSE(p.inviter.createInvite(alice,bob)); qint64 now=1; PairingService bad([&]{return now;},[](qsizetype n){return QByteArray(n-1,1);}); EXPECT_FALSE(bad.createInvite(alice,bob)); }
TEST(PairingServiceTests, IndependentPairsHaveIndependentKeys) { Peers p; auto x=throughM3(p); ASSERT_EQ(p.inviter.finalize(x.m3),PairingService::Status::Accepted); auto k=*p.inviter.pairKey(bob); Peers q; q.ri.n=100; q.rc.n=200; auto y=throughM3(q); ASSERT_EQ(q.inviter.finalize(y.m3),PairingService::Status::Accepted); EXPECT_NE(k,*q.inviter.pairKey(bob)); }
TEST(PairingServiceTests, ExpiryIsEnforcedDuringEveryProtocolFlight) { Peers p; auto m=*p.inviter.createInvite(alice,bob,1); auto h=*p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); auto c=*p.inviter.respondToClient(m.publicInvite,h); p.now=m.publicInvite.expiresAtMs; EXPECT_FALSE(p.client.answerChallenge(c)); EXPECT_EQ(p.client.lastStatus(),PairingService::Status::Expired); Peers q; auto x=throughM3(q); q.now=x.made.publicInvite.expiresAtMs; EXPECT_EQ(q.inviter.finalize(x.m3),PairingService::Status::Expired); EXPECT_FALSE(q.inviter.pairKey(bob)); }
TEST(PairingServiceTests, RejectsNonCanonicalPublicValuesAndMalformedInvite) { Peers p; auto m=*p.inviter.createInvite(alice,bob); auto malformed=m.publicInvite; malformed.salt.chop(1); EXPECT_FALSE(p.client.beginPairing(malformed,m.displayCode,bob,alice)); auto h=*p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); auto shortA=h; shortA.A.chop(1); EXPECT_FALSE(p.inviter.respondToClient(m.publicInvite,shortA)); auto longA=h; longA.A.append(char(1)); EXPECT_FALSE(p.inviter.respondToClient(m.publicInvite,longA)); auto c=*p.inviter.respondToClient(m.publicInvite,h); auto shortB=c; shortB.B.chop(1); EXPECT_FALSE(p.client.answerChallenge(shortB)); auto longB=c; longB.B.append(char(1)); EXPECT_FALSE(p.client.answerChallenge(longB)); }
TEST(PairingServiceTests, RejectsWrongSizedProofs) { Peers p; auto m=*p.inviter.createInvite(alice,bob); auto h=*p.client.beginPairing(m.publicInvite,m.displayCode,bob,alice); auto c=*p.inviter.respondToClient(m.publicInvite,h); auto m1=*p.client.answerChallenge(c); m1.M1.chop(1); EXPECT_FALSE(p.inviter.verifyClientProof(m1)); Peers q; auto y=throughM3(q); auto badM2=y.m2; badM2.M2.append(char(0)); EXPECT_FALSE(q.client.verifyServerProof(badM2)); auto badM3=y.m3; badM3.M3.chop(1); EXPECT_EQ(q.inviter.finalize(badM3),PairingService::Status::InvalidProof); }

TEST(PairingServiceTests, FrozenKatHexDecoderRejectsNonCanonicalInput)
{
    EXPECT_FALSE(strictKatHex(QJsonValue(), 1));
    EXPECT_FALSE(strictKatHex(QJsonValue(7), 1));
    EXPECT_FALSE(strictKatHex(QJsonValue(QStringLiteral("0")), 1));
    EXPECT_FALSE(strictKatHex(QJsonValue(QStringLiteral("0000")), 1));
    EXPECT_FALSE(strictKatHex(QJsonValue(QStringLiteral("0g")), 1));
    EXPECT_FALSE(strictKatHex(QJsonValue(QStringLiteral("AA")), 1));
    const auto canonical = strictKatHex(QJsonValue(QStringLiteral("af")), 1);
    ASSERT_TRUE(canonical);
    EXPECT_EQ(*canonical, QByteArray::fromHex("af"));
}

TEST(PairingServiceTests, FrozenKatSourceHashCanonicalizesCheckoutLineEndings)
{
    const auto lf = canonicalSourceSha256(QByteArray("alpha\nbeta\n"));
    const auto crlf = canonicalSourceSha256(QByteArray("alpha\r\nbeta\r\n"));
    ASSERT_TRUE(lf);
    ASSERT_TRUE(crlf);
    EXPECT_EQ(*lf, *crlf);
    EXPECT_FALSE(canonicalSourceSha256(QByteArray("alpha\rbeta\n")));
}

TEST(PairingServiceTests, DeterministicExchangeMatchesFrozenKat)
{
    QFile fixture(QStringLiteral(PAIRING_TEST_FIXTURE_DIR "/pairing-srp6a-hkdf-v1.json"));
    ASSERT_TRUE(fixture.open(QIODevice::ReadOnly));

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(fixture.readAll(), &parseError);
    ASSERT_EQ(parseError.error, QJsonParseError::NoError);
    ASSERT_TRUE(document.isObject());

    const QJsonObject root = document.object();
    ASSERT_TRUE(root.value(QStringLiteral("schema")).isDouble());
    ASSERT_EQ(root.value(QStringLiteral("schema")).toInt(), 1);
    ASSERT_TRUE(root.value(QStringLiteral("name")).isString());
    ASSERT_EQ(root.value(QStringLiteral("name")).toString(),
              QStringLiteral("pairing-srp6a-hkdf-v1"));
    ASSERT_TRUE(root.value(QStringLiteral("oracle")).isString());
    ASSERT_EQ(root.value(QStringLiteral("oracle")).toString(),
              QStringLiteral("C++ PairingService"));

    const QJsonValue sourceRevisionValue = root.value(QStringLiteral("sourceRevision"));
    const auto sourceRevision = strictKatHex(sourceRevisionValue, 20);
    ASSERT_TRUE(sourceRevision);
    EXPECT_EQ(sourceRevisionValue.toString(),
              QStringLiteral("ffad9334acfba9b9bb2ea8ba3645cb0c05c94f11"));

    ASSERT_TRUE(root.value(QStringLiteral("sourceFiles")).isObject());
    const QJsonObject sourceFiles = root.value(QStringLiteral("sourceFiles")).toObject();
    const auto headerHash = strictKatHex(
        sourceFiles.value(QStringLiteral("src/gui/src/PairingService.h")), 32);
    const auto implementationHash = strictKatHex(
        sourceFiles.value(QStringLiteral("src/gui/src/PairingService.cpp")), 32);
    ASSERT_TRUE(headerHash);
    ASSERT_TRUE(implementationHash);
    const auto actualHeaderHash = sha256File(
        QStringLiteral(PAIRING_SOURCE_DIR "/PairingService.h"));
    const auto actualImplementationHash = sha256File(
        QStringLiteral(PAIRING_SOURCE_DIR "/PairingService.cpp"));
    ASSERT_TRUE(actualHeaderHash);
    ASSERT_TRUE(actualImplementationHash);
    EXPECT_EQ(*headerHash, *actualHeaderHash);
    EXPECT_EQ(*implementationHash, *actualImplementationHash);

    ASSERT_TRUE(root.value(QStringLiteral("inputs")).isObject());
    const QJsonObject inputs = root.value(QStringLiteral("inputs")).toObject();
    const auto expectInputString = [&inputs](const char* key, const char* expectedValue) {
        const QJsonValue value = inputs.value(QLatin1String(key));
        EXPECT_TRUE(value.isString()) << key;
        EXPECT_EQ(value.toString(), QLatin1String(expectedValue)) << key;
    };
    expectInputString("clockMs", "1800000000000");
    expectInputString("expiresAtMs", "1800000300000");
    expectInputString("generation", "0");
    expectInputString("inviterUuid", "11111111-1111-4111-8111-111111111111");
    expectInputString("clientUuid", "22222222-2222-4222-8222-222222222222");

    ASSERT_TRUE(inputs.value(QStringLiteral("rng")).isArray());
    const QJsonArray rng = inputs.value(QStringLiteral("rng")).toArray();
    struct ExpectedRngCall {
        const char* endpoint;
        int counter;
        int size;
        const char* purpose;
    };
    const std::array<ExpectedRngCall, 6> expectedRng{{
        {"inviter", 1, 16, "inviteId"},
        {"inviter", 2, 16, "salt"},
        {"inviter", 3, 4, "displayCode"},
        {"client", 1, 256, "clientSecretA"},
        {"client", 2, 16, "sessionId"},
        {"inviter", 4, 256, "serverSecretB"},
    }};
    ASSERT_EQ(rng.size(), qsizetype(expectedRng.size()));
    for (qsizetype index = 0; index < rng.size(); ++index) {
        ASSERT_TRUE(rng.at(index).isObject()) << index;
        const QJsonObject call = rng.at(index).toObject();
        const auto& expectedCall = expectedRng[std::size_t(index)];
        ASSERT_TRUE(call.value(QStringLiteral("endpoint")).isString()) << index;
        ASSERT_TRUE(call.value(QStringLiteral("counter")).isDouble()) << index;
        ASSERT_TRUE(call.value(QStringLiteral("size")).isDouble()) << index;
        ASSERT_TRUE(call.value(QStringLiteral("purpose")).isString()) << index;
        EXPECT_EQ(call.value(QStringLiteral("endpoint")).toString(),
                  QLatin1String(expectedCall.endpoint)) << index;
        EXPECT_EQ(call.value(QStringLiteral("counter")).toInt(), expectedCall.counter) << index;
        EXPECT_EQ(call.value(QStringLiteral("size")).toInt(), expectedCall.size) << index;
        EXPECT_EQ(call.value(QStringLiteral("purpose")).toString(),
                  QLatin1String(expectedCall.purpose)) << index;
    }

    ASSERT_TRUE(root.value(QStringLiteral("expected")).isObject());
    const QJsonObject expected = root.value(QStringLiteral("expected")).toObject();
    const auto inviteId = strictKatHex(expected.value(QStringLiteral("inviteId")), 16);
    const auto salt = strictKatHex(expected.value(QStringLiteral("salt")), 16);
    const auto displayCodeHex = strictKatHex(
        expected.value(QStringLiteral("displayCodeHex")), 6);
    const auto sessionId = strictKatHex(expected.value(QStringLiteral("sessionId")), 16);
    const auto publicA = strictKatHex(expected.value(QStringLiteral("A")), 256);
    const auto publicB = strictKatHex(expected.value(QStringLiteral("B")), 256);
    const auto proofM1 = strictKatHex(expected.value(QStringLiteral("M1")), 32);
    const auto proofM2 = strictKatHex(expected.value(QStringLiteral("M2")), 32);
    const auto proofM3 = strictKatHex(expected.value(QStringLiteral("M3")), 32);
    const auto pairKey = strictKatHex(expected.value(QStringLiteral("pairKey")), 32);
    ASSERT_TRUE(inviteId);
    ASSERT_TRUE(salt);
    ASSERT_TRUE(displayCodeHex);
    ASSERT_TRUE(sessionId);
    ASSERT_TRUE(publicA);
    ASSERT_TRUE(publicB);
    ASSERT_TRUE(proofM1);
    ASSERT_TRUE(proofM2);
    ASSERT_TRUE(proofM3);
    ASSERT_TRUE(pairKey);
    const QJsonValue displayCodeValue = expected.value(QStringLiteral("displayCodeAscii"));
    ASSERT_TRUE(displayCodeValue.isString());
    const QByteArray displayCode = displayCodeValue.toString().toLatin1();
    ASSERT_EQ(displayCode.size(), 6);
    ASSERT_TRUE(std::all_of(displayCode.cbegin(), displayCode.cend(), [](char character) {
        return character >= '0' && character <= '9';
    }));

    Peers peers;
    const Exchange exchange = throughM3(peers);

    EXPECT_EQ(exchange.made.publicInvite.inviteId, *inviteId);
    EXPECT_EQ(exchange.made.publicInvite.salt, *salt);
    EXPECT_EQ(exchange.made.publicInvite.localUuid, alice);
    EXPECT_EQ(exchange.made.publicInvite.expectedRemoteUuid, bob);
    EXPECT_EQ(exchange.made.publicInvite.createdAtMs, 1800000000000LL);
    EXPECT_EQ(exchange.made.publicInvite.expiresAtMs, 1800000300000LL);
    EXPECT_EQ(exchange.made.publicInvite.generation, 0u);
    EXPECT_EQ(exchange.made.displayCode, displayCode);
    EXPECT_EQ(exchange.made.displayCode, *displayCodeHex);
    EXPECT_EQ(exchange.hello.sessionId, *sessionId);
    EXPECT_EQ(exchange.hello.A, *publicA);
    EXPECT_EQ(exchange.challenge.B, *publicB);
    EXPECT_EQ(exchange.m1.M1, *proofM1);
    EXPECT_EQ(exchange.m2.M2, *proofM2);
    EXPECT_EQ(exchange.m3.M3, *proofM3);

    ASSERT_TRUE(peers.client.pairKey(alice));
    EXPECT_EQ(*peers.client.pairKey(alice), *pairKey);
    EXPECT_FALSE(peers.inviter.pairKey(bob));
    ASSERT_EQ(peers.inviter.finalize(exchange.m3), PairingService::Status::Accepted);
    ASSERT_TRUE(peers.inviter.pairKey(bob));
    EXPECT_EQ(*peers.inviter.pairKey(bob), *pairKey);
    EXPECT_EQ(peers.ri.calls, (std::vector<qsizetype>{16, 16, 4, 256}));
    EXPECT_EQ(peers.rc.calls, (std::vector<qsizetype>{256, 16}));
    EXPECT_EQ(peers.ri.n, 5u);
    EXPECT_EQ(peers.rc.n, 3u);
}
