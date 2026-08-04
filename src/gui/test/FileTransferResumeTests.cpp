#include "../src/FileTransferResume.h"

#include <gtest/gtest.h>
#include <QFile>
#include <QCryptographicHash>
#include <QTemporaryDir>

namespace {
FileTransferResume::Manifest manifest()
{
    FileTransferResume::Manifest m;
    m.transferId = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    m.peerUuid = QUuid("{12345678-1234-4234-9234-123456789abc}");
    m.itemIndex = 7;
    m.relativePath = "folder/file.bin";
    m.expectedSize = 100;
    m.sha256 = QByteArray(32, '\x5a');
    m.offset = 64;
    m.prefixSha256 = QCryptographicHash::hash(QByteArray(64,'a'),QCryptographicHash::Sha256);
    m.updatedAtUtc = QDateTime::currentDateTimeUtc();
    return m;
}
}

TEST(FileTransferResumeTests, RoundTripsAuthenticatedManifest)
{
    const auto original=manifest(); QString error;
    const QByteArray encoded=FileTransferResume::encodeManifest(original,QByteArray(32,'k'),&error);
    ASSERT_FALSE(encoded.isEmpty()) << error.toStdString();
    const auto decoded=FileTransferResume::decodeManifest(encoded,QByteArray(32,'k'),original.peerUuid,&error);
    ASSERT_TRUE(decoded.has_value()) << error.toStdString();
    EXPECT_EQ(decoded->transferId,original.transferId); EXPECT_EQ(decoded->relativePath,original.relativePath);
    EXPECT_EQ(decoded->offset,64u);
}

TEST(FileTransferResumeTests, RejectsWrongPeerOrKeyAndCorruption)
{
    const auto original=manifest(); const QByteArray encoded=FileTransferResume::encodeManifest(original,QByteArray(32,'k'));
    EXPECT_FALSE(FileTransferResume::decodeManifest(encoded,QByteArray(32,'x'),original.peerUuid).has_value());
    EXPECT_FALSE(FileTransferResume::decodeManifest(encoded,QByteArray(32,'k'),QUuid::createUuid()).has_value());
    QByteArray corrupt=encoded; corrupt[20]^=1;
    EXPECT_FALSE(FileTransferResume::decodeManifest(corrupt,QByteArray(32,'k'),original.peerUuid).has_value());
    EXPECT_FALSE(FileTransferResume::decodeManifest(encoded.left(12),QByteArray(32,'k'),original.peerUuid).has_value());
    EXPECT_FALSE(FileTransferResume::decodeManifest(QByteArray(70*1024,'x'),QByteArray(32,'k'),original.peerUuid).has_value());
}

TEST(FileTransferResumeTests, AuthenticatesRecoveryPathAgainstTagSubstitution)
{
    auto original=manifest();
    original.recoveryPath=QStringLiteral("C:/received/InputLeap original one - file.bin");
    const QByteArray key(32,'k');
    const QByteArray encoded=FileTransferResume::encodeManifest(original,key);
    ASSERT_FALSE(encoded.isEmpty());
    const auto decoded=FileTransferResume::decodeManifest(encoded,key,original.peerUuid);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->recoveryPath,original.recoveryPath);

    auto substituted=original;
    substituted.recoveryPath=QString(original.recoveryPath.size(),QChar('X'));
    QByteArray forged=FileTransferResume::encodeManifest(substituted,key);
    ASSERT_EQ(forged.size(),encoded.size());
    constexpr qsizetype tagBytes=32;
    forged.replace(forged.size()-tagBytes,tagBytes,encoded.right(tagBytes));
    EXPECT_FALSE(FileTransferResume::decodeManifest(
        forged,key,original.peerUuid).has_value());
}

TEST(FileTransferResumeTests, RejectsUnsafeIdentityAndOverflow)
{
    auto m=manifest();
    for(const QString& path:{QString("../x"),QString("/absolute"),QString("a\\..\\x"),QString("a//b"),QString(".inputleap-part-x")}) {
        m.relativePath=path; EXPECT_TRUE(FileTransferResume::encodeManifest(m,QByteArray(32,'k')).isEmpty()) << path.toStdString();
    }
    m=manifest(); m.offset=m.expectedSize+1; EXPECT_TRUE(FileTransferResume::encodeManifest(m,QByteArray(32,'k')).isEmpty());
    m=manifest(); m.transferId=QByteArray(15,'i'); EXPECT_TRUE(FileTransferResume::encodeManifest(m,QByteArray(32,'k')).isEmpty());
}

TEST(FileTransferResumeTests, VerifiesTempSizeAndPrefixBeforeOfferingOffset)
{
    QTemporaryDir dir; ASSERT_TRUE(dir.isValid()); auto m=manifest(); m.expectedSize=100; m.offset=64;
    const QString part=FileTransferResume::partPath(dir.path(),m.transferId);
    QFile f(part); ASSERT_TRUE(f.open(QIODevice::WriteOnly)); ASSERT_EQ(f.write(QByteArray(64,'a')),64); f.close();
    QString error; EXPECT_EQ(FileTransferResume::verifiedOffset(m,part,&error),64u);
    ASSERT_TRUE(f.open(QIODevice::Append)); ASSERT_EQ(f.write("x"),1); f.close();
    EXPECT_EQ(FileTransferResume::verifiedOffset(m,part,&error),0u);
}

TEST(FileTransferResumeTests, RejectsManifestTimestampTooFarInFuture)
{
    auto m=manifest(); m.updatedAtUtc=QDateTime::currentDateTimeUtc().addSecs(6*60);
    const auto encoded=FileTransferResume::encodeManifest(m,QByteArray(32,'k'));
    ASSERT_FALSE(encoded.isEmpty());
    EXPECT_FALSE(FileTransferResume::decodeManifest(encoded,QByteArray(32,'k'),m.peerUuid).has_value());
}

TEST(FileTransferResumeTests, RejectsInvalidTransferIdInInternalPaths)
{
    EXPECT_TRUE(FileTransferResume::partPath("root",QByteArray()).isEmpty());
    EXPECT_TRUE(FileTransferResume::partPath("root",QByteArray("../../outside")).isEmpty());
    EXPECT_TRUE(FileTransferResume::manifestPath("root",QByteArray(15,'x')).isEmpty());
    EXPECT_FALSE(FileTransferResume::partPath("root",QByteArray(16,'x')).isEmpty());
}

TEST(FileTransferResumeTests, DerivesDomainSeparatedManifestKey)
{
    const QByteArray sessionKey(32,'s');
    const QByteArray a=FileTransferResume::deriveContextKey(sessionKey,"manifest-v1");
    const QByteArray b=FileTransferResume::deriveContextKey(sessionKey,"wire-v1");
    EXPECT_EQ(a.size(),32); EXPECT_EQ(b.size(),32); EXPECT_NE(a,b); EXPECT_NE(a,sessionKey);
}

TEST(FileTransferResumeTests, ScopesInternalStorageByAuthenticatedPeer)
{
    const QByteArray id(16,'i');
    const QByteArray a=FileTransferResume::scopedStorageId(QUuid("{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}"),id);
    const QByteArray b=FileTransferResume::scopedStorageId(QUuid("{bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb}"),id);
    EXPECT_EQ(a.size(),16); EXPECT_EQ(b.size(),16); EXPECT_NE(a,b);
    EXPECT_TRUE(FileTransferResume::scopedStorageId({},id).isEmpty());
}

TEST(FileTransferResumeTests, ConstantTimeHashComparisonRequiresExactLength)
{
    EXPECT_TRUE(FileTransferResume::constantTimeEqual(QByteArray(32,'a'),QByteArray(32,'a')));
    EXPECT_FALSE(FileTransferResume::constantTimeEqual(QByteArray(32,'a'),QByteArray(32,'b')));
    EXPECT_FALSE(FileTransferResume::constantTimeEqual(QByteArray(31,'a'),QByteArray(32,'a')));
}
