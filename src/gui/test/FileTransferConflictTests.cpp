#include "../src/ConflictResolutionPolicy.h"

#include <gtest/gtest.h>

namespace {
ConflictRequest request(const QUuid& peer, const QByteArray& batch, quint32 index = 0, quint32 count = 2,
                        const QByteArray& transferId = QByteArray(16, 't'))
{
    return {peer, batch, transferId, QStringLiteral("report.pdf"), QStringLiteral("C:/Downloads/report.pdf"), index, count};
}
}

TEST(ConflictResolutionPolicyTests, ExposesReplaceRenameAndSkipWithoutAnAutomaticReplaceDefault)
{
    ConflictResolutionPolicy policy;
    const auto peer = QUuid::createUuid();
    const QByteArray batch(16, 'b');

    EXPECT_EQ(policy.resolve(request(peer, batch), {}), ConflictAction::Rename);
    EXPECT_EQ(policy.resolve(request(peer, batch), [](const ConflictRequest&) {
        return ConflictDecision{ConflictAction::Replace, false};
    }), ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peer, batch), [](const ConflictRequest&) {
        return ConflictDecision{ConflictAction::Rename, false};
    }), ConflictAction::Rename);
    EXPECT_EQ(policy.resolve(request(peer, batch), [](const ConflictRequest&) {
        return ConflictDecision{ConflictAction::Skip, false};
    }), ConflictAction::Skip);
}

TEST(ConflictResolutionPolicyTests, ApplyAllIsScopedToAuthenticatedPeerAndBatch)
{
    ConflictResolutionPolicy policy;
    const auto peerA = QUuid::createUuid();
    const auto peerB = QUuid::createUuid();
    const QByteArray batchA(16, 'a');
    const QByteArray batchB(16, 'b');
    int prompts = 0;
    auto replaceAll = [&](const ConflictRequest&) {
        ++prompts;
        return ConflictDecision{ConflictAction::Replace, true};
    };

    EXPECT_EQ(policy.resolve(request(peerA,batchA,0,3,QByteArray(16,'a')),replaceAll),ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peerA,batchA,1,3,QByteArray(16,'b')),[&](const ConflictRequest&) {
        ++prompts;
        return ConflictDecision{ConflictAction::Skip, false};
    }), ConflictAction::Replace);
    EXPECT_EQ(prompts, 1);

    EXPECT_EQ(policy.resolve(request(peerA, batchB, 0, 2), replaceAll), ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peerB, batchA, 0, 2), replaceAll), ConflictAction::Replace);
    EXPECT_EQ(prompts, 3);
}

TEST(ConflictResolutionPolicyTests, ApplyAllExpiresAtBatchEndAndCanBeResetOnDisconnect)
{
    ConflictResolutionPolicy policy;
    const auto peer = QUuid::createUuid();
    const QByteArray batch(16, 'x');
    int prompts = 0;
    auto replaceAll = [&](const ConflictRequest&) {
        ++prompts;
        return ConflictDecision{ConflictAction::Replace, true};
    };

    EXPECT_EQ(policy.resolve(request(peer,batch,0,2,QByteArray(16,'a')),replaceAll),ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peer,batch,1,2,QByteArray(16,'b')),replaceAll),ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peer,batch,0,2,QByteArray(16,'c')),replaceAll),ConflictAction::Replace);
    EXPECT_EQ(prompts, 2);

    policy.resetPeer(peer);
    EXPECT_EQ(policy.resolve(request(peer,batch,0,2,QByteArray(16,'d')),replaceAll),ConflictAction::Replace);
    EXPECT_EQ(prompts, 3);
}

TEST(ConflictResolutionPolicyTests, ApplyAllRejectsReplayCountMismatchAndNonMonotonicItems)
{
    ConflictResolutionPolicy policy;
    const auto peer = QUuid::createUuid();
    const QByteArray batch(16, 'r');
    int prompts = 0;
    auto decide = [&](const ConflictRequest&) { ++prompts; return ConflictDecision{ConflictAction::Replace, true}; };

    EXPECT_EQ(policy.resolve(request(peer,batch,0,4,QByteArray(16,'a')),decide),ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peer,batch,1,4,QByteArray(16,'b')),decide),ConflictAction::Replace);
    EXPECT_EQ(prompts,1);
    EXPECT_EQ(policy.resolve(request(peer,batch,1,4,QByteArray(16,'c')),decide),ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peer,batch,2,5,QByteArray(16,'d')),decide),ConflictAction::Replace);
    EXPECT_EQ(policy.resolve(request(peer,batch,3,4,QByteArray(16,'b')),decide),ConflictAction::Replace);
    EXPECT_EQ(prompts,4);
    EXPECT_EQ(policy.resolve(request(peer,batch,3,4,QByteArray(16,'e')),decide),ConflictAction::Replace);
    EXPECT_EQ(prompts,5);
}

TEST(ConflictResolutionPolicyTests, CompleteBatchExpiresApplyAllWithoutConflictOnFinalItem)
{
    ConflictResolutionPolicy policy; const auto peer=QUuid::createUuid(); const QByteArray batch(16,'f'); int prompts=0;
    auto decide=[&](const ConflictRequest&){++prompts;return ConflictDecision{ConflictAction::Replace,true};};
    EXPECT_EQ(policy.resolve(request(peer,batch,0,3,QByteArray(16,'a')),decide),ConflictAction::Replace);
    policy.completeBatch(peer,batch,3);
    EXPECT_EQ(policy.resolve(request(peer,batch,1,3,QByteArray(16,'b')),decide),ConflictAction::Replace);
    EXPECT_EQ(prompts,2);
}
