#include "CapabilityNegotiationPolicy.h"
#include <gtest/gtest.h>

namespace {
CapabilityAdvertisement remote(QString control = "1.0")
{
    CapabilityAdvertisement ad;
    ad.uuid = QUuid("{00000000-0000-0000-0000-000000000001}");
    ad.versions.insert(CapabilityId::Control, ProtocolVersion::parse(control).value());
    return ad;
}
}

TEST(CapabilityNegotiationPolicy, NegotiatesOlderEqualMinorAndFutureMajorDeterministically)
{
    CapabilityNegotiationPolicy policy;
    auto equal = policy.negotiate(remote());
    EXPECT_EQ(equal.base.status, NegotiationStatus::Supported);
    auto minor = policy.negotiate(remote("1.9"));
    EXPECT_EQ(minor.base.status, NegotiationStatus::Degraded);
    auto future = policy.negotiate(remote("2.0"));
    EXPECT_EQ(future.base.status, NegotiationStatus::UpgradeLocal);
    EXPECT_FALSE(future.baseConnectionAllowed());
    EXPECT_EQ(future.base.reason, "Atualização necessária — atualize este computador.");
    EXPECT_NE(future.base.technical.indexOf("local=1.0"), -1);
}

TEST(CapabilityNegotiationPolicy, RecordsTheExactCommonFileTransferVersion)
{
    CapabilityNegotiationPolicy policy;
    auto ad=remote(); ad.claimed.insert(CapabilityId::FileTransfer); ad.versions.insert(CapabilityId::FileTransfer,{1,0});
    auto decision=policy.negotiate(ad).capability(CapabilityId::FileTransfer);
    ASSERT_TRUE(decision.negotiatedVersion.has_value()); EXPECT_EQ(*decision.negotiatedVersion,(ProtocolVersion{1,0}));
    ad.versions[CapabilityId::FileTransfer]={1,1};
    decision=policy.negotiate(ad).capability(CapabilityId::FileTransfer);
    ASSERT_TRUE(decision.negotiatedVersion.has_value()); EXPECT_EQ(*decision.negotiatedVersion,(ProtocolVersion{1,1}));
    ad.versions[CapabilityId::FileTransfer]={1,2};
    decision=policy.negotiate(ad).capability(CapabilityId::FileTransfer);
    ASSERT_TRUE(decision.negotiatedVersion.has_value()); EXPECT_EQ(*decision.negotiatedVersion,(ProtocolVersion{1,2}));
}

TEST(CapabilityNegotiationPolicy, OptionalIncompatibilityDoesNotDisableBase)
{
    CapabilityNegotiationPolicy policy;
    auto ad = remote();
    ad.versions.insert(CapabilityId::FileTransfer, {2, 0});
    ad.claimed.insert(CapabilityId::FileTransfer);
    auto result = policy.negotiate(ad);
    EXPECT_TRUE(result.baseConnectionAllowed());
    EXPECT_EQ(result.capability(CapabilityId::FileTransfer).status, NegotiationStatus::UpgradeLocal);
    EXPECT_FALSE(result.capabilityAllowed(CapabilityId::FileTransfer));
}

TEST(CapabilityNegotiationPolicy, FailsClosedForMalformedClaimsDependenciesAndSecurityAuthorization)
{
    CapabilityNegotiationPolicy policy;
    auto malformed = remote(); malformed.metadataValid = false;
    EXPECT_EQ(policy.negotiate(malformed).base.status, NegotiationStatus::SecurityBlocked);

    auto claimed = remote(); claimed.claimed.insert(CapabilityId::FileTransfer);
    EXPECT_EQ(policy.negotiate(claimed).capability(CapabilityId::FileTransfer).status, NegotiationStatus::SecurityBlocked);
    auto versionOnly = remote(); versionOnly.versions.insert(CapabilityId::FileTransfer,{1,1});
    EXPECT_EQ(policy.negotiate(versionOnly).capability(CapabilityId::FileTransfer).status, NegotiationStatus::SecurityBlocked);

    auto pairing = remote(); pairing.claimed.insert(CapabilityId::Pairing); pairing.versions.insert(CapabilityId::Pairing, {1,0});
    auto advisory = policy.negotiate(pairing);
    EXPECT_EQ(advisory.capability(CapabilityId::Pairing).status, NegotiationStatus::SecurityBlocked);
    EXPECT_FALSE(advisory.capabilityAllowed(CapabilityId::Pairing));
    EXPECT_TRUE(advisory.capability(CapabilityId::Pairing).protocolCompatible());
    pairing.authenticated.insert(CapabilityId::Pairing);
    EXPECT_EQ(policy.negotiate(pairing).capability(CapabilityId::Pairing).status, NegotiationStatus::Supported);
}

TEST(CapabilityNegotiationPolicy, LegacyMapsOnlyDocumentedSafeControlBaseline)
{
    CapabilityNegotiationPolicy policy;
    CapabilityAdvertisement ad; ad.uuid=QUuid::createUuid(); ad.legacy=true; ad.legacyAppVersion="3.1.0";
    const auto safe=policy.negotiate(ad);
    EXPECT_TRUE(safe.baseConnectionAllowed());
    EXPECT_EQ(safe.capability(CapabilityId::FileTransfer).status, NegotiationStatus::Unknown);
    ad.legacyAppVersion="3.0.9";
    EXPECT_EQ(policy.negotiate(ad).base.status, NegotiationStatus::SecurityBlocked);
    ad.legacyAppVersion="3.1.0-modernized";
    EXPECT_TRUE(policy.negotiate(ad).baseConnectionAllowed());
}

TEST(CapabilityNegotiationPolicy, SnapshotsAreUuidIsolatedAndStaleActionsRevalidate)
{
    CapabilityNegotiationStore store;
    auto first=remote(); auto second=remote(); second.uuid=QUuid("{00000000-0000-0000-0000-000000000002}");
    store.replace(first); store.replace(second);
    auto captured=store.snapshot(first.uuid).value(); EXPECT_TRUE(captured.baseConnectionAllowed());
    first.versions[CapabilityId::Control]={2,0}; store.replace(first);
    EXPECT_FALSE(store.revalidate(first.uuid, CapabilityId::Control));
    EXPECT_TRUE(store.revalidate(second.uuid, CapabilityId::Control));
}

TEST(CapabilityNegotiationPolicy, VersionListEncodingIsStableAndStrict)
{
    QMap<CapabilityId, ProtocolVersion> versions{{CapabilityId::Pairing,{1,0}},{CapabilityId::Control,{1,0}},{CapabilityId::FileTransfer,{1,1}}};
    EXPECT_EQ(CapabilityNegotiationPolicy::encodeVersions(versions), "control:1.0,file-transfer:1.1,pairing:1.0");
    const auto parsed=CapabilityNegotiationPolicy::parseVersions("control:1.0,file-transfer:1.1,pairing:1.0");
    ASSERT_TRUE(parsed.has_value()); EXPECT_EQ(parsed->size(),3);
    EXPECT_FALSE(CapabilityNegotiationPolicy::parseVersions("control:1.0,control:1.0").has_value());
    EXPECT_FALSE(CapabilityNegotiationPolicy::parseVersions("control:01.0").has_value());
}
