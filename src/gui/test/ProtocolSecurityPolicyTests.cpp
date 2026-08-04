#include "ProtocolSecurityPolicy.h"
#include <gtest/gtest.h>
#include <atomic>
#include <thread>
#include <vector>

TEST(ProtocolSecurityPolicy, CanonicalEndpointAndIdentityBinding)
{
    ProtocolSecurityPolicy p([] { return qint64(1000); }); const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'k');
    const auto token=p.issue(peer,peer,"192.0.2.10:443",{"control:1.0","file-transfer:1.2"},key,5000); ASSERT_TRUE(token);
    EXPECT_TRUE(p.accept(*token,peer,peer,"192.0.2.10:443",{"file-transfer:1.2","control:1.0"},key));
    EXPECT_FALSE(p.accept(*token,peer,peer,"192.0.2.11:443",{"control:1.0","file-transfer:1.2"},key));
    EXPECT_FALSE(p.issue(peer,QUuid::createUuid(),"192.0.2.10:443",{"control:1.0"},key,100));
    EXPECT_TRUE(ProtocolSecurityPolicy::canonicalEndpoint("[FE80::1%12]:443").has_value());
    const auto ipv6Endpoint = ProtocolSecurityPolicy::canonicalEndpoint(
        QHostAddress(QStringLiteral("fe80::1")), 443);
    ASSERT_TRUE(ipv6Endpoint.has_value());
    EXPECT_EQ(*ipv6Endpoint, QStringLiteral("[fe80::1]:443"));
    EXPECT_FALSE(ProtocolSecurityPolicy::canonicalEndpoint("example.test:443").has_value());
}

TEST(ProtocolSecurityPolicy, RejectsReplayExpiryDowngradeAndWrongIdentity)
{
    qint64 now=100; ProtocolSecurityPolicy p([&]{return now;}); const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'s');
    auto token=p.issue(peer,peer,"fe80::1%12",{"file-transfer:1.2"},key,10); ASSERT_TRUE(token);
    EXPECT_TRUE(p.accept(*token,peer,peer,"[fe80::1%12]",{"file-transfer:1.2"},key));
    EXPECT_FALSE(p.accept(*token,peer,peer,"[fe80::1%12]",{"file-transfer:1.2"},key));
    auto expired=p.issue(peer,peer,"fe80::1%12",{"file-transfer:1.2"},key,10); ASSERT_TRUE(expired); now=111;
    EXPECT_FALSE(p.accept(*expired,peer,peer,"fe80::1%12",{"file-transfer:1.2"},key));
    auto downgrade=p.issue(peer,peer,"fe80::1%12",{"file-transfer:1.2"},key,100); ASSERT_TRUE(downgrade);
    EXPECT_FALSE(p.accept(*downgrade,peer,peer,"fe80::1%12",{"file-transfer:1.0"},key));
}

TEST(ProtocolSecurityPolicy, ConcurrentAcceptConsumesNonceOnce)
{
    ProtocolSecurityPolicy p([] { return qint64(1000); }); const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'x');
    auto token=p.issue(peer,peer,"127.0.0.1:5000",{"control:1.0"},key,1000); ASSERT_TRUE(token);
    std::atomic<int> accepted{0}; std::vector<std::thread> workers;
    for(int i=0;i<16;++i) workers.emplace_back([&]{if(p.accept(*token,peer,peer,"127.0.0.1:5000",{"control:1.0"},key))++accepted;});
    for(auto& worker:workers) worker.join(); EXPECT_EQ(accepted.load(),1);
}
