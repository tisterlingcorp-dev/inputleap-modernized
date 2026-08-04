#include "DiagnosticsRemediationService.h"
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <gtest/gtest.h>
#include <QCoreApplication>

namespace {
QString dummyExecutablePath(const QString& name)
{
    static QTemporaryDir temporaryPath;
    if (!temporaryPath.isValid()) return QCoreApplication::applicationDirPath() + "/" + name;
    const QString candidate = QDir::cleanPath(temporaryPath.path() + "/" + name);
    if (!QFile::exists(candidate)) {
        QFile file(candidate);
        file.open(QIODevice::WriteOnly);
        file.close();
    }
    return candidate;
}

FirewallRuleSpec one(QString suffix="input-leaps.exe", quint16 port=24800) {
    return {dummyExecutablePath(suffix),{port},FirewallProfile::Domain|FirewallProfile::Private};
}
FirewallRuleSetSpec set(){ return {{one(),one("input-leap.exe",24810)}}; }
FirewallObservedRule rule(const FirewallRuleSpec&s,bool allow=true,FirewallProfiles profiles=FirewallProfile::Domain|FirewallProfile::Private){
 return {"owned",s.executablePath,s.ports,profiles,true,true,allow,6};
}
class FakeAdapter final:public DiagnosticsRemediationAdapter{
public:
 QList<DetectionCallback> callbacks; QList<FirewallRuleSetSpec> detected; QList<FirewallRuleSetSpec> launched;
 LaunchCallback launchCallback;
 void detectFirewall(const FirewallRuleSetSpec&s,DetectionCallback cb)override{detected<<s;callbacks<<std::move(cb);}
 void launchElevatedFirewallHelper(const FirewallRuleSetSpec&s,LaunchCallback cb)override{launched<<s;launchCallback=std::move(cb);}
};
}
TEST(FirewallPolicy, AggregateRequiresEveryExactAllowRule){auto s=set();EXPECT_EQ(FirewallRemediationPolicy::classify(s,{rule(s.rules[0]),rule(s.rules[1])}).status,FirewallDetectionStatus::Present);EXPECT_EQ(FirewallRemediationPolicy::classify(s,{rule(s.rules[0])}).status,FirewallDetectionStatus::Missing);EXPECT_EQ(FirewallRemediationPolicy::classify(s,{rule(s.rules[0],false),rule(s.rules[1])}).status,FirewallDetectionStatus::Missing);}
TEST(FirewallPolicy, RejectsWrongAssociationAndPublic){auto s=set();auto wrong0=rule(s.rules[0]);wrong0.localPorts={24810};auto wrong1=rule(s.rules[1]);wrong1.localPorts={24800};EXPECT_EQ(FirewallRemediationPolicy::classify(s,{wrong0,wrong1}).status,FirewallDetectionStatus::Missing);EXPECT_EQ(FirewallRemediationPolicy::classify(s,{rule(s.rules[0],true,FirewallProfile::Domain|FirewallProfile::Private|FirewallProfile::Public),rule(s.rules[1])}).status,FirewallDetectionStatus::Missing);}
TEST(FirewallPolicy, ValidatesBoundedDistinctRuleSet){auto s=set();EXPECT_TRUE(FirewallRemediationPolicy::validate(s).ok);s.rules<<one();EXPECT_FALSE(FirewallRemediationPolicy::validate(s).ok);s=set();s.rules[1].executablePath=s.rules[0].executablePath;EXPECT_FALSE(FirewallRemediationPolicy::validate(s).ok);}
TEST(FirewallService, IgnoresStaleOutOfOrderInspection){FakeAdapter a;DiagnosticsRemediationService svc(&a);auto first=set(),second=set();second.rules[0].ports={24900};svc.inspect(first);svc.inspect(second);ASSERT_EQ(a.callbacks.size(),2);a.callbacks[1]({FirewallDetectionStatus::Missing,"new"});a.callbacks[0]({FirewallDetectionStatus::Present,"stale"});EXPECT_EQ(svc.lastDetection().status,FirewallDetectionStatus::Missing);EXPECT_TRUE(svc.canRemediateFirewall());}
TEST(FirewallService, VerifyUsesExactLaunchedImmutableSetAndBlocksConcurrency){FakeAdapter a;DiagnosticsRemediationService svc(&a);auto original=set();svc.inspect(original);a.callbacks.takeFirst()({FirewallDetectionStatus::Missing,"missing"});svc.remediateFirewall(true);ASSERT_EQ(a.launched.size(),1);auto other=set();other.rules[0].ports={25000};svc.inspect(other);EXPECT_EQ(a.detected.size(),1);a.launchCallback(RemediationLaunchResult::Started);ASSERT_EQ(a.detected.size(),2);EXPECT_EQ(a.detected.last().rules[0].ports,original.rules[0].ports);auto verify= a.callbacks.takeFirst();verify({FirewallDetectionStatus::Present,"ok"});EXPECT_EQ(svc.lastDetection().status,FirewallDetectionStatus::Present);}
TEST(FirewallService, OffersOnlyMissingAndRequiresConsent){FakeAdapter a;DiagnosticsRemediationService svc(&a);svc.inspect(set());a.callbacks.takeFirst()({FirewallDetectionStatus::AccessDenied,"denied"});EXPECT_FALSE(svc.canRemediateFirewall());svc.remediateFirewall(true);EXPECT_TRUE(a.launched.isEmpty());svc.inspect(set());a.callbacks.takeFirst()({FirewallDetectionStatus::Missing,"missing"});svc.remediateFirewall(false);EXPECT_TRUE(a.launched.isEmpty());}
