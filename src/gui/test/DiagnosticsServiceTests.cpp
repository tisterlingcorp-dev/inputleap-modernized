#include "DiagnosticsService.h"
#include "EndpointPolicy.h"

#include <gtest/gtest.h>
#include <QEventLoop>
#include <QTimer>

class FakeDiagnosticsAdapter final : public DiagnosticsAdapter
{
public:
    struct TcpPending { QString host; quint16 port; TcpCallback callback; };
    struct ResolvePending { QString host; ResolveCallback callback; };
    QList<TcpPending> tcp;
    QList<ResolvePending> resolves;
    QList<FolderCallback> folders;
    FolderProbe folder{true, true, true, {}};

    void resolveHost(const QString& host, ResolveCallback callback) override { resolves.append({host, std::move(callback)}); }
    void probeTcp(const QString& host, quint16 port, int, TcpCallback callback) override { tcp.append({host, port, std::move(callback)}); }
    void probeFolder(const QString&, FolderCallback callback) override { folders.append(std::move(callback)); }
    void cancelAll() override { tcp.clear(); resolves.clear(); folders.clear(); }
    void finishFolder() { auto cb = std::move(folders.first()); folders.removeFirst(); cb(folder); }
    void finishResolve(QStringList addresses, QString detail = {}) { auto cb = std::move(resolves.first().callback); resolves.removeFirst(); cb({addresses, detail}); }
    void finishTcp(quint16 port, TcpProbe result) { for (int i=0;i<tcp.size();++i) if(tcp[i].port==port){auto cb=std::move(tcp[i].callback);tcp.removeAt(i);cb(result);return;} }
};

static DiagnosticsInput validInput()
{
    DiagnosticsInput in; in.deviceUuid=QUuid("{12345678-1234-1234-1234-123456789abc}"); in.deviceSelected=true;
    in.endpoint="192.168.1.20"; in.controlPort=24800; in.transferPort=24810; in.discovered=true; in.compatible=true;
    in.version="3.1.0"; in.fileTransferCapability=true; in.tlsPskCapability=true; in.hasPairSessionKey=true; in.receiveFolder="C:/Recebidos"; return in;
}
static const DiagnosticCheck& check(const DiagnosticsReport& r,const QString& id){for(const auto& c:r.checks)if(c.id==id)return c;throw std::runtime_error("missing");}
static DiagnosticsReport complete(FakeDiagnosticsAdapter& a, DiagnosticsService& s, DiagnosticsInput in=validInput())
{
    DiagnosticsReport r; QObject::connect(&s,&DiagnosticsService::completed,[&](quint64,const DiagnosticsReport& v){r=v;}); s.start(in);
    if(!a.folders.isEmpty())a.finishFolder();
    if(!a.resolves.isEmpty())a.finishResolve({"192.168.1.30"});
    if(in.controlPort)a.finishTcp(in.controlPort,{DiagnosticsAdapter::TcpState::Reachable,"ok"});
    if(in.fileTransferCapability&&in.transferPort)a.finishTcp(in.transferPort,{DiagnosticsAdapter::TcpState::Reachable,"ok"});
    return r;
}

TEST(DiagnosticsServiceTests, StableOrderIncludesIndependentVersionAndHonestTls)
{
    FakeDiagnosticsAdapter a; DiagnosticsService s(&a); auto r=complete(a,s); QStringList ids;for(const auto& c:r.checks)ids<<c.id;
    EXPECT_EQ(ids,QStringList({"discovery","version","dns-ip","control-port","transfer-port","tls-psk","receive-folder","folder-permissions"}));
    EXPECT_EQ(check(r,"version").severity,DiagnosticSeverity::Ok); EXPECT_EQ(check(r,"tls-psk").severity,DiagnosticSeverity::Warning);
}
TEST(DiagnosticsServiceTests, MissingAndIncompatibleVersionsHaveOwnSeverity)
{
    FakeDiagnosticsAdapter a; DiagnosticsService s(&a); auto in=validInput();in.version.clear();auto r=complete(a,s,in);EXPECT_EQ(check(r,"version").severity,DiagnosticSeverity::Warning);
    FakeDiagnosticsAdapter b; DiagnosticsService s2(&b);in=validInput();in.compatible=false;r=complete(b,s2,in);EXPECT_EQ(check(r,"version").severity,DiagnosticSeverity::Error);
}
TEST(DiagnosticsServiceTests, HostnameWaitsForResolutionThenUsesDeterministicUsableAddress)
{
    FakeDiagnosticsAdapter a; DiagnosticsService s(&a);auto in=validInput();in.endpoint="peer.local";DiagnosticsReport r;QObject::connect(&s,&DiagnosticsService::completed,[&](quint64,const DiagnosticsReport&v){r=v;});s.start(in);
    ASSERT_EQ(a.resolves.size(),1);EXPECT_TRUE(a.tcp.isEmpty());a.finishResolve({"fe80::1","192.168.1.9","10.0.0.3"});
    ASSERT_EQ(a.tcp.size(),2);EXPECT_EQ(a.tcp[0].host,"10.0.0.3");a.finishFolder();a.finishTcp(24800,{DiagnosticsAdapter::TcpState::Reachable,{}});a.finishTcp(24810,{DiagnosticsAdapter::TcpState::Reachable,{}});
    EXPECT_EQ(check(r,"dns-ip").severity,DiagnosticSeverity::Ok);
}
TEST(DiagnosticsServiceTests, NxdomainIsErrorAndDoesNotProbeTcp)
{
    FakeDiagnosticsAdapter a;DiagnosticsService s(&a);auto in=validInput();in.endpoint="missing.invalid";DiagnosticsReport r;QObject::connect(&s,&DiagnosticsService::completed,[&](quint64,const DiagnosticsReport&v){r=v;});s.start(in);a.finishResolve({},"Host not found");a.finishFolder();
    EXPECT_TRUE(a.tcp.isEmpty());EXPECT_EQ(check(r,"dns-ip").severity,DiagnosticSeverity::Error);
}
TEST(DiagnosticsServiceTests, MissingCapabilitiesAndPortsAreNeverProbed)
{
    FakeDiagnosticsAdapter a;DiagnosticsService s(&a);auto in=validInput();in.fileTransferCapability=false;in.transferPort=0;in.controlPort=0;auto r=complete(a,s,in);
    EXPECT_TRUE(a.tcp.isEmpty());EXPECT_EQ(check(r,"control-port").severity,DiagnosticSeverity::Error);EXPECT_EQ(check(r,"transfer-port").severity,DiagnosticSeverity::Warning);
}
TEST(DiagnosticsServiceTests, NoSelectedDeviceMakesNoDiscoveryOrCompatibilityClaims)
{
    FakeDiagnosticsAdapter a;DiagnosticsService s(&a);auto in=validInput();in.deviceSelected=false;in.deviceUuid={};in.discovered=false;in.compatible=false;in.endpoint.clear();auto r=complete(a,s,in);
    EXPECT_EQ(check(r,"discovery").severity,DiagnosticSeverity::Warning);EXPECT_TRUE(check(r,"discovery").simple.contains("selecionado"));EXPECT_TRUE(a.tcp.isEmpty());
}
TEST(DiagnosticsServiceTests, AsyncFolderLateResultIsDiscarded)
{
    FakeDiagnosticsAdapter a;DiagnosticsService s(&a);QList<quint64> done;QObject::connect(&s,&DiagnosticsService::completed,[&](quint64 id,const DiagnosticsReport&){done<<id;});auto first=s.start(validInput());auto old=a.folders[0];auto second=s.start(validInput());old(a.folder);a.finishFolder();a.finishTcp(24800,{DiagnosticsAdapter::TcpState::Reachable,{}});a.finishTcp(24810,{DiagnosticsAdapter::TcpState::Reachable,{}});EXPECT_FALSE(done.contains(first));EXPECT_EQ(done,QList<quint64>({second}));
}
TEST(DiagnosticsServiceTests, GenericCredentialPatternsAreRedactedWithoutSecretApi)
{
    FakeDiagnosticsAdapter a;DiagnosticsService s(&a);a.folder.technical="password=abc123";auto in=validInput();DiagnosticsReport r;QObject::connect(&s,&DiagnosticsService::completed,[&](quint64,const DiagnosticsReport&v){r=v;});s.start(in);a.finishFolder();a.finishTcp(24800,{DiagnosticsAdapter::TcpState::Refused,"token=SENTINEL-SECRET"});a.finishTcp(24810,{DiagnosticsAdapter::TcpState::Reachable,"pin: 654321"});auto text=r.toPlainText(true);EXPECT_FALSE(text.contains("abc123"));EXPECT_FALSE(text.contains("SENTINEL"));EXPECT_FALSE(text.contains("654321"));
}
TEST(EndpointPolicyTests, FirstUsableIsDeterministic)
{ EXPECT_EQ(EndpointPolicy::firstUsable({"192.168.2.2","fe80::1","10.0.0.9","10.0.0.2"}),"10.0.0.2"); }

TEST(DiagnosticsServiceTests, FolderAndDnsTimeoutsCompleteWithoutLateDoubleCompletion)
{
    FakeDiagnosticsAdapter folderAdapter;DiagnosticsService folderService(&folderAdapter);auto folderInput=validInput();folderInput.controlPort=0;folderInput.fileTransferCapability=false;folderInput.transferPort=0;folderInput.folderTimeoutMs=100;
    DiagnosticsReport folderReport;QEventLoop folderLoop;QObject::connect(&folderService,&DiagnosticsService::completed,[&](quint64,const DiagnosticsReport&r){folderReport=r;folderLoop.quit();});folderService.start(folderInput);QTimer::singleShot(500,&folderLoop,&QEventLoop::quit);folderLoop.exec();EXPECT_EQ(check(folderReport,"receive-folder").severity,DiagnosticSeverity::Warning);
    auto lateFolder=std::move(folderAdapter.folders.first());folderAdapter.folders.clear();lateFolder(folderAdapter.folder);EXPECT_EQ(folderReport.checks.size(),8);

    FakeDiagnosticsAdapter dnsAdapter;DiagnosticsService dnsService(&dnsAdapter);auto dnsInput=validInput();dnsInput.endpoint="timeout.example";dnsInput.networkTimeoutMs=100;
    DiagnosticsReport dnsReport;QEventLoop dnsLoop;QObject::connect(&dnsService,&DiagnosticsService::completed,[&](quint64,const DiagnosticsReport&r){dnsReport=r;dnsLoop.quit();});dnsService.start(dnsInput);dnsAdapter.finishFolder();QTimer::singleShot(500,&dnsLoop,&QEventLoop::quit);dnsLoop.exec();EXPECT_EQ(check(dnsReport,"dns-ip").severity,DiagnosticSeverity::Error);EXPECT_TRUE(dnsAdapter.tcp.isEmpty());
    auto lateResolve=std::move(dnsAdapter.resolves.first().callback);dnsAdapter.resolves.clear();lateResolve({{"192.168.1.8"},{}});EXPECT_TRUE(dnsAdapter.tcp.isEmpty());
}
