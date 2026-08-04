#include "PairingController.h"
#include "PairingProtocolCodec.h"
#include "PairingWizard.h"
#include <QCheckBox>
#include <QLabel>
#include <gtest/gtest.h>
#include <QApplication>
#include <QJsonDocument>
#include <QLineEdit>
#include <QSignalSpy>
#include <QTcpServer>
#include <QTcpSocket>

namespace {
const QUuid inviterUuid("{11111111-1111-4111-8111-111111111111}");
const QUuid remoteUuid("{22222222-2222-4222-8222-222222222222}");
bool waitFor(const std::function<bool()>& predicate, int timeout=5000) {
    QElapsedTimer timer; timer.start();
    while (!predicate() && timer.elapsed()<timeout) QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    return predicate();
}
}

TEST(PairingProtocolCodecTests, RoundTripsPublicInviteWithoutSecrets) {
    PairingService service;
    auto made=service.createInvite(inviterUuid,remoteUuid);
    ASSERT_TRUE(made);
    PairingProtocolCodec::Message message=PairingProtocolCodec::invite(made->publicInvite);
    QByteArray frame=PairingProtocolCodec::encode(message);
    EXPECT_FALSE(frame.contains(made->displayCode));
    EXPECT_FALSE(frame.toLower().contains("verifier"));
    EXPECT_FALSE(frame.toLower().contains("key"));
    PairingProtocolCodec::Message decoded; QString error;
    ASSERT_TRUE(PairingProtocolCodec::decodeFrame(frame,&decoded,&error));
    EXPECT_EQ(decoded.type,PairingProtocolCodec::Type::Invite);
    EXPECT_EQ(decoded.invite.localUuid,inviterUuid);
    EXPECT_EQ(decoded.invite.expectedRemoteUuid,remoteUuid);
}

TEST(PairingProtocolCodecTests, RejectsOversizedUnknownVersionAndTrailingData) {
    PairingProtocolCodec::Message decoded; QString error;
    QByteArray oversized(4,'\0'); oversized[0]=1;
    EXPECT_FALSE(PairingProtocolCodec::decodeFrame(oversized,&decoded,&error));
    QByteArray bad="{\"version\":99,\"type\":\"success\",\"fields\":{}}";
    QByteArray framed; quint32 n=bad.size(); for(int s=24;s>=0;s-=8) framed.append(char(n>>s)); framed+=bad;
    EXPECT_FALSE(PairingProtocolCodec::decodeFrame(framed,&decoded,&error));
    auto valid=PairingProtocolCodec::encode(PairingProtocolCodec::success(QByteArray(16,'s'))); valid+='x';
    EXPECT_FALSE(PairingProtocolCodec::decodeFrame(valid,&decoded,&error));
}

TEST(PairingProtocolCodecTests, AuthenticatedMonitorMetadataIsCanonicalAndSessionBound) {
    const QByteArray key(32,'k'),sid(16,'s'),iid(16,'i');
    std::vector<ScreenLayout::Monitor> monitors={{"hashed-display",QRect(0,20,1920,1080),1.25,Qt::LandscapeOrientation,true}};
    auto made=PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,monitors); ASSERT_TRUE(made);
    PairingProtocolCodec::Message decoded; QString error;
    ASSERT_TRUE(PairingProtocolCodec::decodeFrame(PairingProtocolCodec::encode(*made),&decoded,&error));
    EXPECT_TRUE(PairingProtocolCodec::authenticateDeviceMetadata(decoded,key,sid,iid,remoteUuid,inviterUuid));
    EXPECT_FALSE(PairingProtocolCodec::authenticateDeviceMetadata(decoded,QByteArray(32,'x'),sid,iid,remoteUuid,inviterUuid));
    EXPECT_FALSE(PairingProtocolCodec::authenticateDeviceMetadata(decoded,key,QByteArray(16,'x'),iid,remoteUuid,inviterUuid));
    EXPECT_FALSE(PairingProtocolCodec::authenticateDeviceMetadata(decoded,key,sid,iid,inviterUuid,remoteUuid));
    decoded.monitors[0].geometry.setWidth(1919);
    EXPECT_FALSE(PairingProtocolCodec::authenticateDeviceMetadata(decoded,key,sid,iid,remoteUuid,inviterUuid));
}

TEST(PairingProtocolCodecTests, RejectsInvalidMonitorMetadataShapes) {
    const QByteArray key(32,'k'),sid(16,'s'),iid(16,'i');
    std::vector<ScreenLayout::Monitor> tooMany(17,{"id",QRect(0,0,1,1),1.0,Qt::PrimaryOrientation,false});
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,tooMany));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{QString(129,'a'),QRect(0,0,1,1),1.0,Qt::PrimaryOrientation,false}}));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{"id",QRect(0,0,0,1),1.0,Qt::PrimaryOrientation,false}}));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{"id",QRect(0,0,1,1),std::numeric_limits<qreal>::infinity(),Qt::PrimaryOrientation,false}}));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{"id",QRect(0,0,1,1),1.0,Qt::ScreenOrientation(99),false}}));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{"id",QRect(-1,0,1,1),1.0,Qt::PrimaryOrientation,false}}));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{"same",QRect(0,0,2,2),1.0,Qt::PrimaryOrientation,false},{"same",QRect(2,0,2,2),1.0,Qt::PrimaryOrientation,false}}));
    EXPECT_FALSE(PairingProtocolCodec::deviceMetadata(key,sid,iid,remoteUuid,inviterUuid,{{"a",QRect(0,0,2,2),1.0,Qt::PrimaryOrientation,false},{"b",QRect(1,0,2,2),1.0,Qt::PrimaryOrientation,false}}));
}

TEST(PairingControllerTests, CompletesRealLoopbackExchangeOnlyAfterFinalAck) {
    PairingController inviter,remote;
    QSignalSpy inviterDone(&inviter,&PairingController::paired);
    QSignalSpy remoteDone(&remote,&PairingController::paired);
    auto invitation=inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0);
    ASSERT_TRUE(invitation);
    ASSERT_GT(inviter.port(),0);
    remote.connectTo(inviterUuid,remoteUuid,QHostAddress::LocalHost,inviter.port());
    ASSERT_TRUE(waitFor([&]{return remote.publicInvite().has_value();}));
    remote.submitCode(invitation->displayCode);
    ASSERT_TRUE(waitFor([&]{return inviterDone.count()==1&&remoteDone.count()==1;}));
    ASSERT_TRUE(inviter.pairKey(remoteUuid));
    ASSERT_TRUE(remote.pairKey(inviterUuid));
    EXPECT_EQ(*inviter.pairKey(remoteUuid),*remote.pairKey(inviterUuid));
}

TEST(PairingControllerTests, ExchangesMetadataOnlyAfterMutualPairing) {
    PairingController inviter,remote;
    inviter.setPeerSupportsDeviceMetadata(true);remote.setPeerSupportsDeviceMetadata(true);
    const std::vector<ScreenLayout::Monitor> inviterMonitors={{"inviter-hash",QRect(0,0,2560,1440),1.5,Qt::LandscapeOrientation,true}};
    const std::vector<ScreenLayout::Monitor> remoteMonitors={{"remote-hash",QRect(0,0,1920,1080),1.0,Qt::PrimaryOrientation,true}};
    inviter.setLocalDeviceMetadata(inviterMonitors); remote.setLocalDeviceMetadata(remoteMonitors);
    int inviterMetadata=0,remoteMetadata=0; QUuid seenByInviter,seenByRemote;
    QObject::connect(&inviter,&PairingController::authenticatedDeviceMetadata,[&](const QUuid&uuid,const auto&monitors){++inviterMetadata;seenByInviter=uuid;EXPECT_EQ(monitors[0].id,"remote-hash");});
    QObject::connect(&remote,&PairingController::authenticatedDeviceMetadata,[&](const QUuid&uuid,const auto&monitors){++remoteMetadata;seenByRemote=uuid;EXPECT_EQ(monitors[0].id,"inviter-hash");});
    auto invitation=inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0); ASSERT_TRUE(invitation);
    remote.connectTo(inviterUuid,remoteUuid,QHostAddress::LocalHost,inviter.port());
    ASSERT_TRUE(waitFor([&]{return remote.publicInvite().has_value();}));
    EXPECT_EQ(inviterMetadata,0); EXPECT_EQ(remoteMetadata,0);
    remote.submitCode(invitation->displayCode);
    ASSERT_TRUE(waitFor([&]{return inviterMetadata==1&&remoteMetadata==1;}));
    EXPECT_EQ(seenByInviter,remoteUuid); EXPECT_EQ(seenByRemote,inviterUuid);
}

TEST(PairingControllerTests, ReusedControllersAcceptMetadataInEachNewSession) {
    PairingController inviter,remote;inviter.setPeerSupportsDeviceMetadata(true);remote.setPeerSupportsDeviceMetadata(true);
    inviter.setLocalDeviceMetadata({{"inviter",QRect(0,0,10,10)}});remote.setLocalDeviceMetadata({{"remote",QRect(0,0,10,10)}});
    int received=0;QObject::connect(&inviter,&PairingController::authenticatedDeviceMetadata,[&](const QUuid&,const auto&){++received;});
    for(int round=0;round<2;++round){
        auto invitation=inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0);ASSERT_TRUE(invitation);
        remote.connectTo(inviterUuid,remoteUuid,QHostAddress::LocalHost,inviter.port());
        ASSERT_TRUE(waitFor([&]{return remote.publicInvite().has_value();}));remote.submitCode(invitation->displayCode);
        ASSERT_TRUE(waitFor([&]{return received==round+1;}));
    }
}

TEST(PairingControllerTests, WrongCodeNeverReportsPaired) {
    PairingController inviter,remote;
    QSignalSpy inviterDone(&inviter,&PairingController::paired),remoteDone(&remote,&PairingController::paired),failed(&remote,&PairingController::failed);
    auto invitation=inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0); ASSERT_TRUE(invitation);
    remote.connectTo(inviterUuid,remoteUuid,QHostAddress::LocalHost,inviter.port());
    ASSERT_TRUE(waitFor([&]{return remote.publicInvite().has_value();}));
    remote.submitCode("000000");
    ASSERT_TRUE(waitFor([&]{return failed.count()>0;}));
    EXPECT_EQ(inviterDone.count(),0); EXPECT_EQ(remoteDone.count(),0);
}

TEST(PairingControllerTests, RejectsSecondConnectionAndOversizedFrame) {
    PairingController inviter;
    QSignalSpy failed(&inviter,&PairingController::failed);
    auto invitation=inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0); ASSERT_TRUE(invitation);
    QTcpSocket one,two; one.connectToHost(QHostAddress::LocalHost,inviter.port()); ASSERT_TRUE(one.waitForConnected(2000));
    two.connectToHost(QHostAddress::LocalHost,inviter.port()); ASSERT_TRUE(two.waitForConnected(2000));
    ASSERT_TRUE(waitFor([&]{return two.state()==QAbstractSocket::UnconnectedState;}));
    QByteArray header; header.append(char(0)); header.append(char(1)); header.append(char(0)); header.append(char(1)); one.write(header); one.flush();
    ASSERT_TRUE(waitFor([&]{return failed.count()>0;}));
}

TEST(PairingWizardTests, PortugueseStepsValidationAndCancellation) {
    PairingWizard wizard(inviterUuid,remoteUuid,QHostAddress::LocalHost,12345);
    wizard.show(); QCoreApplication::processEvents();
    EXPECT_EQ(wizard.windowTitle(),QString::fromUtf8("Adicionar computador"));
    EXPECT_EQ(wizard.currentId(),PairingWizard::EndpointPage);
    wizard.next();
    EXPECT_EQ(wizard.currentId(),PairingWizard::CodePage);
    wizard.setCodeForTest("12"); wizard.next();
    EXPECT_EQ(wizard.currentId(),PairingWizard::CodePage);
    EXPECT_FALSE(wizard.errorText().isEmpty());
    QSignalSpy cancelled(&wizard,&PairingWizard::cancelledSafely);
    wizard.reject(); EXPECT_EQ(cancelled.count(),1);
}

TEST(PairingWizardTests, InviterDisplaysLocalCodeWithoutEditableCodeField) {
    PairingWizard wizard(inviterUuid,remoteUuid,QHostAddress::LocalHost);
    ASSERT_TRUE(wizard.isInviter()); ASSERT_GT(wizard.pairingPort(),0);
    EXPECT_TRUE(QRegularExpression("^[0-9]{6}$").match(wizard.displayCode()).hasMatch());
    EXPECT_EQ(wizard.findChild<QLineEdit*>("pairingCode"),nullptr);
    wizard.reject();
}

TEST(PairingWizardTests, DoesNotClaimClipboardPermissionIsApplied) {
    PairingWizard wizard(inviterUuid,remoteUuid,QHostAddress::LocalHost);
    bool honestText=false;
    for(const auto* label:wizard.findChildren<QLabel*>())
        honestText |= label->text().contains(QString::fromUtf8("Permissões detalhadas serão configuradas depois"));
    EXPECT_TRUE(honestText);
    EXPECT_TRUE(wizard.findChildren<QCheckBox*>().isEmpty());
    wizard.reject();
}

TEST(PairingControllerTests, RejectsForgedSuccessForAnotherSession) {
    PairingService invitationService; auto made=invitationService.createInvite(inviterUuid,remoteUuid); ASSERT_TRUE(made);
    QTcpServer server; ASSERT_TRUE(server.listen(QHostAddress::LocalHost,0));
    PairingController remote; QSignalSpy paired(&remote,&PairingController::paired),failed(&remote,&PairingController::failed);
    remote.connectTo(inviterUuid,remoteUuid,QHostAddress::LocalHost,server.serverPort());
    ASSERT_TRUE(waitFor([&]{return server.hasPendingConnections();})); auto* socket=server.nextPendingConnection(); ASSERT_NE(socket,nullptr);
    socket->write(PairingProtocolCodec::encode(PairingProtocolCodec::invite(made->publicInvite))); socket->flush();
    ASSERT_TRUE(waitFor([&]{return remote.publicInvite().has_value();})); remote.submitCode(made->displayCode);
    ASSERT_TRUE(waitFor([&]{return socket->bytesAvailable()>0;})); socket->readAll();
    socket->write(PairingProtocolCodec::encode(PairingProtocolCodec::success(QByteArray(16,'x')))); socket->flush();
    ASSERT_TRUE(waitFor([&]{return failed.count()>0;})); EXPECT_EQ(paired.count(),0);
}

TEST(PairingControllerTests, CancelledInviteCanBeCreatedAgain) {
    PairingController inviter; ASSERT_TRUE(inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0));
    inviter.cancel(); EXPECT_TRUE(inviter.listen(inviterUuid,remoteUuid,QHostAddress::LocalHost,0));
}
