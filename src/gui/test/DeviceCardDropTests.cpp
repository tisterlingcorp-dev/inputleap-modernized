#include "DeviceCard.h"
#include "DeviceCardDropPolicy.h"
#include <gtest/gtest.h>
#include <QDropEvent>
#include <QDragEnterEvent>
#include <QApplication>
#include <QFile>
#include <QMimeData>
#include <QProgressBar>
#include <QSignalSpy>
#include <QTemporaryDir>

namespace {
DiscoveredDeviceView transferable(const QUuid& id) {
    DiscoveredDeviceView d; d.uuid=id; d.displayName="Peer"; d.state=DeviceConnectionModel::State::Connected;
    d.discoveryAvailable=true; d.compatible=true; d.transferPort=24801; d.addresses.insert("192.0.2.1");
    d.capabilities.insert(ZeroconfCapability::FileTransfer);
    CapabilityAdvertisement advertised; advertised.uuid=id;
    advertised.versions={{CapabilityId::Control,{1,0}},{CapabilityId::FileTransfer,{1,1}}};
    advertised.claimed.insert(CapabilityId::FileTransfer);
    d.negotiation=CapabilityNegotiationPolicy().negotiate(advertised); return d;
}
QString makeFile(QTemporaryDir& dir,const QString& name) { QFile f(dir.filePath(name)); EXPECT_TRUE(f.open(QIODevice::WriteOnly)); f.write("x"); return f.fileName(); }
}

TEST(DeviceCardDropPolicy, AcceptsOnlyBoundedExistingLocalUrlsAndClassifiesConfirmation) {
    QTemporaryDir dir; const QString ordinary=makeFile(dir,"nota.txt"), dangerous=makeFile(dir,"instalar.exe");
    QMimeData local; local.setUrls({QUrl::fromLocalFile(ordinary)});
    auto result=DeviceCardDropPolicy::evaluate(&local); EXPECT_TRUE(result.accepted); EXPECT_EQ(result.confirmation,DeviceCardDropPolicy::Confirmation::None);
    QMimeData remote; remote.setUrls({QUrl("https://example.test/a.txt")}); EXPECT_FALSE(DeviceCardDropPolicy::evaluate(&remote).accepted);
    QMimeData text; text.setText("texto"); EXPECT_FALSE(DeviceCardDropPolicy::evaluate(&text).accepted);
    QMimeData missing; missing.setUrls({QUrl::fromLocalFile(dir.filePath("missing"))}); EXPECT_FALSE(DeviceCardDropPolicy::evaluate(&missing).accepted);
    QMimeData risky; risky.setUrls({QUrl::fromLocalFile(dangerous)}); result=DeviceCardDropPolicy::evaluate(&risky); EXPECT_TRUE(result.accepted); EXPECT_EQ(result.confirmation,DeviceCardDropPolicy::Confirmation::Dangerous);
    QMimeData folder; folder.setUrls({QUrl::fromLocalFile(dir.path())}); result=DeviceCardDropPolicy::evaluate(&folder); EXPECT_TRUE(result.accepted); EXPECT_EQ(result.confirmation,DeviceCardDropPolicy::Confirmation::Directory);
    QList<QUrl> tooMany; for(int i=0;i<101;++i) tooMany << QUrl::fromLocalFile(ordinary); QMimeData count; count.setUrls(tooMany); EXPECT_FALSE(DeviceCardDropPolicy::evaluate(&count).accepted);
}

TEST(DeviceCard, DropTargetsExactUuidAndDisabledCardRejects) {
    QTemporaryDir dir; const QString path=makeFile(dir,"nota.txt"); QMimeData mime; mime.setUrls({QUrl::fromLocalFile(path)});
    const QUuid a=QUuid::createUuid(); DeviceCard card; card.resize(400,200); card.setDevice(transferable(a)); QSignalSpy spy(&card,&DeviceCard::filesDropped);
    QDragEnterEvent enter(QPoint(10,10),Qt::CopyAction,&mime,Qt::LeftButton,Qt::NoModifier); QApplication::sendEvent(&card,&enter); EXPECT_TRUE(enter.isAccepted());
    QDropEvent event(QPointF(10,10),Qt::CopyAction,&mime,Qt::LeftButton,Qt::NoModifier); QApplication::sendEvent(&card,&event);
    ASSERT_EQ(spy.count(),1); EXPECT_EQ(spy.at(0).at(0).toUuid(),a); EXPECT_EQ(spy.at(0).at(1).toStringList(),QStringList{path});
    auto disabled=transferable(QUuid::createUuid()); disabled.state=DeviceConnectionModel::State::Offline; card.setDevice(disabled);
    QDropEvent rejected(QPointF(10,10),Qt::CopyAction,&mime,Qt::LeftButton,Qt::NoModifier); QApplication::sendEvent(&card,&rejected); EXPECT_FALSE(rejected.isAccepted()); EXPECT_EQ(spy.count(),1);
}

TEST(DeviceCard, ProgressIsUuidIsolatedAndCleansUpOnCompletionOrError) {
    const QUuid a=QUuid::createUuid(),b=QUuid::createUuid(); DeviceCard card; card.setDevice(transferable(a));
    card.setTransferProgress(b,"outro",50,100); EXPECT_FALSE(card.findChild<QProgressBar*>("deviceTransferProgress")->isVisibleTo(&card));
    card.setTransferProgress(a,"nota.txt",25,100); auto* bar=card.findChild<QProgressBar*>("deviceTransferProgress"); ASSERT_NE(bar,nullptr); EXPECT_TRUE(bar->isVisibleTo(&card)); EXPECT_EQ(bar->value(),25);
    card.finishTransfer(b,false,"erro"); EXPECT_TRUE(bar->isVisibleTo(&card)); card.finishTransfer(a,true,{}); EXPECT_FALSE(bar->isVisibleTo(&card));
    card.setTransferProgress(a,"nota.txt",1,2); card.finishTransfer(a,false,"Falhou"); EXPECT_FALSE(bar->isVisibleTo(&card));
}
