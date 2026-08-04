/*
 * InputLeap -- mouse and keyboard sharing utility
 */

#include "../src/FileTransferService.h"
#include "../src/FileTransferResume.h"

#include <gtest/gtest.h>

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryDir>
#include <QThread>
#include <QSignalSpy>
#include <QDataStream>
#include <QCryptographicHash>
#include <QTcpSocket>
#include <QHostAddress>
#include <QSslCipher>
#include <QSslSocket>
#include <QSslPreSharedKeyAuthenticator>
#include <QSslConfiguration>

#include <atomic>
#include <thread>
#include <vector>

#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#endif

namespace
{
bool waitFor(const std::atomic_bool& complete, int timeoutMs = 10000)
{
    QElapsedTimer timer;
    timer.start();
    while (!complete.load() && timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        QThread::msleep(5);
    }
    return complete.load();
}

bool sendItemsAndProcessEvents(FileTransferService& receiver,
                               const QList<FileTransferService::TransferItem>& items,
                               QString* errorMessage = nullptr,
                               FileTransferService::ProgressCallback progressCallback = {},
                               FileTransferService::CancelCallback cancelCallback = {},
                               const QUuid& localUuid = {}, const QByteArray& psk = {})
{
    std::atomic_bool complete = false;
    bool sent = false;
    std::thread sender([&]() {
        sent = FileTransferService::sendItems(
            "127.0.0.1", receiver.port(), items, errorMessage,
            std::move(progressCallback), std::move(cancelCallback), {}, localUuid, psk, true);
        complete.store(true);
    });
    const bool completedInTime = waitFor(complete);
    sender.join();
    return completedInTime && sent;
}

QString createFile(const QTemporaryDir& directory, const QString& relativePath, const QByteArray& contents)
{
    const QString path = directory.filePath(relativePath);
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(contents) != contents.size()) {
        return {};
    }
    return path;
}

#ifdef Q_OS_WIN
bool createDirectoryJunction(const QString& junctionPath, const QString& targetPath,
                             bool createDirectory = true, DWORD shareMode = 0)
{
    if (createDirectory && !QDir().mkdir(junctionPath)) return false;
    const QString nativeJunction = QDir::toNativeSeparators(junctionPath);
    const QString nativeTarget = QDir::toNativeSeparators(QFileInfo(targetPath).absoluteFilePath());
    const std::wstring substitute = L"\\??\\" + nativeTarget.toStdWString();
    const std::wstring printName = nativeTarget.toStdWString();
    const DWORD substituteBytes = DWORD(substitute.size() * sizeof(wchar_t));
    const DWORD printBytes = DWORD(printName.size() * sizeof(wchar_t));
    const DWORD pathBytes = substituteBytes + sizeof(wchar_t) + printBytes + sizeof(wchar_t);
    constexpr DWORD headerBytes = 16;
    std::vector<BYTE> storage(headerBytes + pathBytes, 0);
    auto writeWord = [&storage](DWORD offset, WORD value) {
        memcpy(storage.data() + offset, &value, sizeof(value));
    };
    const DWORD tag = IO_REPARSE_TAG_MOUNT_POINT;
    memcpy(storage.data(), &tag, sizeof(tag));
    writeWord(4, WORD(8 + pathBytes));
    writeWord(8, 0);
    writeWord(10, WORD(substituteBytes));
    writeWord(12, WORD(substituteBytes + sizeof(wchar_t)));
    writeWord(14, WORD(printBytes));
    memcpy(storage.data() + headerBytes, substitute.data(), substituteBytes);
    memcpy(storage.data() + headerBytes + substituteBytes + sizeof(wchar_t),
           printName.data(), printBytes);

    HANDLE handle = CreateFileW(
        reinterpret_cast<LPCWSTR>(nativeJunction.utf16()), GENERIC_WRITE, shareMode, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (handle == INVALID_HANDLE_VALUE) return false;
    DWORD returned = 0;
    const BOOL created = DeviceIoControl(
        handle, FSCTL_SET_REPARSE_POINT, storage.data(), DWORD(storage.size()),
        nullptr, 0, &returned, nullptr);
    CloseHandle(handle);
    return created != FALSE;
}

bool removeDirectoryJunctionTag(const QString& junctionPath)
{
    const QString nativeJunction=QDir::toNativeSeparators(junctionPath);
    HANDLE handle=CreateFileW(reinterpret_cast<LPCWSTR>(nativeJunction.utf16()),
        GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr);
    if(handle==INVALID_HANDLE_VALUE)return false;
    std::vector<BYTE> deletion(8,0);
    const DWORD tag=IO_REPARSE_TAG_MOUNT_POINT;
    memcpy(deletion.data(),&tag,sizeof(tag));
    DWORD returned=0;
    const BOOL removed=DeviceIoControl(handle,FSCTL_DELETE_REPARSE_POINT,
        deletion.data(),DWORD(deletion.size()),nullptr,0,&returned,nullptr);
    CloseHandle(handle);
    return removed!=FALSE;
}
#endif

QByteArray sendAuthenticatedV5Blocking(FileTransferService& receiver, const QUuid& tlsPeer,
                                       const QByteArray& psk, const QByteArray& token,
                                       const QString& name, const QByteArray& payload,
                                       quint32 itemIndex=0,quint32 itemCount=1)
{
    QSslSocket socket;
    QObject::connect(&socket, &QSslSocket::preSharedKeyAuthenticationRequired, &socket,
                     [tlsPeer, psk](QSslPreSharedKeyAuthenticator* auth) {
                         auth->setIdentity(QByteArray("inputleap-file-transfer:") +
                                           tlsPeer.toString(QUuid::WithoutBraces).toLower().toLatin1());
                         auth->setPreSharedKey(psk);
                     });
    QSslConfiguration config = socket.sslConfiguration();
    config.setProtocol(QSsl::TlsV1_2);
    QList<QSslCipher> ciphers;
    for (const auto& cipher : QSslConfiguration::defaultConfiguration().supportedCiphers())
        if (FileTransferService::tlsPskCipherNames().contains(cipher.name())) ciphers.append(cipher);
    config.setCiphers(ciphers);
    socket.setSslConfiguration(config);
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    socket.connectToHostEncrypted(QStringLiteral("127.0.0.1"), receiver.port());
    if (!socket.waitForEncrypted(5000)) return {};
    const QByteArray transferId = QUuid::createUuid().toRfc4122();
    const QByteArray batchId = QUuid::createUuid().toRfc4122();
    QByteArray wire;
    QDataStream out(&wire, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << quint32(0x494c4654) << quint16(5) << transferId << itemIndex
        << batchId << itemCount << token << name << quint64(payload.size())
        << QCryptographicHash::hash(payload, QCryptographicHash::Sha256);
    if (socket.write(wire) != wire.size() || !socket.waitForBytesWritten(5000)) return {};
    if (!socket.waitForReadyRead(5000)) return {};
    QByteArray response = socket.readAll();
    if (response.isEmpty() || response.at(0) != 1) return response;
    if (socket.write(payload) != payload.size() || !socket.waitForBytesWritten(5000)) return {};
    while (socket.waitForReadyRead(5000)) response += socket.readAll();
    socket.disconnectFromHost();
    return response;
}

QByteArray sendAuthenticatedV5(FileTransferService& receiver, const QUuid& tlsPeer,
                               const QByteArray& psk, const QByteArray& token,
                               const QString& name, const QByteArray& payload,
                               quint32 itemIndex=0,quint32 itemCount=1)
{
    std::atomic_bool complete = false;
    QByteArray response;
    std::thread sender([&] {
        response = sendAuthenticatedV5Blocking(
            receiver,tlsPeer,psk,token,name,payload,itemIndex,itemCount);
        complete.store(true);
    });
    const bool completedInTime = waitFor(complete);
    sender.join();
    return completedInTime ? response : QByteArray();
}

QByteArray sendAuthenticatedV4Blocking(FileTransferService& receiver,
                                       const QUuid& tlsPeer,
                                       const QByteArray& psk,
                                       const QString& name,
                                       const QByteArray& payload)
{
    QSslSocket socket;
    QObject::connect(&socket, &QSslSocket::preSharedKeyAuthenticationRequired, &socket,
                     [tlsPeer, psk](QSslPreSharedKeyAuthenticator* auth) {
        auth->setIdentity(QByteArray("inputleap-file-transfer:") +
                          tlsPeer.toString(QUuid::WithoutBraces).toLower().toLatin1());
        auth->setPreSharedKey(psk);
    });
    QSslConfiguration config = socket.sslConfiguration();
    config.setProtocol(QSsl::TlsV1_2);
    QList<QSslCipher> ciphers;
    for (const auto& cipher : QSslConfiguration::defaultConfiguration().supportedCiphers())
        if (FileTransferService::tlsPskCipherNames().contains(cipher.name())) ciphers.append(cipher);
    config.setCiphers(ciphers);
    socket.setSslConfiguration(config);
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    socket.connectToHostEncrypted(QStringLiteral("127.0.0.1"), receiver.port());
    if (!socket.waitForEncrypted(5000)) return {};
    QByteArray wire;
    QDataStream out(&wire, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_0);
    out << quint32(0x494c4654) << quint16(4)
        << QUuid::createUuid().toRfc4122() << quint32(0)
        << QUuid::createUuid().toRfc4122() << quint32(1)
        << name << quint64(payload.size())
        << QCryptographicHash::hash(payload, QCryptographicHash::Sha256);
    if (socket.write(wire) != wire.size() || !socket.waitForBytesWritten(5000)) return {};
    if (!socket.waitForReadyRead(5000)) return {};
    QByteArray response = socket.readAll();
    if (!response.isEmpty() && response.at(0) == 1) {
        socket.write(payload);
        socket.waitForBytesWritten(5000);
        while (socket.waitForReadyRead(5000)) response += socket.readAll();
    }
    return response;
}

QByteArray sendAuthenticatedV4(FileTransferService& receiver,
                               const QUuid& tlsPeer,
                               const QByteArray& psk,
                               const QString& name,
                               const QByteArray& payload)
{
    std::atomic_bool complete = false;
    QByteArray response;
    std::thread sender([&] {
        response = sendAuthenticatedV4Blocking(receiver, tlsPeer, psk, name, payload);
        complete.store(true);
    });
    const bool completedInTime = waitFor(complete);
    sender.join();
    return completedInTime ? response : QByteArray();
}
}

TEST(FileTransferServiceTests, PreservesRelativeFolderPathsForMultipleItems)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QString first = createFile(temporaryDirectory, "first.txt", "first");
    const QString second = createFile(temporaryDirectory, "second.txt", "second");
    ASSERT_FALSE(first.isEmpty());
    ASSERT_FALSE(second.isEmpty());

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid(); const QByteArray psk(32, 's');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk);
    receiver.setReceiveDirectory(temporaryDirectory.filePath("received"));
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    const QList<FileTransferService::TransferItem> items = {
        {first, QStringLiteral("folder/first.txt")},
        {second, QStringLiteral("folder/nested/second.txt")}
    };
    QString sendError;
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver, items, &sendError, {}, {}, peerUuid, psk)) << sendError.toStdString();
    EXPECT_TRUE(QFile::exists(temporaryDirectory.filePath("received/folder/first.txt")));
    EXPECT_TRUE(QFile::exists(temporaryDirectory.filePath("received/folder/nested/second.txt")));
}

TEST(FileTransferServiceTests, FileReceivedCarriesAuthenticatedPeerUuid)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source = createFile(directory, QStringLiteral("received.txt"), QByteArrayLiteral("peer identity"));
    ASSERT_FALSE(source.isEmpty());
    const QUuid authenticatedPeer = QUuid::createUuid();
    const QUuid differentPeer = QUuid::createUuid();
    const QByteArray key(32, 'k');

    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; });
    receiver.setReceiveDirectory(directory.filePath(QStringLiteral("received")));
    receiver.setDevicePreSharedKey(authenticatedPeer, key);
    ASSERT_TRUE(receiver.startListening(0));
    QSignalSpy receivedSpy(&receiver, &FileTransferService::fileReceived);

    std::atomic_bool complete = false;
    bool sent = false;
    std::thread sender([&] {
        sent = FileTransferService::sendItems("127.0.0.1", receiver.port(),
            {{source, QStringLiteral("received.txt")}}, nullptr, {}, {}, {}, authenticatedPeer, key, true);
        complete.store(true);
    });
    ASSERT_TRUE(waitFor(complete));
    sender.join();
    ASSERT_TRUE(sent);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 2000);
    ASSERT_EQ(receivedSpy.count(), 1);
    const QList<QVariant> arguments = receivedSpy.takeFirst();
    ASSERT_EQ(arguments.size(), 5);
    EXPECT_EQ(arguments.at(3).toUuid(), authenticatedPeer);
    EXPECT_NE(arguments.at(3).toUuid(), differentPeer);
    EXPECT_FALSE(arguments.at(3).toUuid().isNull());
    EXPECT_FALSE(arguments.at(4).toByteArray().isEmpty());
}

TEST(FileTransferServiceTests, KeepsExistingDestinationAndAddsCollisionSuffix)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QString source = createFile(temporaryDirectory, "source.txt", "new contents");
    ASSERT_FALSE(source.isEmpty());

    const QString receiveDirectory = temporaryDirectory.filePath("received");
    ASSERT_TRUE(QDir().mkpath(receiveDirectory));
    QFile existing(receiveDirectory + "/source.txt");
    ASSERT_TRUE(existing.open(QIODevice::WriteOnly));
    ASSERT_GT(existing.write("existing contents"), 0);
    existing.close();

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid(); const QByteArray psk(32, 'k');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk);
    receiver.setReceiveDirectory(receiveDirectory);
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    QString sendError;
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver, {{source, QStringLiteral("source.txt")}}, &sendError, {}, {}, peerUuid, psk))
        << sendError.toStdString();
    EXPECT_TRUE(QFile::exists(receiveDirectory + "/source.txt"));
    EXPECT_TRUE(QFile::exists(receiveDirectory + "/source (1).txt"));
}

TEST(FileTransferServiceTests, ReportsProgressForLargePayload)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QByteArray payload(2 * 1024 * 1024, 'x');
    const QString source = createFile(temporaryDirectory, "large.bin", payload);
    ASSERT_FALSE(source.isEmpty());

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid(); const QByteArray psk(32, 'p');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk);
    receiver.setReceiveDirectory(temporaryDirectory.filePath("received"));
    QString listenError;
    ASSERT_TRUE(receiver.startListening(0, &listenError)) << listenError.toStdString();

    std::atomic_int progressEvents = 0;
    std::atomic<quint64> lastBytesDone = 0;
    QString sendError;
    ASSERT_TRUE(sendItemsAndProcessEvents(
        receiver,
        {{source, QStringLiteral("large.bin")}},
        &sendError,
        [&](const QString&, quint64 bytesDone, quint64) {
            ++progressEvents;
            lastBytesDone.store(bytesDone);
        }, {}, peerUuid, psk)) << sendError.toStdString();

    EXPECT_GE(progressEvents.load(), 2);
    EXPECT_EQ(lastBytesDone.load(), static_cast<quint64>(payload.size()));
}

TEST(FileTransferServiceTests, RejectsCancellationBeforeConnecting)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QString source = createFile(temporaryDirectory, "cancelled.txt", "cancelled");
    ASSERT_FALSE(source.isEmpty());

    QString errorMessage;
    EXPECT_FALSE(FileTransferService::sendItems(
        "127.0.0.1", 1, {{source, QStringLiteral("cancelled.txt")}}, &errorMessage, {}, []() {
            return true;
        }));
    EXPECT_FALSE(errorMessage.isEmpty());
}

TEST(FileTransferServiceTests, ReportsUnavailablePeer)
{
    QTemporaryDir temporaryDirectory;
    ASSERT_TRUE(temporaryDirectory.isValid());
    const QString source = createFile(temporaryDirectory, "unavailable.txt", "unavailable");
    ASSERT_FALSE(source.isEmpty());

    QString errorMessage;
    EXPECT_FALSE(FileTransferService::sendItems(
        "127.0.0.1", 1, {{source, QStringLiteral("unavailable.txt")}}, &errorMessage));
    EXPECT_FALSE(errorMessage.isEmpty());
}

TEST(FileTransferServiceTests, ResumesInterruptedAuthenticatedTransferWithStableIdentity)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    const QByteArray payload(3*1024*1024,'r');
    const QString source=createFile(directory,"resume.bin",payload); ASSERT_FALSE(source.isEmpty());
    const QUuid senderUuid=QUuid::createUuid(); const QByteArray key(32,'k');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; }); receiver.setReceiveDirectory(directory.filePath("received")); receiver.setDevicePreSharedKey(senderUuid,key);
    QString listenError; ASSERT_TRUE(receiver.startListening(0,&listenError))<<listenError.toStdString();
    FileTransferService::TransferItem item{source,"resume.bin",QByteArray::fromHex("00112233445566778899aabbccddeeff")};

    auto run=[&](FileTransferService::ProgressCallback progress,FileTransferService::CancelCallback cancel,QString* error){
        std::atomic_bool complete=false; bool result=false;
        std::thread sender([&]{result=FileTransferService::sendItems("127.0.0.1",receiver.port(),{item},error,
            std::move(progress),std::move(cancel),{},senderUuid,key,true);complete=true;});
        const bool finished=waitFor(complete,20000); sender.join(); return finished&&result;
    };
    std::atomic_bool interrupt=false; QString firstError;
    EXPECT_FALSE(run([&](const QString&,quint64 done,quint64){if(done>=1024*1024)interrupt=true;},[&]{return interrupt.load();},&firstError));
    for(int i=0;i<20;++i){QCoreApplication::processEvents(QEventLoop::AllEvents,10);QThread::msleep(5);}
    const QByteArray storageId=FileTransferResume::scopedStorageId(senderUuid,item.transferId);
    const QString partPath=FileTransferResume::partPath(receiver.receiveDirectory(),storageId);
    const QString manifestPath=FileTransferResume::manifestPath(receiver.receiveDirectory(),storageId);
    EXPECT_TRUE(QFile::exists(partPath));
    QFile checkpointFile(manifestPath);ASSERT_TRUE(checkpointFile.open(QIODevice::ReadOnly));
    const auto checkpoint=FileTransferResume::decodeManifest(checkpointFile.readAll(),
        FileTransferResume::deriveContextKey(key,"manifest-v1"),senderUuid);
    ASSERT_TRUE(checkpoint.has_value());
    const quint64 expectedResumeOffset=checkpoint->offset;
    EXPECT_GT(expectedResumeOffset,0u);EXPECT_LT(expectedResumeOffset,quint64(payload.size()));
    checkpointFile.close();

    QFile tampered(partPath);ASSERT_TRUE(tampered.open(QIODevice::ReadWrite));
    ASSERT_TRUE(tampered.seek(0));ASSERT_EQ(tampered.write("x",1),1);tampered.close();
    QString tamperedError;
    EXPECT_FALSE(run({}, {}, &tamperedError));
    EXPECT_FALSE(QFile::exists(directory.filePath("received/resume.bin")));
    ASSERT_TRUE(tampered.open(QIODevice::ReadWrite));
    ASSERT_TRUE(tampered.seek(0));ASSERT_EQ(tampered.write("r",1),1);tampered.close();

    quint64 firstReported=0; bool observed=false; QString secondError;
    ASSERT_TRUE(run([&](const QString&,quint64 done,quint64){if(!observed){observed=true;firstReported=done;}},{},&secondError))<<secondError.toStdString();
    EXPECT_EQ(firstReported,expectedResumeOffset);
    QFile received(directory.filePath("received/resume.bin")); ASSERT_TRUE(received.open(QIODevice::ReadOnly)); EXPECT_EQ(received.readAll(),payload); received.close();
    QFile completionFile(manifestPath); ASSERT_TRUE(completionFile.open(QIODevice::ReadOnly));
    const auto completion=FileTransferResume::decodeManifest(completionFile.readAll(),FileTransferResume::deriveContextKey(key,"manifest-v1"),senderUuid);
    ASSERT_TRUE(completion.has_value()); EXPECT_TRUE(completion->completed);
    QString duplicateError; quint64 completedOffset=0;
    ASSERT_TRUE(run([&](const QString&,quint64 done,quint64){completedOffset=done;},{},&duplicateError))<<duplicateError.toStdString();
    EXPECT_EQ(completedOffset,quint64(payload.size()));
    EXPECT_FALSE(QFile::exists(directory.filePath("received/resume (1).bin")));
    EXPECT_TRUE(QFile::exists(manifestPath));
}

TEST(FileTransferServiceTests, InvalidAuthenticatedManifestFailsClosedWithoutDeletingState)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","payload");
    const QString received=directory.filePath("received");ASSERT_TRUE(QDir().mkpath(received));
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'v');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    const QByteArray storageId=FileTransferResume::scopedStorageId(peer,transferId);
    const QString partPath=FileTransferResume::partPath(received,storageId);
    const QString manifestPath=FileTransferResume::manifestPath(received,storageId);
    QFile part(partPath);ASSERT_TRUE(part.open(QIODevice::WriteOnly));
    ASSERT_EQ(part.write("preserve-part"),13);part.close();
    QFile corrupt(manifestPath);ASSERT_TRUE(corrupt.open(QIODevice::WriteOnly));
    ASSERT_EQ(corrupt.write("corrupt-manifest"),16);corrupt.close();

    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    EXPECT_FALSE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                           &error,{}, {},peer,key));
    EXPECT_FALSE(QFile::exists(QDir(received).filePath("target.bin")));
    ASSERT_TRUE(part.open(QIODevice::ReadOnly));EXPECT_EQ(part.readAll(),QByteArray("preserve-part"));part.close();
    ASSERT_TRUE(corrupt.open(QIODevice::ReadOnly));EXPECT_EQ(corrupt.readAll(),QByteArray("corrupt-manifest"));
}

TEST(FileTransferServiceTests, OrphanPartialWithoutManifestIsRemovedBeforeFreshTransfer)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QByteArray payload("fresh-payload");
    const QString source=createFile(directory,"source.bin",payload);
    const QString received=directory.filePath("received");ASSERT_TRUE(QDir().mkpath(received));
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'w');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    const QByteArray storageId=FileTransferResume::scopedStorageId(peer,transferId);
    const QString partPath=FileTransferResume::partPath(received,storageId);
    QFile orphan(partPath);ASSERT_TRUE(orphan.open(QIODevice::WriteOnly));
    ASSERT_EQ(orphan.write("orphan"),6);orphan.close();

    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                          &error,{}, {},peer,key))
        <<error.toStdString();
    QFile published(QDir(received).filePath("target.bin"));
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));EXPECT_EQ(published.readAll(),payload);
    const QString manifestPath=FileTransferResume::manifestPath(received,storageId);
    QFile manifestFile(manifestPath);ASSERT_TRUE(manifestFile.open(QIODevice::ReadOnly));
    const auto saved=FileTransferResume::decodeManifest(manifestFile.readAll(),
        FileTransferResume::deriveContextKey(key,"manifest-v1"),peer);
    ASSERT_TRUE(saved.has_value());EXPECT_TRUE(saved->completed);
    EXPECT_TRUE(QDir(received).entryList(
        {QStringLiteral(".inputleap-manifest-tmp-*")},QDir::Files|QDir::Hidden).isEmpty());
}

TEST(FileTransferServiceTests, FailedManifestPromotionPreservesPreviousAuthenticatedManifest)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QByteArray payload("checkpoint-payload");
    const QString source=createFile(directory,"source.bin",payload);
    const QString received=directory.filePath("received");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'z');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    int promotions=0;FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failManifestPromotion=[&]{return ++promotions==2;};
    receiver.setAtomicPublishTestHooks(hooks);
    ASSERT_TRUE(receiver.startListening(0));QString error;
    EXPECT_FALSE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                           &error,{}, {},peer,key));
    EXPECT_EQ(promotions,2);
    const QByteArray storageId=FileTransferResume::scopedStorageId(peer,transferId);
    const QString manifestPath=FileTransferResume::manifestPath(received,storageId);
    QFile manifestFile(manifestPath);ASSERT_TRUE(manifestFile.open(QIODevice::ReadOnly));
    const auto saved=FileTransferResume::decodeManifest(manifestFile.readAll(),
        FileTransferResume::deriveContextKey(key,"manifest-v1"),peer);
    ASSERT_TRUE(saved.has_value());EXPECT_EQ(saved->offset,0u);EXPECT_FALSE(saved->completed);
    EXPECT_TRUE(QFile::exists(FileTransferResume::partPath(received,storageId)));
    EXPECT_TRUE(QDir(received).entryList(
        {QStringLiteral(".inputleap-manifest-tmp-*")},QDir::Files|QDir::Hidden).isEmpty());
    EXPECT_FALSE(QFile::exists(QDir(received).filePath("target.bin")));
}

TEST(FileTransferServiceTests, AlteredPublishedFileAfterFinalManifestFailureRequiresManualReview)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QByteArray payload("first-published-payload");
    const QString source=createFile(directory,"source.bin",payload);
    const QString received=directory.filePath("received");
    const QString destination=QDir(received).filePath("target.bin");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'y');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failManifestWrite=[](bool completed,bool recovery){return completed&&!recovery;};
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomes(&receiver,&FileTransferService::publicationCompleted);
    QSignalSpy rejected(&receiver,&FileTransferService::fileRejected);
    QSignalSpy receivedSpy(&receiver,&FileTransferService::fileReceived);
    ASSERT_TRUE(receiver.startListening(0));QString error;
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                          &error,{}, {},peer,key))<<error.toStdString();
    ASSERT_EQ(outcomes.count(),1);EXPECT_EQ(receivedSpy.count(),1);
    QFile published(destination);ASSERT_TRUE(published.open(QIODevice::WriteOnly|QIODevice::Truncate));
    const QByteArray external("externally-modified");
    ASSERT_EQ(published.write(external),external.size());published.close();

    error.clear();
    EXPECT_FALSE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                           &error,{}, {},peer,key));
    ASSERT_EQ(outcomes.count(),2);EXPECT_EQ(rejected.count(),1);EXPECT_EQ(receivedSpy.count(),1);
    const auto review=qvariant_cast<FileTransferService::PublicationOutcome>(outcomes.at(1).at(1));
    EXPECT_EQ(review.status,FileTransferService::PublicationStatus::ReviewRequired);
    EXPECT_EQ(review.destinationPath,destination);EXPECT_TRUE(review.recoveryPath.isEmpty());
    EXPECT_EQ(review.peerUuid,peer);EXPECT_EQ(review.transferId,transferId);
    EXPECT_FALSE(QFile::exists(QDir(received).filePath("target (1).bin")));
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));EXPECT_EQ(published.readAll(),external);
}

TEST(FileTransferServiceTests, IndeterminateReplayDoesNotRecreateMissingDestinationDirectories)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","payload");
    const QString received=directory.filePath("received");
    const QString nested=QDir(received).filePath("nested/deeper");
    const QString destination=QDir(nested).filePath("target.bin");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'d');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failManifestWrite=[](bool completed,bool recovery){return completed&&!recovery;};
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomes(&receiver,&FileTransferService::publicationCompleted);
    ASSERT_TRUE(receiver.startListening(0));QString error;
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver,{{source,"nested/deeper/target.bin",transferId}},
                                          &error,{}, {},peer,key));
    ASSERT_TRUE(QFile::remove(destination));
    ASSERT_TRUE(QDir().rmdir(nested));
    ASSERT_TRUE(QDir().rmdir(QDir(received).filePath("nested")));
    error.clear();
    EXPECT_FALSE(sendItemsAndProcessEvents(receiver,{{source,"nested/deeper/target.bin",transferId}},
                                           &error,{}, {},peer,key));
    ASSERT_EQ(outcomes.count(),2);
    EXPECT_EQ(qvariant_cast<FileTransferService::PublicationOutcome>(outcomes.at(1).at(1)).status,
              FileTransferService::PublicationStatus::ReviewRequired);
    EXPECT_FALSE(QFileInfo::exists(QDir(received).filePath("nested")));
}

TEST(FileTransferServiceTests, AlteredReplacementAfterFinalManifestFailureRequiresManualReview)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    const QString received=directory.filePath("received");ASSERT_TRUE(QDir().mkpath(received));
    const QString destination=createFile(directory,"received/target.bin","old");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'e');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    int moved=0;FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase==FileTransferService::AtomicPublishPhase::ExistingMoved)++moved;
    };
    hooks.failManifestWrite=[](bool completed,bool recovery){return completed&&!recovery;};
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomes(&receiver,&FileTransferService::publicationCompleted);
    QSignalSpy rejected(&receiver,&FileTransferService::fileRejected);
    QSignalSpy receivedSpy(&receiver,&FileTransferService::fileReceived);
    ASSERT_TRUE(receiver.startListening(0));QString error;
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                          &error,{}, {},peer,key));
    ASSERT_EQ(outcomes.count(),1);ASSERT_EQ(receivedSpy.count(),1);EXPECT_EQ(moved,1);
    QFile published(destination);ASSERT_TRUE(published.open(QIODevice::WriteOnly|QIODevice::Truncate));
    const QByteArray altered("altered");ASSERT_EQ(published.write(altered),altered.size());published.close();
    error.clear();
    EXPECT_FALSE(sendItemsAndProcessEvents(receiver,{{source,"target.bin",transferId}},
                                           &error,{}, {},peer,key));
    ASSERT_EQ(outcomes.count(),2);EXPECT_EQ(rejected.count(),1);EXPECT_EQ(receivedSpy.count(),1);
    const auto review=qvariant_cast<FileTransferService::PublicationOutcome>(outcomes.at(1).at(1));
    EXPECT_EQ(review.status,FileTransferService::PublicationStatus::ReviewRequired);
    EXPECT_EQ(review.destinationPath,destination);EXPECT_EQ(moved,1);
}

TEST(FileTransferServiceTests, TransfersManySmallFilesInOneServiceRun)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    QList<FileTransferService::TransferItem> items;
    for (int i = 0; i < 48; ++i) {
        const QString name = QStringLiteral("small-%1.txt").arg(i);
        const QString path = createFile(directory, name, QByteArray("item-") + QByteArray::number(i));
        ASSERT_FALSE(path.isEmpty());
        items.append({path, QStringLiteral("batch/") + name});
    }
    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid(); const QByteArray psk(32, 'm');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk); receiver.setReceiveDirectory(directory.filePath("received"));
    QString error; ASSERT_TRUE(receiver.startListening(0, &error)) << error.toStdString();
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver, items, &error, {}, {}, peerUuid, psk)) << error.toStdString();
    for (int i = 0; i < 48; ++i)
        EXPECT_TRUE(QFile::exists(directory.filePath(QStringLiteral("received/batch/small-%1.txt").arg(i))));
}

TEST(FileTransferServiceTests, TransfersLogicallyLargeSparseFileWithoutLargeTestAllocation)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    const QString sourcePath = directory.filePath("sparse-large.bin");
    QFile source(sourcePath); ASSERT_TRUE(source.open(QIODevice::WriteOnly));
    ASSERT_TRUE(source.resize(4 * 1024 * 1024));
    ASSERT_TRUE(source.seek(source.size() - 4)); ASSERT_EQ(source.write("tail", 4), 4); source.close();

    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid(); const QByteArray psk(32, 'l');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); });
    receiver.setDevicePreSharedKey(peerUuid, psk); receiver.setReceiveDirectory(directory.filePath("received"));
    QString error; ASSERT_TRUE(receiver.startListening(0, &error)) << error.toStdString();
    ASSERT_TRUE(sendItemsAndProcessEvents(receiver, {{sourcePath, "sparse-large.bin"}}, &error, {}, {}, peerUuid, psk)) << error.toStdString();
    const QString receivedPath=directory.filePath("received/sparse-large.bin");
    QElapsedTimer receiveWait;receiveWait.start();
    while(QFileInfo(receivedPath).size()!=4*1024*1024&&receiveWait.elapsed()<5000){QCoreApplication::processEvents(QEventLoop::AllEvents,10);QThread::msleep(5);}
    ASSERT_EQ(QFileInfo(receivedPath).size(),4*1024*1024);
    QFile received(receivedPath);
    ASSERT_TRUE(received.open(QIODevice::ReadOnly)); EXPECT_EQ(received.size(), 4 * 1024 * 1024);
    ASSERT_TRUE(received.seek(received.size() - 4)); EXPECT_EQ(received.read(4), QByteArray("tail"));
}

TEST(FileTransferServiceTests, AppliesConfiguredBandwidthLimitToRealChunkLoop)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    const QString source = createFile(directory, "limited.bin", QByteArray(256 * 1024, 'l'));
    ASSERT_FALSE(source.isEmpty());
    FileTransferService receiver;
    const QUuid peerUuid = QUuid::createUuid(); const QByteArray psk(32, 'b');
    receiver.setReceivePermissionCallback([](const QUuid& uuid) { return !uuid.isNull(); }); receiver.setDevicePreSharedKey(peerUuid, psk); receiver.setReceiveDirectory(directory.filePath("received"));
    QString error; ASSERT_TRUE(receiver.startListening(0, &error)) << error.toStdString();

    std::atomic_bool complete = false; bool sent = false; QElapsedTimer elapsed; elapsed.start();
    std::thread sender([&] {
        sent = FileTransferService::sendItems("127.0.0.1", receiver.port(), {{source, "limited.bin"}}, &error,
            {}, {}, {}, peerUuid, psk, true, nullptr, 128 * 1024);
        complete = true;
    });
    EXPECT_TRUE(waitFor(complete, 10000)); sender.join();
    EXPECT_TRUE(sent) << error.toStdString();
    EXPECT_GE(elapsed.elapsed(), 1200); // first 64 KiB burst, then three paced chunks
}

namespace
{
bool sendAuthenticatedConflict(FileTransferService& receiver, const FileTransferService::TransferItem& item,
                    const QUuid& peer, const QByteArray& key, QString* error,
                    FileTransferService::ProgressCallback progress = {},
                    FileTransferService::TransferSummary* summary = nullptr)
{
    std::atomic_bool complete=false; bool sent=false;
    std::thread sender([&]{
        sent=FileTransferService::sendItems("127.0.0.1",receiver.port(),{item},error,std::move(progress),{},
                                            {},peer,key,true,nullptr,0,true,summary);
        complete=true;
    });
    const bool timely=waitFor(complete,20000); sender.join(); return timely&&sent;
}
}

TEST(FileTransferServiceTests, ConflictCallbackMayStopListenerWithoutUsingFreedReceiveState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source = createFile(directory, "source.txt", "new");
    ASSERT_FALSE(source.isEmpty());
    const QString received = directory.filePath("received");
    ASSERT_TRUE(QDir().mkpath(received));
    ASSERT_FALSE(createFile(directory, "received/report.txt", "old").isEmpty());
    const QUuid peer = QUuid::createUuid();
    const QByteArray key(32, 'x');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; });
    receiver.setReceiveDirectory(received);
    receiver.setDevicePreSharedKey(peer, key);
    receiver.setConflictCallback([&receiver](const ConflictRequest&) {
        receiver.stopListening();
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        return ConflictDecision{ConflictAction::Replace, false};
    });
    ASSERT_TRUE(receiver.startListening(0));
    QSignalSpy started(&receiver, &FileTransferService::receivingStarted);
    QSignalSpy completed(&receiver, &FileTransferService::fileReceived);
    QString error;
    FileTransferService::TransferSummary summary;

    EXPECT_FALSE(sendAuthenticatedConflict(receiver,
                                {source, "report.txt", QUuid::createUuid().toRfc4122()},
                                peer, key, &error, {}, &summary));
    EXPECT_EQ(started.count(), 0);
    EXPECT_EQ(completed.count(), 0);
    QFile original(directory.filePath("received/report.txt"));
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(), QByteArray("old"));
}

TEST(FileTransferServiceTests, AuthenticatedV5HonorsReplaceRenameAndSkipExplicitly)
{
    for (const auto action : {ConflictAction::Replace, ConflictAction::Rename, ConflictAction::Skip}) {
        SCOPED_TRACE(static_cast<int>(action));
        QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
        const QString source=createFile(directory,"source.txt","new"); ASSERT_FALSE(source.isEmpty());
        const QString received=directory.filePath("received"); ASSERT_TRUE(QDir().mkpath(received));
        ASSERT_FALSE(createFile(directory,"received/report.txt","old").isEmpty());
        const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'v');
        FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; }); receiver.setReceiveDirectory(received); receiver.setDevicePreSharedKey(peer,key);
        receiver.setConflictCallback([action](const ConflictRequest&){return ConflictDecision{action,false};});
        ASSERT_TRUE(receiver.startListening(0));
        QString error;FileTransferService::TransferSummary summary;
        ASSERT_TRUE(sendAuthenticatedConflict(receiver,{source,"report.txt",QUuid::createUuid().toRfc4122()},peer,key,&error,{},&summary)) << error.toStdString();
        QFile original(directory.filePath("received/report.txt")); ASSERT_TRUE(original.open(QIODevice::ReadOnly));
        EXPECT_EQ(original.readAll(),action==ConflictAction::Replace?QByteArray("new"):QByteArray("old"));
        EXPECT_EQ(QFile::exists(directory.filePath("received/report (1).txt")),action==ConflictAction::Rename);
        EXPECT_EQ(summary.skipped,action==ConflictAction::Skip?1u:0u);
        EXPECT_EQ(summary.transferred,action==ConflictAction::Skip?0u:1u);
        EXPECT_TRUE(QDir(received).entryList(
            {QStringLiteral("InputLeap original *")},QDir::Files).isEmpty());
    }
}

TEST(FileTransferServiceTests, DeduplicatesOnlyExactSecureHashWithoutReceivingPayload)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    const QByteArray payload("identical payload");
    const QString source=createFile(directory,"source.bin",payload); ASSERT_FALSE(source.isEmpty());
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    ASSERT_FALSE(createFile(directory,"received/same.bin",payload).isEmpty());
    const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'d');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; }); receiver.setReceiveDirectory(directory.filePath("received")); receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    QSignalSpy started(&receiver,&FileTransferService::receivingStarted);
    ASSERT_TRUE(receiver.startListening(0));
    quint64 firstProgress=0; QString error;
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,{source,"same.bin",QUuid::createUuid().toRfc4122()},peer,key,&error,
        [&](const QString&,quint64 done,quint64){if(!firstProgress)firstProgress=done;})) << error.toStdString();
    EXPECT_EQ(started.count(),0);
    EXPECT_EQ(firstProgress,quint64(payload.size()));
    EXPECT_FALSE(QFile::exists(directory.filePath("received/same (1).bin")));
}

TEST(FileTransferServiceTests, RevocationDuringExistingDestinationHashCannotDeduplicateOrPublish)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray payload(8 * 1024 * 1024, 'h');
    const QString source = createFile(directory, QStringLiteral("source.bin"), payload);
    ASSERT_FALSE(source.isEmpty());
    const QString receiveDirectory = directory.filePath(QStringLiteral("received"));
    ASSERT_TRUE(QDir().mkpath(receiveDirectory));
    QFile destination(receiveDirectory + QStringLiteral("/source.bin"));
    ASSERT_TRUE(destination.open(QIODevice::WriteOnly));
    ASSERT_EQ(destination.write(payload), payload.size());
    destination.close();

    const QUuid peerUuid = QUuid::createUuid();
    const QByteArray psk(32, 'r');
    std::atomic_int permissionChecks = 0;
    std::atomic_int conflictCalls = 0;
    std::atomic_int incomingCalls = 0;
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([&](const QUuid& uuid) {
        const int check = ++permissionChecks;
        return !uuid.isNull() && check < 2;
    });
    receiver.setConflictCallback([&](const ConflictRequest&) {
        ++conflictCalls;
        return ConflictDecision{ConflictAction::Replace, false};
    });
    receiver.setIncomingFileCallback([&](const QString&, quint64, const QString&, const QUuid&) {
        ++incomingCalls;
        return true;
    });
    receiver.setReceiveDirectory(receiveDirectory);
    receiver.setDevicePreSharedKey(peerUuid, psk);
    ASSERT_TRUE(receiver.startListening(0));
    QSignalSpy receivingSpy(&receiver, &FileTransferService::receivingStarted);
    QSignalSpy receivedSpy(&receiver, &FileTransferService::fileReceived);
    QSignalSpy rejectedSpy(&receiver, &FileTransferService::fileRejected);

    QString sendError;
    EXPECT_FALSE(sendItemsAndProcessEvents(receiver, {{source, QStringLiteral("source.bin")}},
                                           &sendError, {}, {}, peerUuid, psk));
    EXPECT_GE(permissionChecks.load(), 2);
    EXPECT_EQ(conflictCalls.load(), 0);
    EXPECT_EQ(incomingCalls.load(), 0);
    EXPECT_EQ(receivingSpy.count(), 0);
    EXPECT_EQ(receivedSpy.count(), 0);
    EXPECT_LE(rejectedSpy.count(), 1);
    if (rejectedSpy.count() == 1) {
        EXPECT_TRUE(rejectedSpy.at(0).at(0).toString().isEmpty());
        EXPECT_TRUE(rejectedSpy.at(0).at(1).toString().isEmpty());
    }
}

TEST(FileTransferServiceTests, EqualSizeDifferentHashIsNeverDeduplicated)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new!"); ASSERT_FALSE(source.isEmpty());
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    ASSERT_FALSE(createFile(directory,"received/same.bin","old!").isEmpty());
    const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'h');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; }); receiver.setReceiveDirectory(directory.filePath("received")); receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    QSignalSpy started(&receiver,&FileTransferService::receivingStarted); ASSERT_TRUE(receiver.startListening(0));
    QString error; ASSERT_TRUE(sendAuthenticatedConflict(receiver,{source,"same.bin",QUuid::createUuid().toRfc4122()},peer,key,&error)) << error.toStdString();
    EXPECT_EQ(started.count(),1);
    QFile result(directory.filePath("received/same.bin")); ASSERT_TRUE(result.open(QIODevice::ReadOnly)); EXPECT_EQ(result.readAll(),QByteArray("new!"));
}

TEST(FileTransferServiceTests, ExistingSymlinkCannotAuthorizeDedupOrReplacement)
{
    QTemporaryDir directory; ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","payload");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    ASSERT_TRUE(QDir().mkpath(directory.filePath("outside")));
    const QString target=createFile(directory,"outside/target.bin","payload");
    ASSERT_FALSE(source.isEmpty()); ASSERT_FALSE(target.isEmpty());
#ifdef Q_OS_WIN
    ASSERT_TRUE(createDirectoryJunction(
        directory.filePath("received/linked"), directory.filePath("outside")));
#else
    ASSERT_TRUE(QFile::link(
        directory.filePath("outside"), directory.filePath("received/linked")));
#endif
    const QUuid peer=QUuid::createUuid(); const QByteArray key(32,'s');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; }); receiver.setReceiveDirectory(directory.filePath("received")); receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};}); ASSERT_TRUE(receiver.startListening(0));
    QString error; EXPECT_FALSE(sendAuthenticatedConflict(receiver,{source,"linked/target.bin",QUuid::createUuid().toRfc4122()},peer,key,&error));
    QFile unchanged(target); ASSERT_TRUE(unchanged.open(QIODevice::ReadOnly)); EXPECT_EQ(unchanged.readAll(),QByteArray("payload"));
}

#ifdef Q_OS_WIN
TEST(FileTransferServiceTests, AnchoredPublishCreatesNewFileInVerifiedParent)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray payload("anchored normal payload");
    const QString source=createFile(directory,"source.bin",payload);
    const QString receiveRoot=directory.filePath("received");
    const QString parent=directory.filePath("received/subdir");
    const QString destination=directory.filePath("received/subdir/target.bin");
    ASSERT_FALSE(source.isEmpty());
    ASSERT_TRUE(QDir().mkpath(parent));
    ASSERT_TRUE(FileTransferService::secureDirectoryForTests(parent));

    bool observedPinnedWindow=false;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::Committed)return;
        observedPinnedWindow=true;
        const QString movedRoot=directory.filePath("received-moved");
        const QString movedLeaf=directory.filePath("received/subdir/target-moved.bin");
        const QString nativeRoot=QDir::toNativeSeparators(receiveRoot);
        const QString nativeMovedRoot=QDir::toNativeSeparators(movedRoot);
        const BOOL movedRootResult=MoveFileExW(reinterpret_cast<LPCWSTR>(nativeRoot.utf16()),
                                                reinterpret_cast<LPCWSTR>(nativeMovedRoot.utf16()),0);
        const DWORD movedRootError=GetLastError();
        EXPECT_FALSE(movedRootResult);
        EXPECT_EQ(movedRootError,DWORD(ERROR_SHARING_VIOLATION));
        const QString nativeDestination=QDir::toNativeSeparators(destination);
        const QString nativeMovedLeaf=QDir::toNativeSeparators(movedLeaf);
        const BOOL movedLeafResult=MoveFileExW(reinterpret_cast<LPCWSTR>(nativeDestination.utf16()),
                                                reinterpret_cast<LPCWSTR>(nativeMovedLeaf.utf16()),0);
        const DWORD movedLeafError=GetLastError();
        EXPECT_FALSE(movedLeafResult);
        EXPECT_EQ(movedLeafError,DWORD(ERROR_SHARING_VIOLATION));
    };
    const bool publishSucceeded=FileTransferService::atomicPublishForTests(
        source,destination,false,hooks);
    const DWORD publishError=GetLastError();
    ASSERT_TRUE(publishSucceeded)<<"GetLastError="<<publishError;
    EXPECT_TRUE(observedPinnedWindow);
    QFile published(destination);
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),payload);
}

TEST(FileTransferServiceTests, InPlaceParentJunctionAfterPinFailsClosedWithoutEscape)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray payload("rooted despite in-place reparse mutation");
    const QString source=createFile(directory,"source.bin",payload);
    const QString parent=directory.filePath("received/subdir");
    const QString outside=directory.filePath("outside");
    const QString destination=directory.filePath("received/subdir/target.bin");
    ASSERT_FALSE(source.isEmpty());
    ASSERT_TRUE(QDir().mkpath(parent));
    ASSERT_TRUE(QDir().mkpath(outside));
    bool mutated=false;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::AncestorsPinned)return;
        mutated=createDirectoryJunction(parent,outside,false,
                                         FILE_SHARE_READ|FILE_SHARE_WRITE);
        EXPECT_TRUE(mutated);
    };
    EXPECT_FALSE(FileTransferService::atomicPublishForTests(source,destination,false,hooks));
    EXPECT_TRUE(mutated);
    EXPECT_FALSE(QFile::exists(directory.filePath("outside/target.bin")));
    ASSERT_TRUE(removeDirectoryJunctionTag(parent));
    EXPECT_FALSE(QFile::exists(destination));
    QFile unchanged(source);
    ASSERT_TRUE(unchanged.open(QIODevice::ReadOnly));
    EXPECT_EQ(unchanged.readAll(),payload);
}

TEST(FileTransferServiceTests, SourcePathAndBytesCannotChangeAfterSourceHandleIsFixed)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray payload("same handle hash to publish");
    const QString source=createFile(directory,"source.bin",payload);
    const QString movedSource=directory.filePath("source-moved.bin");
    const QString destination=directory.filePath("received/target.bin");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    bool observed=false;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::SourcePinned)return;
        observed=true;
        const QString nativeSource=QDir::toNativeSeparators(source);
        const QString nativeMoved=QDir::toNativeSeparators(movedSource);
        const BOOL moved=MoveFileExW(reinterpret_cast<LPCWSTR>(nativeSource.utf16()),
                                    reinterpret_cast<LPCWSTR>(nativeMoved.utf16()),0);
        const DWORD moveError=GetLastError();
        EXPECT_FALSE(moved);
        EXPECT_EQ(moveError,DWORD(ERROR_SHARING_VIOLATION));
        HANDLE writer=CreateFileW(reinterpret_cast<LPCWSTR>(nativeSource.utf16()),
            GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        const DWORD writeOpenError=GetLastError();
        EXPECT_EQ(writer,INVALID_HANDLE_VALUE);
        EXPECT_EQ(writeOpenError,DWORD(ERROR_SHARING_VIOLATION));
        if(writer!=INVALID_HANDLE_VALUE)CloseHandle(writer);
    };
    ASSERT_TRUE(FileTransferService::atomicPublishForTests(source,destination,false,hooks));
    EXPECT_TRUE(observed);
    QFile published(destination);
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),payload);
}

TEST(FileTransferServiceTests, AuthorizedDestinationCannotBeDeletedOrRenamedBeforeReplaceTransition)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    ASSERT_FALSE(source.isEmpty());
    ASSERT_FALSE(destination.isEmpty());
    bool observed=false;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::SourcePinned)return;
        observed=true;
        const QString nativeDestination=QDir::toNativeSeparators(destination);
        const BOOL deleted=DeleteFileW(reinterpret_cast<LPCWSTR>(nativeDestination.utf16()));
        const DWORD deleteError=GetLastError();
        EXPECT_FALSE(deleted);
        EXPECT_EQ(deleteError,DWORD(ERROR_SHARING_VIOLATION));
        const QString moved=directory.filePath("received/attacker.bin");
        const QString nativeMoved=QDir::toNativeSeparators(moved);
        const BOOL renamed=MoveFileExW(reinterpret_cast<LPCWSTR>(nativeDestination.utf16()),
                                      reinterpret_cast<LPCWSTR>(nativeMoved.utf16()),0);
        const DWORD renameError=GetLastError();
        EXPECT_FALSE(renamed);
        EXPECT_EQ(renameError,DWORD(ERROR_SHARING_VIOLATION));
    };
    QString recovery;
    ASSERT_TRUE(FileTransferService::atomicPublishForTests(
        source,destination,true,hooks,&recovery));
    EXPECT_TRUE(observed);
    EXPECT_TRUE(recovery.isEmpty());
    QFile published(destination);
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),QByteArray("new"));
}

TEST(FileTransferServiceTests, AttackerLeafBetweenReplaceStagesReportsVisibleRecovery)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    ASSERT_FALSE(source.isEmpty());
    ASSERT_FALSE(destination.isEmpty());
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::ExistingMoved)return;
        QFile attacker(destination);
        EXPECT_TRUE(attacker.open(QIODevice::WriteOnly|QIODevice::NewOnly));
        if(attacker.isOpen())EXPECT_EQ(attacker.write("attacker"),qint64(8));
    };
    QString recovery;
    EXPECT_FALSE(FileTransferService::atomicPublishForTests(
        source,destination,true,hooks,&recovery));
    ASSERT_FALSE(recovery.isEmpty());
    QFile attacker(destination);
    ASSERT_TRUE(attacker.open(QIODevice::ReadOnly));
    EXPECT_EQ(attacker.readAll(),QByteArray("attacker"));
    QFile original(recovery);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    EXPECT_TRUE(QFile::exists(source));
    EXPECT_EQ(QDir(directory.filePath("received")).entryList(
        {QStringLiteral("InputLeap original *")},QDir::Files),
        QStringList{QFileInfo(recovery).fileName()});
}

TEST(FileTransferServiceTests, FailedPublishRollsOriginalBackWithoutRecoveryResidue)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    bool publishFailureInjected=false;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failOperation=[&](FileTransferService::AtomicPublishOperation operation){
        if(operation==FileTransferService::AtomicPublishOperation::PublishSource)
            publishFailureInjected=true;
        return operation==FileTransferService::AtomicPublishOperation::PublishSource;
    };
    QString recovery;
    EXPECT_FALSE(FileTransferService::atomicPublishForTests(
        source,destination,true,hooks,&recovery));
    EXPECT_TRUE(recovery.isEmpty());
    QFile original(destination);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    EXPECT_TRUE(QFile::exists(source));
    EXPECT_TRUE(publishFailureInjected);
    EXPECT_TRUE(QDir(directory.filePath("received")).entryList(
        {QStringLiteral("InputLeap original *")},QDir::Files).isEmpty());
}

TEST(FileTransferServiceTests, FailedRollbackLeavesOriginalInReportedVisibleRecovery)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    int publishCalls=0,rollbackCalls=0,cleanupCalls=0;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failOperation=[&](FileTransferService::AtomicPublishOperation operation){
        if(operation==FileTransferService::AtomicPublishOperation::PublishSource)++publishCalls;
        if(operation==FileTransferService::AtomicPublishOperation::RollbackOriginal)++rollbackCalls;
        if(operation==FileTransferService::AtomicPublishOperation::CleanupOriginal)++cleanupCalls;
        return operation==FileTransferService::AtomicPublishOperation::PublishSource||
               operation==FileTransferService::AtomicPublishOperation::RollbackOriginal;
    };
    QString recovery;
    EXPECT_FALSE(FileTransferService::atomicPublishForTests(
        source,destination,true,hooks,&recovery));
    ASSERT_FALSE(recovery.isEmpty());
    EXPECT_FALSE(QFile::exists(destination));
    QFile original(recovery);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    EXPECT_EQ(publishCalls,1);EXPECT_EQ(rollbackCalls,1);EXPECT_EQ(cleanupCalls,0);
}

TEST(FileTransferServiceTests, CleanupFailureIsCommittedAndReportsOriginalRecoveryCopy)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    int publishCalls=0,rollbackCalls=0,cleanupCalls=0;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failOperation=[&](FileTransferService::AtomicPublishOperation operation){
        if(operation==FileTransferService::AtomicPublishOperation::PublishSource)++publishCalls;
        if(operation==FileTransferService::AtomicPublishOperation::RollbackOriginal)++rollbackCalls;
        if(operation==FileTransferService::AtomicPublishOperation::CleanupOriginal)++cleanupCalls;
        return operation==FileTransferService::AtomicPublishOperation::CleanupOriginal;
    };
    QString recovery;
    EXPECT_TRUE(FileTransferService::atomicPublishForTests(
        source,destination,true,hooks,&recovery));
    ASSERT_FALSE(recovery.isEmpty());
    QFile published(destination);
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),QByteArray("new"));
    QFile original(recovery);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    EXPECT_EQ(publishCalls,1);EXPECT_EQ(rollbackCalls,0);EXPECT_EQ(cleanupCalls,1);
}

TEST(FileTransferServiceTests, SuccessfulReplaceObservesCommitAndCleanupAndLeavesNoRecovery)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    QList<FileTransferService::AtomicPublishPhase> phases;
    QString observedRecovery;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString& recovery){
        phases.push_back(phase);
        if(phase==FileTransferService::AtomicPublishPhase::Committed)observedRecovery=recovery;
    };
    QString recovery;
    ASSERT_TRUE(FileTransferService::atomicPublishForTests(source,destination,true,hooks,&recovery));
    EXPECT_EQ(phases,(QList<FileTransferService::AtomicPublishPhase>{
        FileTransferService::AtomicPublishPhase::AncestorsPinned,
        FileTransferService::AtomicPublishPhase::SourcePinned,
        FileTransferService::AtomicPublishPhase::ExistingMoved,
        FileTransferService::AtomicPublishPhase::Committed,
        FileTransferService::AtomicPublishPhase::BeforeCleanup}));
    EXPECT_FALSE(observedRecovery.isEmpty());
    EXPECT_TRUE(recovery.isEmpty());
    EXPECT_FALSE(QFile::exists(observedRecovery));
    EXPECT_TRUE(QDir(directory.filePath("received")).entryList(
        {QStringLiteral("InputLeap original *")},QDir::Files).isEmpty());
}

TEST(FileTransferServiceTests, PublishFailureEmitsTerminalRecoveryOutcomeAndKeepsResumeState)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    const QString received=directory.filePath("received");
    ASSERT_TRUE(QDir().mkpath(received));
    const QString destination=createFile(directory,"received/target.bin","old");
    const QUuid peer=QUuid::createUuid();
    const QByteArray key(32,'o');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);
    receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    int publishCalls=0,rollbackCalls=0;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failOperation=[&](FileTransferService::AtomicPublishOperation operation){
        if(operation==FileTransferService::AtomicPublishOperation::PublishSource)++publishCalls;
        if(operation==FileTransferService::AtomicPublishOperation::RollbackOriginal)++rollbackCalls;
        return operation==FileTransferService::AtomicPublishOperation::PublishSource||
               operation==FileTransferService::AtomicPublishOperation::RollbackOriginal;
    };
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomeSpy(&receiver,&FileTransferService::publicationCompleted);
    QSignalSpy rejectedSpy(&receiver,&FileTransferService::fileRejected);
    QSignalSpy receivedSpy(&receiver,&FileTransferService::fileReceived);
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,{source,"target.bin",transferId},peer,key,&error));
    ASSERT_EQ(outcomeSpy.count(),1);
    EXPECT_EQ(rejectedSpy.count(),1);
    EXPECT_EQ(receivedSpy.count(),0);
    const auto outcome=qvariant_cast<FileTransferService::PublicationOutcome>(outcomeSpy.at(0).at(1));
    EXPECT_EQ(outcome.status,FileTransferService::PublicationStatus::RecoveryRequired);
    EXPECT_EQ(outcome.destinationPath,destination);
    EXPECT_FALSE(outcome.recoveryPath.isEmpty());
    EXPECT_EQ(outcome.peerUuid,peer);
    EXPECT_EQ(outcome.transferId,transferId);
    EXPECT_EQ(rejectedSpy.at(0).at(2).toByteArray(),transferId);
    QFile original(outcome.recoveryPath);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    const QByteArray storageId=FileTransferResume::scopedStorageId(peer,transferId);
    EXPECT_TRUE(QFile::exists(FileTransferResume::partPath(received,storageId)));
    const QString manifestPath=FileTransferResume::manifestPath(received,storageId);
    QFile manifestFile(manifestPath);ASSERT_TRUE(manifestFile.open(QIODevice::ReadOnly));
    QString manifestError;
    const auto manifest=FileTransferResume::decodeManifest(
        manifestFile.readAll(),FileTransferResume::deriveContextKey(key,"manifest-v1"),
        peer,&manifestError);
    ASSERT_TRUE(manifest.has_value())<<manifestError.toStdString();
    EXPECT_EQ(manifest->recoveryPath,outcome.recoveryPath);
    EXPECT_FALSE(manifest->completed);
    EXPECT_EQ(publishCalls,1);EXPECT_EQ(rollbackCalls,1);
    error.clear();
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,{source,"target.bin",transferId},peer,key,&error));
    ASSERT_EQ(outcomeSpy.count(),2);EXPECT_EQ(rejectedSpy.count(),2);
    const auto replayOutcome=qvariant_cast<FileTransferService::PublicationOutcome>(
        outcomeSpy.at(1).at(1));
    EXPECT_EQ(replayOutcome.status,FileTransferService::PublicationStatus::RecoveryRequired);
    EXPECT_EQ(replayOutcome.recoveryPath,outcome.recoveryPath);
    EXPECT_EQ(replayOutcome.transferId,transferId);
    EXPECT_EQ(publishCalls,1);EXPECT_EQ(rollbackCalls,1);
}

TEST(FileTransferServiceTests, RecoveryPreparationManifestFailureLeavesDestinationUnchanged)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    const QString received=directory.filePath("received");ASSERT_TRUE(QDir().mkpath(received));
    const QString destination=createFile(directory,"received/target.bin","old");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'g');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    bool existingMoved=false;FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase==FileTransferService::AtomicPublishPhase::ExistingMoved)existingMoved=true;
    };
    hooks.failManifestWrite=[](bool completed,bool recovery){return !completed&&recovery;};
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomes(&receiver,&FileTransferService::publicationCompleted);
    QSignalSpy rejected(&receiver,&FileTransferService::fileRejected);
    QSignalSpy receivedSpy(&receiver,&FileTransferService::fileReceived);
    ASSERT_TRUE(receiver.startListening(0));QString error;
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,{source,"target.bin",transferId},peer,key,&error));
    ASSERT_EQ(outcomes.count(),1);EXPECT_EQ(rejected.count(),1);EXPECT_EQ(receivedSpy.count(),0);
    const auto outcome=qvariant_cast<FileTransferService::PublicationOutcome>(outcomes.at(0).at(1));
    EXPECT_EQ(outcome.status,FileTransferService::PublicationStatus::Unchanged);
    EXPECT_TRUE(outcome.recoveryPath.isEmpty());EXPECT_FALSE(existingMoved);
    QFile original(destination);ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    EXPECT_TRUE(QDir(received).entryList(
        {QStringLiteral("InputLeap original *")},QDir::Files).isEmpty());
}

TEST(FileTransferServiceTests, RecoveryCommitManifestFailureReportsDurableRecoveryAndNeverCleansIt)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    const QString received=directory.filePath("received");ASSERT_TRUE(QDir().mkpath(received));
    const QString destination=createFile(directory,"received/target.bin","old");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'h');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    int movedCount=0,cleanupCalls=0;FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase==FileTransferService::AtomicPublishPhase::ExistingMoved)++movedCount;
    };
    hooks.failOperation=[&](FileTransferService::AtomicPublishOperation operation){
        if(operation==FileTransferService::AtomicPublishOperation::CleanupOriginal)++cleanupCalls;
        return false;
    };
    hooks.failManifestWrite=[](bool completed,bool recovery){return completed&&recovery;};
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomes(&receiver,&FileTransferService::publicationCompleted);
    QSignalSpy rejected(&receiver,&FileTransferService::fileRejected);
    QSignalSpy receivedSpy(&receiver,&FileTransferService::fileReceived);
    ASSERT_TRUE(receiver.startListening(0));QString error;
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,{source,"target.bin",transferId},peer,key,&error));
    ASSERT_EQ(outcomes.count(),1);EXPECT_EQ(rejected.count(),1);EXPECT_EQ(receivedSpy.count(),0);
    const auto outcome=qvariant_cast<FileTransferService::PublicationOutcome>(outcomes.at(0).at(1));
    EXPECT_EQ(outcome.status,FileTransferService::PublicationStatus::RecoveryRequired);
    EXPECT_FALSE(outcome.recoveryPath.isEmpty());EXPECT_EQ(movedCount,1);EXPECT_EQ(cleanupCalls,0);
    QFile published(destination);ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),QByteArray("new"));
    QFile original(outcome.recoveryPath);ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    const QByteArray storageId=FileTransferResume::scopedStorageId(peer,transferId);
    QFile manifestFile(FileTransferResume::manifestPath(received,storageId));
    ASSERT_TRUE(manifestFile.open(QIODevice::ReadOnly));
    const auto saved=FileTransferResume::decodeManifest(manifestFile.readAll(),
        FileTransferResume::deriveContextKey(key,"manifest-v1"),peer);
    ASSERT_TRUE(saved.has_value());EXPECT_FALSE(saved->completed);
    EXPECT_EQ(saved->recoveryPath,outcome.recoveryPath);manifestFile.close();
    error.clear();
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,{source,"target.bin",transferId},peer,key,&error));
    ASSERT_EQ(outcomes.count(),2);EXPECT_EQ(movedCount,1);EXPECT_EQ(cleanupCalls,0);
    const auto replay=qvariant_cast<FileTransferService::PublicationOutcome>(outcomes.at(1).at(1));
    EXPECT_EQ(replay.status,FileTransferService::PublicationStatus::RecoveryRequired);
    EXPECT_EQ(replay.recoveryPath,outcome.recoveryPath);
}

TEST(FileTransferServiceTests, ReceiveRootSwapBeforePartialOpenCannotCreateOrTruncateOutsideRoot)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"payload.bin","payload");
    ASSERT_FALSE(source.isEmpty());
    const QString receiveRoot=directory.filePath("received");
    const QString movedRoot=directory.filePath("received-original");
    const QString outside=directory.filePath("outside");
    ASSERT_TRUE(QDir().mkpath(receiveRoot));
    ASSERT_TRUE(QDir().mkpath(outside));
    const QString outsideSentinel=createFile(directory,"outside/sentinel.bin","do-not-touch");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'r');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(receiveRoot);receiver.setDevicePreSharedKey(peer,key);
    bool seamReached=false;
    receiver.setAtomicPublishTestHooks({[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::BeforePartialOpen)return;
        seamReached=true;
        EXPECT_TRUE(MoveFileExW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(receiveRoot).utf16()),
                                reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(movedRoot).utf16()),0));
        EXPECT_TRUE(createDirectoryJunction(receiveRoot,outside));
    },{}});
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    const FileTransferService::TransferItem item{
        source,QStringLiteral("payload.bin"),QUuid::createUuid().toRfc4122(),
        QUuid::createUuid().toRfc4122(),0,1};
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,item,peer,key,&error));
    EXPECT_TRUE(seamReached)<<error.toStdString();
    QFile sentinel(outsideSentinel);ASSERT_TRUE(sentinel.open(QIODevice::ReadOnly));
    EXPECT_EQ(sentinel.readAll(),QByteArray("do-not-touch"));
    EXPECT_EQ(QDir(outside).entryList(QDir::Files|QDir::Hidden),QStringList{QStringLiteral("sentinel.bin")});
    EXPECT_TRUE(QDir(movedRoot).entryList(QDir::Files|QDir::Hidden).isEmpty());
}

TEST(FileTransferServiceTests, NestedDirectoryCreationFailsClosedDuringRootJunctionRace)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"payload.bin","payload");
    const QString receiveRoot=directory.filePath("received");
    const QString outside=directory.filePath("outside");
    ASSERT_FALSE(source.isEmpty());ASSERT_TRUE(QDir().mkpath(receiveRoot));
    ASSERT_TRUE(QDir().mkpath(outside));
    const QString sentinel=createFile(directory,"outside/sentinel.bin","do-not-touch");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'d');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(receiveRoot);receiver.setDevicePreSharedKey(peer,key);
    int receiveRootPins=0;bool mutated=false;
    receiver.setAtomicPublishTestHooks({[&](FileTransferService::AtomicPublishPhase phase,const QString& path){
        if(phase!=FileTransferService::AtomicPublishPhase::DirectoryComponentPinned||
           QDir::cleanPath(path)!=QDir::cleanPath(receiveRoot))return;
        if(++receiveRootPins!=2)return;
        mutated=createDirectoryJunction(receiveRoot,outside,false,
                                        FILE_SHARE_READ|FILE_SHARE_WRITE);
    },{}});
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    const FileTransferService::TransferItem item{
        source,QStringLiteral("nested/payload.bin"),QUuid::createUuid().toRfc4122(),
        QUuid::createUuid().toRfc4122(),0,1};
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,item,peer,key,&error));
    EXPECT_EQ(receiveRootPins,2);EXPECT_TRUE(mutated);
    if(mutated)EXPECT_TRUE(removeDirectoryJunctionTag(receiveRoot));
    EXPECT_FALSE(QDir(directory.filePath("received/nested")).exists());
    EXPECT_FALSE(QDir(directory.filePath("outside/nested")).exists());
    QFile unchanged(sentinel);ASSERT_TRUE(unchanged.open(QIODevice::ReadOnly));
    EXPECT_EQ(unchanged.readAll(),QByteArray("do-not-touch"));
    EXPECT_EQ(QDir(outside).entryList(QDir::Files|QDir::Hidden),
              QStringList{QStringLiteral("sentinel.bin")});
}

TEST(FileTransferServiceTests, ReceiveRootJunctionAfterPartialParentPinFailsClosedWithoutEscape)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"payload.bin","payload");
    const QString receiveRoot=directory.filePath("received");
    const QString outside=directory.filePath("outside");
    ASSERT_FALSE(source.isEmpty());
    ASSERT_TRUE(QDir().mkpath(receiveRoot));
    ASSERT_TRUE(QDir().mkpath(outside));
    const QString outsideSentinel=createFile(directory,"outside/sentinel.bin","do-not-touch");
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'p');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(receiveRoot);receiver.setDevicePreSharedKey(peer,key);
    bool seamReached=false,mutated=false;
    receiver.setAtomicPublishTestHooks({[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::PartialParentPinned)return;
        seamReached=true;
        mutated=createDirectoryJunction(receiveRoot,outside,false,
                                        FILE_SHARE_READ|FILE_SHARE_WRITE);
    },{}});
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    const FileTransferService::TransferItem item{
        source,QStringLiteral("payload.bin"),QUuid::createUuid().toRfc4122(),
        QUuid::createUuid().toRfc4122(),0,1};
    const bool sent=sendAuthenticatedConflict(receiver,item,peer,key,&error);
    EXPECT_TRUE(seamReached)<<error.toStdString();
    EXPECT_TRUE(mutated);
    EXPECT_FALSE(sent);
    if(mutated)EXPECT_TRUE(removeDirectoryJunctionTag(receiveRoot));
    QFile sentinel(outsideSentinel);ASSERT_TRUE(sentinel.open(QIODevice::ReadOnly));
    EXPECT_EQ(sentinel.readAll(),QByteArray("do-not-touch"));
    EXPECT_EQ(QDir(outside).entryList(QDir::Files|QDir::Hidden),QStringList{QStringLiteral("sentinel.bin")});
    EXPECT_FALSE(QFile::exists(directory.filePath("received/payload.bin")));
    EXPECT_TRUE(QDir(receiveRoot).entryList(QDir::Files|QDir::Hidden).isEmpty());
}

TEST(FileTransferServiceTests, PublicationChainRejectsDescendantJunctionBeforeDerivation)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"payload.bin","payload");
    const QString receiveRoot=directory.filePath("received");
    const QString destinationParent=QDir(receiveRoot).filePath("nested");
    const QString outside=directory.filePath("outside");
    ASSERT_TRUE(QDir().mkpath(receiveRoot));ASSERT_TRUE(QDir().mkpath(outside));
    const QString sentinel=createFile(directory,"outside/sentinel.txt","do-not-touch");
    ASSERT_FALSE(sentinel.isEmpty());
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'q');
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(receiveRoot);receiver.setDevicePreSharedKey(peer,key);
    bool reached=false;bool mutated=false;
    receiver.setAtomicPublishTestHooks({[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::BeforePublicationChain||reached)return;
        reached=true;mutated=createDirectoryJunction(destinationParent,outside,false,
                                                     FILE_SHARE_READ|FILE_SHARE_WRITE);
    },{}});
    ASSERT_TRUE(receiver.startListening(0));
    QString error;const FileTransferService::TransferItem item{
        source,QStringLiteral("nested/payload.bin"),QUuid::createUuid().toRfc4122(),
        QUuid::createUuid().toRfc4122(),0,1};
    EXPECT_FALSE(sendAuthenticatedConflict(receiver,item,peer,key,&error));
    EXPECT_TRUE(reached);EXPECT_TRUE(mutated);
    if(mutated)EXPECT_TRUE(removeDirectoryJunctionTag(destinationParent));
    EXPECT_FALSE(QFile::exists(QDir(destinationParent).filePath("payload.bin")));
    EXPECT_FALSE(QFile::exists(QDir(outside).filePath("payload.bin")));
    EXPECT_EQ(QDir(outside).entryList(QDir::Files|QDir::Hidden),QStringList{"sentinel.txt"});
    QFile unchanged(sentinel);ASSERT_TRUE(unchanged.open(QIODevice::ReadOnly));
    EXPECT_EQ(unchanged.readAll(),QByteArray("do-not-touch"));
}

TEST(FileTransferServiceTests, CleanupFailureEmitsCommittedWithRecoveryOutcome)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    const QString received=directory.filePath("received");
    ASSERT_TRUE(QDir().mkpath(received));
    const QString destination=createFile(directory,"received/target.bin","old");
    const QUuid peer=QUuid::createUuid();
    const QByteArray key(32,'c');
    const QByteArray transferId=QUuid::createUuid().toRfc4122();
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&){return true;});
    receiver.setReceiveDirectory(received);
    receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([](const ConflictRequest&){return ConflictDecision{ConflictAction::Replace,false};});
    int cleanupCalls=0;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.failOperation=[&](FileTransferService::AtomicPublishOperation operation){
        if(operation==FileTransferService::AtomicPublishOperation::CleanupOriginal)++cleanupCalls;
        return operation==FileTransferService::AtomicPublishOperation::CleanupOriginal;
    };
    receiver.setAtomicPublishTestHooks(hooks);
    QSignalSpy outcomeSpy(&receiver,&FileTransferService::publicationCompleted);
    QSignalSpy rejectedSpy(&receiver,&FileTransferService::fileRejected);
    QSignalSpy receivedSpy(&receiver,&FileTransferService::fileReceived);
    ASSERT_TRUE(receiver.startListening(0));
    QString error;
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,
        {source,"target.bin",transferId},peer,key,&error))<<error.toStdString();
    ASSERT_EQ(outcomeSpy.count(),1);
    EXPECT_EQ(rejectedSpy.count(),0);
    EXPECT_EQ(receivedSpy.count(),1);
    const auto outcome=qvariant_cast<FileTransferService::PublicationOutcome>(outcomeSpy.at(0).at(1));
    EXPECT_EQ(outcome.status,FileTransferService::PublicationStatus::CommittedWithRecovery);
    EXPECT_EQ(outcome.destinationPath,destination);
    EXPECT_EQ(outcome.transferId,transferId);
    EXPECT_EQ(receivedSpy.at(0).at(4).toByteArray(),transferId);
    EXPECT_FALSE(outcome.recoveryPath.isEmpty());
    QFile published(destination);
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),QByteArray("new"));
    QFile original(outcome.recoveryPath);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    EXPECT_EQ(cleanupCalls,1);
    published.close();original.close();error.clear();
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,
        {source,"target.bin",transferId},peer,key,&error))<<error.toStdString();
    ASSERT_EQ(outcomeSpy.count(),1);EXPECT_EQ(receivedSpy.count(),1);
    EXPECT_EQ(cleanupCalls,1);
}

TEST(FileTransferServiceTests, ParentRenameAfterSourcePinFailsAndPublishStaysRooted)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QByteArray payload("anchored publish payload");
    const QString source=createFile(directory,"source.bin",payload);
    const QString destinationParent=directory.filePath("received/subdir");
    const QString parkedParent=directory.filePath("received/authorized-parent");
    const QString outside=directory.filePath("outside");
    const QString destination=directory.filePath("received/subdir/target.bin");
    ASSERT_FALSE(source.isEmpty());
    ASSERT_TRUE(QDir().mkpath(destinationParent));
    ASSERT_TRUE(QDir().mkpath(outside));
    bool attempted=false;
    FileTransferService::AtomicPublishTestHooks hooks;
    hooks.phase=[&](FileTransferService::AtomicPublishPhase phase,const QString&){
        if(phase!=FileTransferService::AtomicPublishPhase::SourcePinned)return;
        attempted=true;
        const QString nativeParent=QDir::toNativeSeparators(destinationParent);
        const QString nativeParked=QDir::toNativeSeparators(parkedParent);
        const BOOL renamed=MoveFileExW(reinterpret_cast<LPCWSTR>(nativeParent.utf16()),
                                      reinterpret_cast<LPCWSTR>(nativeParked.utf16()),0);
        const DWORD renameError=GetLastError();
        EXPECT_FALSE(renamed);
        EXPECT_EQ(renameError,DWORD(ERROR_SHARING_VIOLATION));
    };
    EXPECT_TRUE(FileTransferService::atomicPublishForTests(source,destination,false,hooks));
    EXPECT_TRUE(attempted);
    EXPECT_FALSE(QFileInfo::exists(directory.filePath("outside/target.bin")));
    QFile published(destination);
    ASSERT_TRUE(published.open(QIODevice::ReadOnly));
    EXPECT_EQ(published.readAll(),payload);
}
#endif

#ifndef Q_OS_WIN
TEST(FileTransferServiceTests, UnsupportedAtomicPublishPlatformFailsClosedWithoutMutation)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString source=createFile(directory,"source.bin","new");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString destination=createFile(directory,"received/target.bin","old");
    QString recovery;
    EXPECT_FALSE(FileTransferService::atomicPublishForTests(source,destination,true,{},&recovery));
    EXPECT_TRUE(recovery.isEmpty());
    QFile original(destination);
    ASSERT_TRUE(original.open(QIODevice::ReadOnly));
    EXPECT_EQ(original.readAll(),QByteArray("old"));
    QFile partial(source);
    ASSERT_TRUE(partial.open(QIODevice::ReadOnly));
    EXPECT_EQ(partial.readAll(),QByteArray("new"));
}
#endif

TEST(FileTransferServiceTests, ApplyAllSurvivesSeparatePersistentQueueDispatchesInOneBatch)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString first=createFile(directory,"first.txt","new-a"),second=createFile(directory,"second.txt","new-b");
    ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    ASSERT_FALSE(createFile(directory,"received/a.txt","old-a").isEmpty());ASSERT_FALSE(createFile(directory,"received/b.txt","old-b").isEmpty());
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'q'),batch=QUuid::createUuid().toRfc4122();int prompts=0;
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; });receiver.setReceiveDirectory(directory.filePath("received"));receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([&](const ConflictRequest&){++prompts;return ConflictDecision{ConflictAction::Replace,true};});
    ASSERT_TRUE(receiver.startListening(0));QString error;
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,{first,"a.txt",QUuid::createUuid().toRfc4122(),batch,0,2},peer,key,&error))<<error.toStdString();
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,{second,"b.txt",QUuid::createUuid().toRfc4122(),batch,1,2},peer,key,&error))<<error.toStdString();
    EXPECT_EQ(prompts,1);
}

TEST(FileTransferServiceTests, NonConflictItemIsRecordedAndReplayRequiresFreshDecision)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());ASSERT_TRUE(QDir().mkpath(directory.filePath("received")));
    const QString first=createFile(directory,"first.txt","new-a"),second=createFile(directory,"second.txt","new-b"),replay=createFile(directory,"replay.txt","changed");
    ASSERT_FALSE(createFile(directory,"received/a.txt","old-a").isEmpty());
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'z'),batch=QUuid::createUuid().toRfc4122();int prompts=0;QString error;
    FileTransferService receiver;
    receiver.setReceivePermissionCallback([](const QUuid&) { return true; });receiver.setReceiveDirectory(directory.filePath("received"));receiver.setDevicePreSharedKey(peer,key);
    receiver.setConflictCallback([&](const ConflictRequest&){++prompts;return ConflictDecision{ConflictAction::Replace,true};});ASSERT_TRUE(receiver.startListening(0));
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,{first,"a.txt",QUuid::createUuid().toRfc4122(),batch,0,3},peer,key,&error));
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,{second,"b.txt",QUuid::createUuid().toRfc4122(),batch,1,3},peer,key,&error));
    ASSERT_TRUE(sendAuthenticatedConflict(receiver,{replay,"b.txt",QUuid::createUuid().toRfc4122(),batch,1,3},peer,key,&error));
    EXPECT_EQ(prompts,2);
}

TEST(FileTransferServiceTests, WireV5RejectsUnauthenticatedHeadersBeforeReceiverEffects)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString received = directory.filePath(QStringLiteral("received"));
    ASSERT_TRUE(QDir().mkpath(received));
    const QString destination = received + QStringLiteral("/sensitive.txt");
    ASSERT_FALSE(createFile(directory, QStringLiteral("received/sensitive.txt"), QByteArrayLiteral("original")).isEmpty());

    FileTransferService receiver;
    std::atomic_int permissionCalls = 0;
    std::atomic_int conflictCalls = 0;
    std::atomic_int incomingCalls = 0;
    receiver.setReceiveDirectory(received);
    receiver.setReceivePermissionCallback([&](const QUuid&) { ++permissionCalls; return true; });
    receiver.setConflictCallback([&](const ConflictRequest&) { ++conflictCalls; return ConflictDecision{ConflictAction::Replace, false}; });
    receiver.setIncomingFileCallback([&](const QString&, quint64, const QString&, const QUuid&) { ++incomingCalls; return true; });
    QSignalSpy infoSpy(&receiver, &FileTransferService::info);
    QSignalSpy errorSpy(&receiver, &FileTransferService::error);
    ASSERT_TRUE(receiver.startListening(0));

    for (const QByteArray token : {QByteArray(), QByteArray("tampered-token")}) {
        QTcpSocket socket;
        socket.connectToHost(QStringLiteral("127.0.0.1"), receiver.port());
        ASSERT_TRUE(socket.waitForConnected(5000));
        QByteArray wire;
        QDataStream out(&wire, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_6_0);
        out << quint32(0x494c4654) << quint16(5) << QUuid::createUuid().toRfc4122() << quint32(0)
            << QUuid::createUuid().toRfc4122() << quint32(1);
        if (!token.isEmpty()) out << token;
        out << QStringLiteral("sensitive.txt") << quint64(8)
            << QCryptographicHash::hash(QByteArray("attacker"), QCryptographicHash::Sha256);
        ASSERT_EQ(socket.write(wire), wire.size());
        ASSERT_TRUE(socket.waitForBytesWritten(5000));
        socket.waitForReadyRead(1000);
        socket.disconnectFromHost();
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    }

    EXPECT_EQ(permissionCalls.load(), 0);
    EXPECT_EQ(conflictCalls.load(), 0);
    EXPECT_EQ(incomingCalls.load(), 0);
    QFile unchanged(destination);
    ASSERT_TRUE(unchanged.open(QIODevice::ReadOnly));
    EXPECT_EQ(unchanged.readAll(), QByteArray("original"));
    EXPECT_EQ(QDir(received).entryList(QDir::Files | QDir::NoDotAndDotDot), QStringList() << QStringLiteral("sensitive.txt"));
    for (const auto& signal : infoSpy) EXPECT_FALSE(signal.at(0).toString().contains(QStringLiteral("sensitive")));
    for (const auto& signal : errorSpy) EXPECT_FALSE(signal.at(0).toString().contains(QStringLiteral("sensitive")));
}

TEST(FileTransferServiceTests, AuthenticatedWireV5RejectsManifestMetadataLimitsBeforeEffects)
{
    QTemporaryDir directory;ASSERT_TRUE(directory.isValid());
    const QString received=directory.filePath(QStringLiteral("received"));
    const QUuid peer=QUuid::createUuid();const QByteArray key(32,'q');
    FileTransferService receiver;std::atomic_int permissionCalls=0;int incomingCalls=0,conflictCalls=0;
    receiver.setReceivePermissionCallback([&](const QUuid&){++permissionCalls;return true;});
    receiver.setIncomingFileCallback([&](const QString&,quint64,const QString&,const QUuid&){++incomingCalls;return true;});
    receiver.setConflictCallback([&](const ConflictRequest&){++conflictCalls;return ConflictDecision{ConflictAction::Replace,false};});
    receiver.setReceiveDirectory(received);receiver.setDevicePreSharedKey(peer,key);
    ASSERT_TRUE(receiver.startListening(0));
    const auto endpoint=ProtocolSecurityPolicy::canonicalEndpoint(
        QHostAddress(QStringLiteral("127.0.0.1")),receiver.port());
    ASSERT_TRUE(endpoint.has_value());
    ProtocolSecurityPolicy issuer([]{return QDateTime::currentMSecsSinceEpoch();});
    const auto indexToken=issuer.issue(peer,peer,*endpoint,{"file-transfer:5"},key,300000);
    ASSERT_TRUE(indexToken.has_value());
    EXPECT_TRUE(sendAuthenticatedV5(receiver,peer,key,*indexToken,
        QStringLiteral("nested/target.bin"),QByteArray("x"),10000,10001).isEmpty());
    const auto pathToken=issuer.issue(peer,peer,*endpoint,{"file-transfer:5"},key,300000);
    ASSERT_TRUE(pathToken.has_value());
    EXPECT_TRUE(sendAuthenticatedV5(receiver,peer,key,*pathToken,
        QString(4097,QChar('a')),QByteArray("x")).isEmpty());
    EXPECT_EQ(permissionCalls.load(),0);EXPECT_EQ(incomingCalls,0);EXPECT_EQ(conflictCalls,0);
    EXPECT_FALSE(QFileInfo::exists(received));
}

TEST(FileTransferServiceTests, AuthenticatedWireV5AcceptsAndRejectsBeforeReceiverEffects)
{
    QTemporaryDir directory;
    ASSERT_TRUE(directory.isValid());
    const QString received = directory.filePath(QStringLiteral("received"));
    const QUuid peer = QUuid::createUuid();
    const QUuid otherPeer = QUuid::createUuid();
    const QByteArray key(32, 'v');
    const QByteArray payload("authenticated wire v5");
    FileTransferService receiver;
    std::atomic_int permissionCalls = 0, conflictCalls = 0, incomingCalls = 0;
    receiver.setReceiveDirectory(received);
    receiver.setDevicePreSharedKey(peer, key);
    receiver.setReceivePermissionCallback([&](const QUuid&) { ++permissionCalls; return true; });
    receiver.setConflictCallback([&](const ConflictRequest&) { ++conflictCalls; return ConflictDecision{ConflictAction::Replace, false}; });
    receiver.setIncomingFileCallback([&](const QString&, quint64, const QString&, const QUuid&) { ++incomingCalls; return true; });
    ASSERT_TRUE(receiver.startListening(0));
    const auto endpoint = ProtocolSecurityPolicy::canonicalEndpoint(QHostAddress(QStringLiteral("127.0.0.1")), receiver.port());
    ASSERT_TRUE(endpoint.has_value());
    ProtocolSecurityPolicy issuer([] { return QDateTime::currentMSecsSinceEpoch(); });
    const auto valid = issuer.issue(peer, peer, *endpoint, {"file-transfer:5"}, key, 300000);
    ASSERT_TRUE(valid.has_value());
    ASSERT_FALSE(sendAuthenticatedV5(receiver, peer, key, *valid, QStringLiteral("accepted.txt"), payload).isEmpty());
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    ASSERT_TRUE(QFile::exists(received + QStringLiteral("/accepted.txt")));
    const QStringList filesAfterAccepted = QDir(received).entryList(QDir::Files | QDir::NoDotAndDotDot);
    const int beforePermission = permissionCalls.load();
    const int beforeIncoming = incomingCalls.load();
    const QByteArray downgraded = sendAuthenticatedV4(
        receiver, peer, key, QStringLiteral("downgraded.txt"), payload);
    ASSERT_FALSE(downgraded.isEmpty());
    EXPECT_NE(downgraded.at(0), 1);
    EXPECT_FALSE(QFile::exists(received + QStringLiteral("/downgraded.txt")));
    EXPECT_EQ(permissionCalls.load(), beforePermission);
    EXPECT_EQ(incomingCalls.load(), beforeIncoming);
    const auto endpointMismatch = issuer.issue(peer, peer, QStringLiteral("127.0.0.2:%1").arg(receiver.port()), {"file-transfer:5"}, key, 300000);
    const auto uuidMismatch = issuer.issue(otherPeer, otherPeer, *endpoint, {"file-transfer:5"}, key, 300000);
    const auto downgradeMismatch = issuer.issue(peer, peer, *endpoint, {"file-transfer:4"}, key, 300000);
    ASSERT_TRUE(endpointMismatch.has_value()); ASSERT_TRUE(uuidMismatch.has_value()); ASSERT_TRUE(downgradeMismatch.has_value());
    for (const auto& token : {*endpointMismatch, *uuidMismatch, *downgradeMismatch, *valid})
        EXPECT_FALSE(sendAuthenticatedV5(receiver, peer, key, token, QStringLiteral("blocked.txt"), payload).isEmpty());
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    EXPECT_EQ(permissionCalls.load(), beforePermission);
    EXPECT_EQ(conflictCalls.load(), 0);
    EXPECT_EQ(incomingCalls.load(), beforeIncoming);
    EXPECT_FALSE(QFile::exists(received + QStringLiteral("/blocked.txt")));
    EXPECT_EQ(QDir(received).entryList(QDir::Files | QDir::NoDotAndDotDot), filesAfterAccepted);
}
