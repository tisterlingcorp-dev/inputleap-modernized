#include "../src/TransferQueue.h"

#include <gtest/gtest.h>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

namespace {
TransferQueue::Item item(const QUuid& peer = QUuid::createUuid())
{
    TransferQueue::Item value;
    value.transferId = TransferQueue::newTransferId();
    value.peerUuid = peer;
    value.displayName = QStringLiteral("Computador da sala");
    value.sources = {{QDir::cleanPath(QDir::tempPath() + QStringLiteral("/documento.txt")), QStringLiteral("documento.txt")}};
    value.state = TransferQueue::State::Pending;
    value.userEnqueued = true;
    value.createdAtUtc = QDateTime::fromMSecsSinceEpoch(1710000000000, Qt::UTC);
    value.updatedAtUtc = value.createdAtUtc;
    return value;
}

void writeBytes(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write(bytes), bytes.size());
}

int quarantineCount(const QTemporaryDir& dir)
{
    return QDir(dir.path()).entryList({QStringLiteral("fila.json.corrupt-*")}, QDir::Files).size();
}
}

TEST(TransferQueueTests, RoundTripUsesAtomicVersionedStoreWithoutSecrets)
{
    QTemporaryDir dir;
    ASSERT_TRUE(dir.isValid());
    TransferQueue queue(dir.filePath("fila.json"));
    const auto original = item();
    ASSERT_TRUE(queue.enqueue(original));
    QString error;
    ASSERT_TRUE(queue.save(&error)) << error.toStdString();

    QFile raw(queue.storePath());
    ASSERT_TRUE(raw.open(QIODevice::ReadOnly));
    const QByteArray bytes = raw.readAll();
    EXPECT_TRUE(bytes.contains("\"version\":3"));
    EXPECT_FALSE(bytes.contains("psk"));
    EXPECT_FALSE(bytes.contains("pairing"));
    EXPECT_FALSE(bytes.contains("endpoint"));
    EXPECT_FALSE(bytes.contains("port"));

    TransferQueue loaded(queue.storePath());
    ASSERT_EQ(loaded.load(&error), TransferQueue::LoadResult::Loaded) << error.toStdString();
    ASSERT_EQ(loaded.items().size(), 1);
    EXPECT_EQ(loaded.items().front().transferId, original.transferId);
    EXPECT_EQ(loaded.items().front().peerUuid, original.peerUuid);
    EXPECT_EQ(loaded.items().front().sources.front().relativePath, QStringLiteral("documento.txt"));
}

TEST(TransferQueueTests, BatchEnqueueIsPersistedAtomically)
{
    QTemporaryDir dir;
    TransferQueue queue(dir.filePath("fila.json"));
    auto first=item(), second=item();
    ASSERT_TRUE(queue.enqueueMany({first,second}));
    TransferQueue loaded(queue.storePath()); ASSERT_EQ(loaded.load(),TransferQueue::LoadResult::Loaded);
    ASSERT_EQ(loaded.items().size(),2);
    EXPECT_EQ(loaded.items().at(0).transferId,first.transferId);
    EXPECT_EQ(loaded.items().at(1).transferId,second.transferId);
}

TEST(TransferQueueTests, EnqueuePersistsBeforeDispatch)
{
    QTemporaryDir dir;
    const QString path = dir.filePath("fila.json");
    TransferQueue queue(path);
    const auto original = item();
    QString error;
    ASSERT_TRUE(queue.enqueue(original, &error)) << error.toStdString();
    TransferQueue restarted(path);
    ASSERT_EQ(restarted.load(&error), TransferQueue::LoadResult::Loaded) << error.toStdString();
    ASSERT_EQ(restarted.items().size(), 1);
    EXPECT_EQ(restarted.items().front().transferId, original.transferId);
}

TEST(TransferQueueTests, PauseContinueKeepsIdRepeatGetsNewIdAndCancelNeverResumes)
{
    QTemporaryDir dir;
    TransferQueue queue(dir.filePath("fila.json"));
    const auto original = item();
    ASSERT_TRUE(queue.enqueue(original));
    quint64 generation = 0;
    ASSERT_TRUE(queue.markRunning(original.transferId, &generation));
    ASSERT_TRUE(queue.pause(original.transferId));
    ASSERT_TRUE(queue.continueItem(original.transferId));
    EXPECT_EQ(queue.find(original.transferId)->transferId, original.transferId);
    ASSERT_TRUE(queue.cancel(original.transferId));
    EXPECT_FALSE(queue.nextEligible([](const auto&) { return true; }).has_value());
    const auto repeated = queue.repeat(original.transferId);
    ASSERT_TRUE(repeated.has_value());
    EXPECT_NE(*repeated, original.transferId);
    EXPECT_EQ(queue.find(*repeated)->state, TransferQueue::State::Pending);
}

TEST(TransferQueueTests, PendingPauseContinueCanRunAndComplete)
{
    QTemporaryDir dir;TransferQueue queue(dir.filePath("fila.json"));const auto original=item();
    ASSERT_TRUE(queue.enqueue(original));ASSERT_TRUE(queue.pause(original.transferId));ASSERT_TRUE(queue.continueItem(original.transferId));
    quint64 generation=0;ASSERT_TRUE(queue.markRunning(original.transferId,&generation));ASSERT_TRUE(queue.finish(original.transferId,generation,TransferQueue::State::Completed));
    EXPECT_EQ(queue.find(original.transferId)->state,TransferQueue::State::Completed);
}

TEST(TransferQueueTests, DisabledPersistenceRejectsLateMutationAndPreservesDisk)
{
    QTemporaryDir dir;
    const QString path = dir.filePath(QStringLiteral("fila.json"));
    TransferQueue queue(path);
    const auto original = item();
    ASSERT_TRUE(queue.enqueue(original));
    quint64 generation = 0;
    ASSERT_TRUE(queue.markRunning(original.transferId, &generation));
    QFile beforeFile(path);
    ASSERT_TRUE(beforeFile.open(QIODevice::ReadOnly));
    const QByteArray before = beforeFile.readAll();
    beforeFile.close();

    queue.disablePersistence();
    QString error;
    EXPECT_FALSE(queue.finish(original.transferId, generation,
                              TransferQueue::State::Completed, &error));
    EXPECT_FALSE(error.isEmpty());
    ASSERT_TRUE(queue.find(original.transferId).has_value());
    EXPECT_EQ(queue.find(original.transferId)->state, TransferQueue::State::Running);
    error.clear();
    EXPECT_FALSE(queue.pause(original.transferId, &error));
    EXPECT_EQ(queue.find(original.transferId)->state, TransferQueue::State::Running);
    QFile afterFile(path);
    ASSERT_TRUE(afterFile.open(QIODevice::ReadOnly));
    EXPECT_EQ(afterFile.readAll(), before);
}

TEST(TransferQueueTests, RunningIsNormalizedAndPersistedAsPendingOnRestart)
{
    QTemporaryDir dir;
    const QString path = dir.filePath("fila.json");
    TransferQueue queue(path);
    const auto original = item();
    ASSERT_TRUE(queue.enqueue(original));
    quint64 generation = 0;
    ASSERT_TRUE(queue.markRunning(original.transferId, &generation));
    TransferQueue restarted(path);
    ASSERT_EQ(restarted.load(), TransferQueue::LoadResult::Loaded);
    EXPECT_EQ(restarted.find(original.transferId)->state, TransferQueue::State::Pending);
    TransferQueue secondRestart(path);
    ASSERT_EQ(secondRestart.load(), TransferQueue::LoadResult::Loaded);
    EXPECT_EQ(secondRestart.find(original.transferId)->state, TransferQueue::State::Pending);
    QFile raw(path);
    ASSERT_TRUE(raw.open(QIODevice::ReadOnly));
    EXPECT_TRUE(raw.readAll().contains("\"state\":\"pending\""));
}

TEST(TransferQueueTests, ConcurrentSelectionCanChooseAnotherEligiblePeer)
{
    QTemporaryDir dir;TransferQueue queue(dir.filePath("fila.json"));auto first=item(QUuid::createUuid()),second=item(QUuid::createUuid());
    ASSERT_TRUE(queue.enqueueMany({first,second}));quint64 generation=0;ASSERT_TRUE(queue.markRunning(first.transferId,&generation));
    const auto next=queue.nextEligibleConcurrent([&](const auto& candidate){return candidate.peerUuid==second.peerUuid;});
    ASSERT_TRUE(next.has_value());EXPECT_EQ(next->transferId,second.transferId);
}

TEST(TransferQueueTests, SchedulerIsGlobalSerialUsesExactUuidAndIgnoresStaleGeneration)
{
    QTemporaryDir dir;
    TransferQueue queue(dir.filePath("fila.json"));
    const QUuid firstPeer = QUuid::createUuid();
    const QUuid secondPeer = QUuid::createUuid();
    const auto first = item(firstPeer);
    const auto second = item(secondPeer);
    ASSERT_TRUE(queue.enqueue(first));
    ASSERT_TRUE(queue.enqueue(second));
    const auto eligibleSecond = queue.nextEligible([&](const auto& candidate) { return candidate.peerUuid == secondPeer; });
    ASSERT_TRUE(eligibleSecond.has_value());
    EXPECT_EQ(eligibleSecond->transferId, second.transferId);
    quint64 generation = 0;
    ASSERT_TRUE(queue.markRunning(first.transferId, &generation));
    EXPECT_FALSE(queue.nextEligible([](const auto&) { return true; }).has_value());
    EXPECT_FALSE(queue.finish(first.transferId, generation - 1, TransferQueue::State::Completed));
    EXPECT_EQ(queue.find(first.transferId)->state, TransferQueue::State::Running);
    EXPECT_TRUE(queue.finish(first.transferId, generation, TransferQueue::State::Completed));
}

TEST(TransferQueueTests, CorruptStoreIsQuarantinedAndNotLoaded)
{
    QTemporaryDir dir;
    const QString path = dir.filePath("fila.json");
    writeBytes(path, "{not-json");
    TransferQueue queue(path);
    QString error;
    EXPECT_EQ(queue.load(&error), TransferQueue::LoadResult::Corrupt);
    EXPECT_FALSE(QFile::exists(path));
    EXPECT_EQ(quarantineCount(dir), 1);
    EXPECT_TRUE(queue.items().isEmpty());
}

TEST(TransferQueueTests, FutureVersionIsUnsupportedAndPreserved)
{
    QTemporaryDir dir;
    const QString path = dir.filePath("fila.json");
    writeBytes(path, R"({"version":4,"items":[]})");
    TransferQueue queue(path);
    EXPECT_EQ(queue.load(), TransferQueue::LoadResult::Unsupported);
    EXPECT_TRUE(QFile::exists(path));
    EXPECT_EQ(quarantineCount(dir), 0);
}

TEST(TransferQueueTests, UnknownFieldsAreRejectedAndQuarantined)
{
    QTemporaryDir dir;
    const QString path = dir.filePath("fila.json");
    writeBytes(path, R"({"version":1,"items":[],"endpoint":"192.0.2.1"})");
    TransferQueue queue(path);
    EXPECT_EQ(queue.load(), TransferQueue::LoadResult::Corrupt);
    EXPECT_FALSE(QFile::exists(path));
    EXPECT_EQ(quarantineCount(dir), 1);
}

TEST(TransferQueueTests, OversizeStoreIsRejectedAndQuarantinedWithoutReadingIt)
{
    QTemporaryDir dir;
    const QString path = dir.filePath("fila.json");
    writeBytes(path, QByteArray(1024 * 1024 + 1, 'x'));
    TransferQueue queue(path);
    EXPECT_EQ(queue.load(), TransferQueue::LoadResult::Corrupt);
    EXPECT_FALSE(QFile::exists(path));
    EXPECT_EQ(quarantineCount(dir), 1);
}

TEST(TransferQueueTests, RejectsMultipleSourcesPerPersistentItem)
{
    QTemporaryDir dir;TransferQueue queue(dir.filePath("fila.json"));auto value=item();
    value.sources.append({QStringLiteral("C:/dados/outro.txt"),QStringLiteral("outro.txt")});
    EXPECT_FALSE(queue.enqueue(value));EXPECT_TRUE(queue.items().isEmpty());
}

TEST(TransferQueueTests, DuplicateAndNonCanonicalIdsFailClosed)
{
    QTemporaryDir dir;const QString path=dir.filePath("fila.json");TransferQueue queue(path);
    auto first=item();first.transferId=QByteArray(16,char(0xab));auto second=item();second.transferId=QByteArray(16,char(0xcd));
    ASSERT_TRUE(queue.enqueueMany({first,second}));QFile file(path);ASSERT_TRUE(file.open(QIODevice::ReadOnly));QByteArray json=file.readAll();file.close();
    json.replace(second.transferId.toHex(),first.transferId.toHex());writeBytes(path,json);TransferQueue duplicate(path);EXPECT_EQ(duplicate.load(),TransferQueue::LoadResult::Corrupt);

    const QString upperPath=dir.filePath("upper.json");TransferQueue upperStore(upperPath);ASSERT_TRUE(upperStore.enqueue(first));QFile upperFile(upperPath);ASSERT_TRUE(upperFile.open(QIODevice::ReadOnly));
    QByteArray upperJson=upperFile.readAll();upperFile.close();upperJson.replace(first.transferId.toHex(),first.transferId.toHex().toUpper());writeBytes(upperPath,upperJson);
    TransferQueue nonCanonical(upperPath);EXPECT_EQ(nonCanonical.load(),TransferQueue::LoadResult::Corrupt);
}

TEST(TransferQueueTests, SkippedIsPersistedDistinctlyAndOnlyRepeatedExplicitly)
{
    QTemporaryDir dir;TransferQueue queue(dir.filePath("fila.json"));auto value=item();
    ASSERT_TRUE(queue.enqueue(value));quint64 generation=0;ASSERT_TRUE(queue.markRunning(value.transferId,&generation));
    ASSERT_TRUE(queue.finish(value.transferId,generation,TransferQueue::State::Skipped));
    ASSERT_EQ(queue.find(value.transferId)->state,TransferQueue::State::Skipped);
    EXPECT_FALSE(queue.nextEligible([](const auto&){return true;}).has_value());
    TransferQueue reloaded(queue.storePath());ASSERT_EQ(reloaded.load(),TransferQueue::LoadResult::Loaded);
    ASSERT_EQ(reloaded.find(value.transferId)->state,TransferQueue::State::Skipped);
    EXPECT_TRUE(reloaded.repeat(value.transferId).has_value());
}

TEST(TransferQueueTests, PersistentBatchIdentitySurvivesIndependentDispatch)
{
    QTemporaryDir dir;TransferQueue queue(dir.filePath("fila.json"));auto first=item(),second=item();
    const QByteArray batch=QUuid::createUuid().toRfc4122();first.batchId=second.batchId=batch;
    first.batchIndex=0;second.batchIndex=1;first.batchCount=second.batchCount=2;
    ASSERT_TRUE(queue.enqueueMany({first,second}));TransferQueue loaded(queue.storePath());ASSERT_EQ(loaded.load(),TransferQueue::LoadResult::Loaded);
    ASSERT_EQ(loaded.items().size(),2);EXPECT_EQ(loaded.items()[0].batchId,batch);EXPECT_EQ(loaded.items()[1].batchId,batch);
    EXPECT_EQ(loaded.items()[0].batchIndex,0u);EXPECT_EQ(loaded.items()[1].batchIndex,1u);EXPECT_EQ(loaded.items()[1].batchCount,2u);
}
