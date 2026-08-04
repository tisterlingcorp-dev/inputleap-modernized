#include "inputleap/win32/DaemonTopologyTransaction.h"
#include "server/Config.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace inputleap {
namespace {

class DaemonTopologyTransactionTests : public testing::Test
{
protected:
    void SetUp() override
    {
        const auto suffix = std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
        root_ = std::filesystem::temp_directory_path() /
            ("inputleap-topology-transaction-" + suffix);
        std::filesystem::create_directories(root_);
        configPath_ = root_ / "authoritative.sgc";
        activePayload_ = topologyPayload(false);
        candidatePayload_ = topologyPayload(true);
        write(configPath_, activePayload_);
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    static std::string topologyPayload(bool includePeer)
    {
        Config config;
        EXPECT_TRUE(config.addScreen("primary"));
        if (includePeer) {
            EXPECT_TRUE(config.addScreen("peer"));
        }
        std::ostringstream payload;
        payload << config;
        return payload.str();
    }

    static void write(const std::filesystem::path& path, const std::string& value)
    {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(stream.is_open());
        stream.write(value.data(), static_cast<std::streamsize>(value.size()));
        ASSERT_TRUE(stream.good());
    }

    static std::string read(const std::filesystem::path& path)
    {
        std::ifstream stream(path, std::ios::binary);
        EXPECT_TRUE(stream.is_open());
        return std::string(
            std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>());
    }

    TopologyTransactionRequest request(
        const std::string& requestNonce = "fedcba9876543210",
        const std::string& expectedGeneration = "0123456789abcdef",
        const std::string& payload = {}) const
    {
        return {requestNonce, expectedGeneration,
                payload.empty() ? candidatePayload_ : payload, "primary"};
    }

    std::filesystem::path root_;
    std::filesystem::path configPath_;
    std::string activePayload_;
    std::string candidatePayload_;
};

TEST_F(DaemonTopologyTransactionTests,
       AppliesCandidateAndPersistsGenerationBeforeReportingSuccess)
{
    DaemonTopologyTransaction transaction(configPath_);
    int candidateApplies = 0;
    int rollbacks = 0;

    const auto result = transaction.apply(
        request(), "0123456789abcdef",
        { [&] { ++candidateApplies; return true; },
          [&] { ++rollbacks; return true; } });

    EXPECT_EQ(result.status, TopologyTransactionStatus::Applied) << result.error;
    EXPECT_EQ(result.generation, "fedcba9876543210");
    EXPECT_EQ(candidateApplies, 1);
    EXPECT_EQ(rollbacks, 0);
    EXPECT_EQ(read(configPath_), candidatePayload_);
    EXPECT_FALSE(std::filesystem::exists(transaction.journalPath()));
    EXPECT_FALSE(std::filesystem::exists(transaction.backupPath()));
    EXPECT_FALSE(std::filesystem::exists(transaction.candidatePath()));
}

TEST_F(DaemonTopologyTransactionTests,
       RejectsStaleExpectedGenerationWithoutTouchingFileOrRuntime)
{
    DaemonTopologyTransaction transaction(configPath_);
    int runtimeCalls = 0;

    const auto result = transaction.apply(
        request("fedcba9876543210", "stale-gen-123456"),
        "0123456789abcdef",
        { [&] { ++runtimeCalls; return true; },
          [&] { ++runtimeCalls; return true; } });

    EXPECT_EQ(result.status, TopologyTransactionStatus::Rejected);
    EXPECT_EQ(runtimeCalls, 0);
    EXPECT_EQ(read(configPath_), activePayload_);
    EXPECT_FALSE(std::filesystem::exists(transaction.journalPath()));
}

TEST_F(DaemonTopologyTransactionTests,
       ReplaysIdenticalCommittedRequestWithoutReapplyingRuntime)
{
    DaemonTopologyTransaction transaction(configPath_);
    ASSERT_EQ(transaction.apply(
        request(), "0123456789abcdef", { [] { return true; }, [] { return true; } }).status,
        TopologyTransactionStatus::Applied);
    int runtimeCalls = 0;

    const auto replay = transaction.apply(
        request(), "fedcba9876543210",
        { [&] { ++runtimeCalls; return true; },
          [&] { ++runtimeCalls; return true; } });

    EXPECT_EQ(replay.status, TopologyTransactionStatus::Replayed) << replay.error;
    EXPECT_EQ(runtimeCalls, 0);
}

TEST_F(DaemonTopologyTransactionTests,
       CleanRestartReportsDurablyCommittedGeneration)
{
    DaemonTopologyTransaction transaction(configPath_);
    ASSERT_EQ(transaction.apply(
        request(), "0123456789abcdef",
        { [] { return true; }, [] { return true; } }).status,
        TopologyTransactionStatus::Applied);

    DaemonTopologyTransaction reconstructed(configPath_);
    const auto recovery = reconstructed.recover();

    EXPECT_EQ(recovery.action, TopologyRecoveryAction::Committed)
        << recovery.error;
    EXPECT_EQ(recovery.requestNonce, "fedcba9876543210");
    EXPECT_EQ(recovery.expectedGeneration, "0123456789abcdef");
}

TEST_F(DaemonTopologyTransactionTests,
       RejectsTamperedAuthoritativeFileAgainstCommittedReceipt)
{
    DaemonTopologyTransaction transaction(configPath_);
    ASSERT_EQ(transaction.apply(
        request(), "0123456789abcdef",
        { [] { return true; }, [] { return true; } }).status,
        TopologyTransactionStatus::Applied);
    write(configPath_, activePayload_);
    int runtimeCalls = 0;

    const auto result = transaction.apply(
        request("abcdef0123456789", "fedcba9876543210"),
        "fedcba9876543210",
        { [&] { ++runtimeCalls; return true; },
          [&] { ++runtimeCalls; return true; } });

    EXPECT_EQ(result.status, TopologyTransactionStatus::Rejected);
    EXPECT_EQ(runtimeCalls, 0);
}

TEST_F(DaemonTopologyTransactionTests,
       CleanRestartFailsClosedWhenCommittedFileWasTampered)
{
    DaemonTopologyTransaction transaction(configPath_);
    ASSERT_EQ(transaction.apply(
        request(), "0123456789abcdef",
        { [] { return true; }, [] { return true; } }).status,
        TopologyTransactionStatus::Applied);
    write(configPath_, activePayload_);

    DaemonTopologyTransaction reconstructed(configPath_);
    const auto recovery = reconstructed.recover();

    EXPECT_EQ(recovery.action, TopologyRecoveryAction::Failed);
}

TEST_F(DaemonTopologyTransactionTests,
       RejectsRequestNonceCollisionWithDifferentPayload)
{
    DaemonTopologyTransaction transaction(configPath_);
    ASSERT_EQ(transaction.apply(
        request(), "0123456789abcdef", { [] { return true; }, [] { return true; } }).status,
        TopologyTransactionStatus::Applied);
    const auto differentPayload = topologyPayload(false);
    int runtimeCalls = 0;

    const auto collision = transaction.apply(
        request("fedcba9876543210", "0123456789abcdef", differentPayload),
        "fedcba9876543210",
        { [&] { ++runtimeCalls; return true; },
          [&] { ++runtimeCalls; return true; } });

    EXPECT_EQ(collision.status, TopologyTransactionStatus::Rejected);
    EXPECT_EQ(runtimeCalls, 0);
    EXPECT_EQ(read(configPath_), candidatePayload_);
}

TEST_F(DaemonTopologyTransactionTests,
       FailedCandidateApplicationRestoresFileAndConfirmedRuntime)
{
    DaemonTopologyTransaction transaction(configPath_);
    int candidateApplies = 0;
    int rollbacks = 0;

    const auto result = transaction.apply(
        request(), "0123456789abcdef",
        { [&] { ++candidateApplies; return false; },
          [&] { ++rollbacks; return true; } });

    EXPECT_EQ(result.status, TopologyTransactionStatus::Rejected);
    EXPECT_EQ(candidateApplies, 1);
    EXPECT_EQ(rollbacks, 1);
    EXPECT_EQ(read(configPath_), activePayload_);
    EXPECT_FALSE(std::filesystem::exists(transaction.journalPath()));
}

TEST_F(DaemonTopologyTransactionTests,
       UnconfirmedRuntimeRollbackKeepsJournalForCrashRecovery)
{
    DaemonTopologyTransaction transaction(configPath_);

    const auto result = transaction.apply(
        request(), "0123456789abcdef",
        { [] { return false; }, [] { return false; } });

    ASSERT_EQ(result.status, TopologyTransactionStatus::RollbackFailed);
    EXPECT_EQ(read(configPath_), activePayload_);
    ASSERT_TRUE(std::filesystem::exists(transaction.journalPath()));
    ASSERT_TRUE(std::filesystem::exists(transaction.backupPath()));

    DaemonTopologyTransaction reconstructed(configPath_);
    const auto recovery = reconstructed.recover();

    EXPECT_EQ(recovery.action, TopologyRecoveryAction::RolledBack) << recovery.error;
    EXPECT_EQ(recovery.requestNonce, "fedcba9876543210");
    EXPECT_EQ(recovery.expectedGeneration, "0123456789abcdef");
    EXPECT_EQ(read(configPath_), activePayload_);
    EXPECT_TRUE(std::filesystem::exists(reconstructed.journalPath()));
    EXPECT_TRUE(std::filesystem::exists(reconstructed.backupPath()));

    reconstructed.finalizeRecovery();

    EXPECT_FALSE(std::filesystem::exists(reconstructed.journalPath()));
    EXPECT_FALSE(std::filesystem::exists(reconstructed.backupPath()));
}

TEST_F(DaemonTopologyTransactionTests,
       MalformedCandidateIsRejectedBeforeJournalOrRuntime)
{
    DaemonTopologyTransaction transaction(configPath_);
    int runtimeCalls = 0;

    const auto result = transaction.apply(
        request("fedcba9876543210", "0123456789abcdef", "invalid topology\n"),
        "0123456789abcdef",
        { [&] { ++runtimeCalls; return true; },
          [&] { ++runtimeCalls; return true; } });

    EXPECT_EQ(result.status, TopologyTransactionStatus::Rejected);
    EXPECT_EQ(runtimeCalls, 0);
    EXPECT_EQ(read(configPath_), activePayload_);
    EXPECT_FALSE(std::filesystem::exists(transaction.journalPath()));
}

} // namespace
} // namespace inputleap
