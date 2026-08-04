#pragma once

#include <filesystem>
#include <functional>
#include <string>

namespace inputleap {

struct TopologyTransactionRequest
{
    std::string requestNonce;
    std::string expectedGeneration;
    std::string payload;
    std::string primaryScreen;
};

struct TopologyTransactionServices
{
    std::function<bool()> applyCandidate;
    std::function<bool()> applyRollback;
};

enum class TopologyTransactionStatus
{
    Applied,
    Replayed,
    Rejected,
    RollbackFailed,
};

struct TopologyTransactionResult
{
    TopologyTransactionStatus status{TopologyTransactionStatus::Rejected};
    std::string generation;
    std::string error;
};

enum class TopologyRecoveryAction
{
    None,
    Committed,
    RolledBack,
    Failed,
};

struct TopologyRecoveryResult
{
    TopologyRecoveryAction action{TopologyRecoveryAction::None};
    std::string requestNonce;
    std::string expectedGeneration;
    std::string error;
};

class DaemonTopologyTransaction
{
public:
    struct JournalRecord;
    struct StateRecord;

    explicit DaemonTopologyTransaction(std::filesystem::path authoritativeConfigPath);

    TopologyTransactionResult apply(
        const TopologyTransactionRequest& request,
        const std::string& authoritativeGeneration,
        const TopologyTransactionServices& services);
    TopologyRecoveryResult recover();
    void finalizeRecovery();

    const std::filesystem::path& configPath() const { return configPath_; }
    const std::filesystem::path& journalPath() const { return journalPath_; }
    const std::filesystem::path& backupPath() const { return backupPath_; }
    const std::filesystem::path& candidatePath() const { return candidatePath_; }
    const std::filesystem::path& statePath() const { return statePath_; }

private:
    bool restoreOriginal(const JournalRecord& journal, std::string& error) const;
    void cleanupArtifacts() const;

    std::filesystem::path configPath_;
    std::filesystem::path journalPath_;
    std::filesystem::path backupPath_;
    std::filesystem::path candidatePath_;
    std::filesystem::path statePath_;
};

} // namespace inputleap
