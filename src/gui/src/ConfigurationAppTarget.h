/* InputLeap -- real AppConfig/environment-profile target for transactional imports. */
#pragma once

#include "ConfigurationImportService.h"
#include "SecureCredentialStore.h"

#include <memory>
#include <thread>

class AppConfig;
class ConfigurationTransactionLock;
class EnvironmentProfileController;
class QLockFile;
class QSettings;

class ConfigurationAppTarget
{
public:
    enum class PendingRecoveryResult { NotNeeded, Recovered, Blocked };

    ConfigurationAppTarget(AppConfig& appConfig,
                           EnvironmentProfileController& profileController);
    ~ConfigurationAppTarget();

    std::optional<ConfigurationPublicSnapshot> snapshot() const;
    ConfigurationImportService::Target target();
    PendingRecoveryResult recoverPendingImport();
    static PendingRecoveryResult recoverPortablePreferencesBeforePreflight(
        QSettings& settings, SecureCredentialStore credentialStore);
    static bool recoverStartupStateBeforePreflight(
        QSettings& settings, SecureCredentialStore credentialStore);

private:
    ConfigurationImportService::MutationResult compareAndApply(
        const ConfigurationPublicSnapshot& candidate,
        const ConfigurationPublicSnapshot& expected);
    ConfigurationImportService::SensitiveReadResult readPairingCode() const;
    ConfigurationImportService::MutationResult writePairingCode(
        const std::optional<SensitiveBytes>& pairingCode,
        const std::optional<SensitiveBytes>& expected);
    ConfigurationImportService::MutationResult beginPending(
        const ConfigurationPublicSnapshot& original,
        const ConfigurationPublicSnapshot& candidate,
        const std::optional<SensitiveBytes>& oldPairingCode,
        const std::optional<SensitiveBytes>& newPairingCode);
    ConfigurationImportService::MutationResult commitPending();
    ConfigurationImportService::MutationResult commitPendingUnlocked();
    ConfigurationImportService::MutationResult abortPending();
    ConfigurationImportService::MutationResult abortPendingUnlocked();
    void assignPreferencesToCache(const ConfigurationPortablePreferences& preferences);
    ConfigurationImportService::MutationResult assignPreferences(
        const ConfigurationPortablePreferences& preferences,
        const ConfigurationPortablePreferences& expected);

    AppConfig& app_config_;
    EnvironmentProfileController& profile_controller_;
    std::unique_ptr<QLockFile> pending_journal_lock_;
    std::unique_ptr<ConfigurationTransactionLock> pending_transaction_lock_;
    bool pending_candidate_applied_ = false;
    std::thread::id pending_owner_thread_;
};
