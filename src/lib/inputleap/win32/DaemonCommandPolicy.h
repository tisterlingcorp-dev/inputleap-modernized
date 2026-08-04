#pragma once

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace inputleap {

struct ValidatedDaemonCommand
{
    std::string command;
    std::vector<std::string> arguments;
    bool server{false};
};

enum class DaemonCommandDomain
{
    Start,
    Reload,
};

struct AppliedDaemonCommandRequest
{
    std::string nonce;
    std::string command;
    bool elevate{false};
    DaemonCommandDomain domain{DaemonCommandDomain::Start};
};

struct AppliedDaemonStopRequest
{
    std::string requestNonce;
    std::string expectedAppliedNonce;
    bool completionDurable{true};
    bool runtimeStopConfirmed{true};
};

class DaemonCommandPolicy
{
public:
    static bool validateExecutable(const std::vector<std::string>& arguments,
                                   const std::filesystem::path& daemonExecutable,
                                   bool& server);
    static std::optional<ValidatedDaemonCommand> validateCommandLine(
        const std::string& command,
        const std::filesystem::path& daemonExecutable);
    static std::string serializeArguments(
        const std::vector<std::string>& arguments);
    static std::optional<ValidatedDaemonCommand> validatePersistedCommand(
        const std::string& command,
        bool elevate,
        const std::string& policyMarker,
        const std::filesystem::path& daemonExecutable);
    static bool applyPersistedCommand(bool persisted,
                                      const std::function<void()>& apply);
    static bool persistApplyAndAcknowledge(
        const std::string& command, bool elevate,
        const std::function<bool(const std::string&, const std::string&)>& persist,
        const std::function<bool()>& apply,
        const std::function<void()>& acknowledge);
    static bool persistApplyAndAcknowledgeOnce(
        const std::string& command, bool elevate, const std::string& requestNonce,
        std::optional<AppliedDaemonCommandRequest>& lastAppliedRequest,
        const std::function<bool(const std::string&, const std::string&)>& persist,
        const std::function<bool()>& apply,
        const std::function<void()>& acknowledge,
        const std::string& reloadExpectedNonce = {});
    static std::optional<AppliedDaemonCommandRequest> restoreAppliedRequest(
        const std::string& command, bool elevate, const std::string& requestNonce,
        const std::string& policyMarker, const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {});
    static bool persistStopAndAcknowledgeOnce(
        const std::string& requestNonce,
        const std::string& expectedAppliedNonce,
        std::optional<AppliedDaemonStopRequest>& lastAppliedRequest,
        const std::function<bool(const std::string&, const std::string&)>& persist,
        const std::function<bool()>& stop,
        const std::function<void()>& acknowledge);
    static std::optional<AppliedDaemonStopRequest> restoreAppliedStopRequest(
        const std::string& requestNonce,
        const std::string& expectedAppliedNonce,
        const std::string& policyMarker,
        const std::string& appliedNonce);
    static std::string persistedCommandMarker(const std::string& command, bool elevate);
    static std::string persistedCommandMarker(
        const std::string& command, bool elevate, const std::string& requestNonce);
    static std::string persistedCommandMarker(
        const std::string& command, bool elevate, const std::string& requestNonce,
        const std::string& reloadExpectedNonce);
    static std::string persistedStopMarker(
        const std::string& requestNonce,
        const std::string& expectedAppliedNonce);
    static std::filesystem::path currentProcessExecutable();
};

} // namespace inputleap
