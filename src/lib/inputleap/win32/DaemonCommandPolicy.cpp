#include "inputleap/win32/DaemonCommandPolicy.h"

#include "inputleap/ArgParser.h"
#include "inputleap/ClientArgs.h"
#include "inputleap/ServerArgs.h"
#include "io/filesystem.h"

#include <windows.h>

#include <cwchar>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <vector>

namespace inputleap {
namespace {

bool equalInsensitive(const std::filesystem::path& left,
                      const std::filesystem::path& right)
{
    return _wcsicmp(left.native().c_str(), right.native().c_str()) == 0;
}

std::string quoteWindowsArgument(const std::string& argument)
{
    if (!argument.empty() &&
        argument.find_first_of(" \t\"") == std::string::npos) {
        return argument;
    }

    std::string quoted = "\"";
    std::size_t backslashes = 0;
    for (const char character : argument) {
        if (character == '\\') {
            ++backslashes;
            continue;
        }
        if (character == '"') {
            quoted.append(backslashes * 2 + 1, '\\');
            quoted.push_back('"');
        }
        else {
            quoted.append(backslashes, '\\');
            quoted.push_back(character);
        }
        backslashes = 0;
    }
    quoted.append(backslashes * 2, '\\');
    quoted.push_back('"');
    return quoted;
}

std::string assembleWindowsCommand(const std::vector<std::string>& arguments)
{
    std::ostringstream command;
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        if (i != 0) {
            command << ' ';
        }
        command << quoteWindowsArgument(arguments[i]);
    }
    return command.str();
}

std::optional<std::filesystem::path> pathFromUtf8(const std::string& value)
{
    if (value.empty()) {
        return std::nullopt;
    }
    const int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (size <= 0) {
        return std::nullopt;
    }
    std::wstring wide(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            wide.data(), size) != size) {
        return std::nullopt;
    }
    return std::filesystem::path(wide);
}

bool persistCommandTransaction(
    const std::string& command, bool elevate, const std::string& requestNonce,
    const std::string& marker,
    const std::function<bool(const std::string&, const std::string&)>& persist,
    const std::function<bool()>& apply,
    const std::function<void()>& acknowledge)
{
    if (!persist("CommandPolicyVersion", std::string()) ||
        !persist("CommandAppliedNonce", std::string()) ||
        !persist("CommandReloadExpectedNonce", std::string()) ||
        !persist("Command", command) ||
        !persist("Elevate", elevate ? std::string("1") : std::string("0")) ||
        !persist("CommandRequestNonce", requestNonce) ||
        !persist("CommandPolicyVersion", marker)) {
        return false;
    }
    if (!apply()) {
        return false;
    }
    acknowledge();
    return true;
}

} // namespace

std::string DaemonCommandPolicy::serializeArguments(
    const std::vector<std::string>& arguments)
{
    return assembleWindowsCommand(arguments);
}

bool DaemonCommandPolicy::validateExecutable(
    const std::vector<std::string>& arguments,
    const std::filesystem::path& daemonExecutable,
    bool& server)
{
    server = false;
    if (arguments.empty()) {
        return false;
    }

    const auto requested = pathFromUtf8(arguments.front());
    if (!requested || !requested->is_absolute() || !daemonExecutable.is_absolute()) {
        return false;
    }

    std::error_code error;
    const auto daemon = std::filesystem::canonical(daemonExecutable, error);
    if (error) {
        return false;
    }
    const auto executable = std::filesystem::canonical(*requested, error);
    if (error || !equalInsensitive(executable.parent_path(), daemon.parent_path())) {
        return false;
    }

    const auto filename = executable.filename();
    if (equalInsensitive(filename, L"input-leaps.exe")) {
        server = true;
        return true;
    }
    if (equalInsensitive(filename, L"input-leapc.exe")) {
        server = false;
        return true;
    }
    return false;
}

std::optional<ValidatedDaemonCommand> DaemonCommandPolicy::validateCommandLine(
    const std::string& command,
    const std::filesystem::path& daemonExecutable)
{
    if (command.find('\0') != std::string::npos ||
        command.find(static_cast<char>(13)) != std::string::npos ||
        command.find(static_cast<char>(10)) != std::string::npos) {
        return std::nullopt;
    }

    std::vector<std::string> arguments;
    std::string mutableCommand = command;
    ArgParser::splitCommandString(mutableCommand, arguments);
    bool server = false;
    if (!validateExecutable(arguments, daemonExecutable, server)) {
        return std::nullopt;
    }

    std::error_code error;
    const auto requested = pathFromUtf8(arguments.front());
    if (!requested) {
        return std::nullopt;
    }
    const auto executable = std::filesystem::canonical(*requested, error);
    if (error) {
        return std::nullopt;
    }
    arguments.front() = path_to_utf8(executable);

    ArgParser parser(nullptr);
    const char** argv = parser.getArgv(arguments);
    const int argc = static_cast<int>(arguments.size());
    bool parsed = false;
    ServerArgs serverArgs;
    if (server) {
        parsed = parser.parseServerArgs(serverArgs, argc, argv);
    }
    else {
        ClientArgs args;
        parsed = parser.parseClientArgs(args, argc, argv);
    }
    delete[] argv;
    if (!parsed) {
        return std::nullopt;
    }

    if (server && !serverArgs.m_configFile.empty()) {
        const auto configPath = path_from_utf8(serverArgs.m_configFile);
        if (!configPath.is_absolute()) {
            return std::nullopt;
        }
        const auto canonicalConfig =
            std::filesystem::weakly_canonical(configPath, error);
        const auto profileDirectory = canonicalConfig.parent_path();
        if (error || canonicalConfig.empty() || profileDirectory.empty()) {
            return std::nullopt;
        }

        std::optional<std::size_t> configArgumentIndex;
        for (std::size_t i = 1; i + 1 < arguments.size(); ++i) {
            if (arguments[i] == "-c" || arguments[i] == "--config") {
                configArgumentIndex = i + 1;
                ++i;
            }
        }
        if (!configArgumentIndex) {
            return std::nullopt;
        }
        arguments[*configArgumentIndex] = path_to_utf8(canonicalConfig);

        if (serverArgs.m_profileDirectory.empty()) {
            arguments.emplace_back("--profile-dir");
            arguments.emplace_back(path_to_utf8(profileDirectory));
        }
        else {
            if (!serverArgs.m_profileDirectory.is_absolute()) {
                return std::nullopt;
            }
            const auto requestedProfile = std::filesystem::weakly_canonical(
                serverArgs.m_profileDirectory, error);
            if (error || !equalInsensitive(requestedProfile, profileDirectory)) {
                return std::nullopt;
            }

            std::optional<std::size_t> profileArgumentIndex;
            for (std::size_t i = 1; i + 1 < arguments.size(); ++i) {
                if (arguments[i] == "--profile-dir") {
                    profileArgumentIndex = i + 1;
                    ++i;
                }
            }
            if (!profileArgumentIndex) {
                return std::nullopt;
            }
            arguments[*profileArgumentIndex] = path_to_utf8(profileDirectory);
        }
    }

    return ValidatedDaemonCommand{
        serializeArguments(arguments), arguments, server};
}

std::optional<ValidatedDaemonCommand> DaemonCommandPolicy::validatePersistedCommand(
    const std::string& command,
    bool elevate,
    const std::string& policyMarker,
    const std::filesystem::path& daemonExecutable)
{
    if (policyMarker != persistedCommandMarker(command, elevate)) {
        return std::nullopt;
    }
    return validateCommandLine(command, daemonExecutable);
}

bool DaemonCommandPolicy::applyPersistedCommand(
    bool persisted, const std::function<void()>& apply)
{
    if (!persisted) {
        return false;
    }
    apply();
    return true;
}

bool DaemonCommandPolicy::persistApplyAndAcknowledge(
    const std::string& command, bool elevate,
    const std::function<bool(const std::string&, const std::string&)>& persist,
    const std::function<bool()>& apply,
    const std::function<void()>& acknowledge)
{
    const std::string marker = command.empty()
        ? std::string()
        : persistedCommandMarker(command, elevate);
    return persistCommandTransaction(
        command, elevate, std::string(), marker, persist, apply, acknowledge);
}

bool DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
    const std::string& command, bool elevate, const std::string& requestNonce,
    std::optional<AppliedDaemonCommandRequest>& lastAppliedRequest,
    const std::function<bool(const std::string&, const std::string&)>& persist,
    const std::function<bool()>& apply,
    const std::function<void()>& acknowledge,
    const std::string& reloadExpectedNonce)
{
    if (requestNonce.empty()) {
        return persistApplyAndAcknowledge(command, elevate, persist, apply, acknowledge);
    }

    const auto domain = reloadExpectedNonce.empty()
        ? DaemonCommandDomain::Start
        : DaemonCommandDomain::Reload;
    if (lastAppliedRequest && lastAppliedRequest->nonce == requestNonce) {
        if (lastAppliedRequest->command == command &&
            lastAppliedRequest->elevate == elevate &&
            lastAppliedRequest->domain == domain) {
            acknowledge();
            return true;
        }
        return false;
    }

    if (!persist("CommandAppliedNonce", std::string()) ||
        !persist("CommandPolicyVersion", std::string()) ||
        !persist("Command", command) ||
        !persist("Elevate", elevate ? std::string("1") : std::string("0")) ||
        !persist("CommandRequestNonce", requestNonce) ||
        !persist("CommandReloadExpectedNonce", reloadExpectedNonce) ||
        !persist("CommandPolicyVersion",
                 reloadExpectedNonce.empty()
                     ? persistedCommandMarker(command, elevate, requestNonce)
                     : persistedCommandMarker(
                         command, elevate, requestNonce, reloadExpectedNonce))) {
        return false;
    }
    if (!apply() || !persist("CommandAppliedNonce", requestNonce)) {
        return false;
    }
    lastAppliedRequest = AppliedDaemonCommandRequest{
        requestNonce, command, elevate, domain};
    acknowledge();
    return true;
}

std::optional<AppliedDaemonCommandRequest> DaemonCommandPolicy::restoreAppliedRequest(
    const std::string& command, bool elevate, const std::string& requestNonce,
    const std::string& policyMarker, const std::string& appliedNonce,
    const std::string& reloadExpectedNonce)
{
    const auto expectedMarker = reloadExpectedNonce.empty()
        ? persistedCommandMarker(command, elevate, requestNonce)
        : persistedCommandMarker(
            command, elevate, requestNonce, reloadExpectedNonce);
    if (command.empty() || requestNonce.empty() || appliedNonce != requestNonce ||
        policyMarker != expectedMarker) {
        return std::nullopt;
    }
    return AppliedDaemonCommandRequest{
        requestNonce, command, elevate,
        reloadExpectedNonce.empty()
            ? DaemonCommandDomain::Start
            : DaemonCommandDomain::Reload};
}

bool DaemonCommandPolicy::persistStopAndAcknowledgeOnce(
    const std::string& requestNonce,
    const std::string& expectedAppliedNonce,
    std::optional<AppliedDaemonStopRequest>& lastAppliedRequest,
    const std::function<bool(const std::string&, const std::string&)>& persist,
    const std::function<bool()>& stop,
    const std::function<void()>& acknowledge)
{
    if (requestNonce.size() != 16 || expectedAppliedNonce.size() != 16 ||
        requestNonce == expectedAppliedNonce) {
        return false;
    }
    if (lastAppliedRequest && lastAppliedRequest->requestNonce == requestNonce) {
        if (lastAppliedRequest->expectedAppliedNonce != expectedAppliedNonce) {
            return false;
        }
        if (!lastAppliedRequest->runtimeStopConfirmed) {
            if (!stop()) {
                return false;
            }
            lastAppliedRequest->runtimeStopConfirmed = true;
        }
        if (!lastAppliedRequest->completionDurable) {
            if (!persist("CommandStopAppliedNonce", requestNonce)) {
                return false;
            }
            lastAppliedRequest->completionDurable = true;
        }
        acknowledge();
        return true;
    }

    if (!persist("CommandStopAppliedNonce", std::string()) ||
        !persist("CommandStopPolicyVersion", std::string()) ||
        !persist("CommandStopRequestNonce", requestNonce) ||
        !persist("CommandStopExpectedAppliedNonce", expectedAppliedNonce) ||
        !persist("CommandStopPolicyVersion",
                 persistedStopMarker(requestNonce, expectedAppliedNonce)) ||
        !persist("CommandPolicyVersion", std::string()) ||
        !persist("CommandAppliedNonce", std::string()) ||
        !persist("CommandReloadExpectedNonce", std::string()) ||
        !persist("Command", std::string()) ||
        !persist("Elevate", std::string("0")) ||
        !persist("CommandRequestNonce", std::string()) ||
        !stop()) {
        return false;
    }

    lastAppliedRequest = AppliedDaemonStopRequest{
        requestNonce, expectedAppliedNonce, false, true};
    if (!persist("CommandStopAppliedNonce", requestNonce)) {
        return false;
    }
    lastAppliedRequest->completionDurable = true;
    acknowledge();
    return true;
}

std::optional<AppliedDaemonStopRequest>
DaemonCommandPolicy::restoreAppliedStopRequest(
    const std::string& requestNonce,
    const std::string& expectedAppliedNonce,
    const std::string& policyMarker,
    const std::string& appliedNonce)
{
    if (requestNonce.size() != 16 || expectedAppliedNonce.size() != 16 ||
        requestNonce == expectedAppliedNonce ||
        (!appliedNonce.empty() && appliedNonce != requestNonce) ||
        policyMarker != persistedStopMarker(
            requestNonce, expectedAppliedNonce)) {
        return std::nullopt;
    }
    return AppliedDaemonStopRequest{
        requestNonce, expectedAppliedNonce, appliedNonce == requestNonce,
        appliedNonce == requestNonce};
}

std::string DaemonCommandPolicy::persistedCommandMarker(
    const std::string& command, bool elevate)
{
    // The registry ACL is the trust boundary. This deterministic digest is a
    // commit marker that prevents torn writes from combining fields belonging
    // to different accepted commands; it is not intended as a MAC.
    std::uint64_t digest = 14695981039346656037ull;
    const auto append = [&digest](unsigned char byte) {
        digest ^= byte;
        digest *= 1099511628211ull;
    };
    for (const unsigned char byte : std::string("authenticated-ipc-v2\0", 21)) {
        append(byte);
    }
    for (const unsigned char byte : command) {
        append(byte);
    }
    append(0);
    append(elevate ? 1 : 0);

    std::ostringstream marker;
    marker << "authenticated-ipc-v2:" << std::hex << std::setw(16)
           << std::setfill('0') << digest;
    return marker.str();
}

std::string DaemonCommandPolicy::persistedCommandMarker(
    const std::string& command, bool elevate, const std::string& requestNonce)
{
    std::uint64_t digest = 14695981039346656037ull;
    const auto append = [&digest](unsigned char byte) {
        digest ^= byte;
        digest *= 1099511628211ull;
    };
    for (const unsigned char byte : std::string("authenticated-ipc-v3\0", 21)) {
        append(byte);
    }
    for (const unsigned char byte : command) {
        append(byte);
    }
    append(0);
    append(elevate ? 1 : 0);
    append(0);
    for (const unsigned char byte : requestNonce) {
        append(byte);
    }

    std::ostringstream marker;
    marker << "authenticated-ipc-v3:" << std::hex << std::setw(16)
           << std::setfill('0') << digest;
    return marker.str();
}

std::string DaemonCommandPolicy::persistedCommandMarker(
    const std::string& command, bool elevate, const std::string& requestNonce,
    const std::string& reloadExpectedNonce)
{
    std::uint64_t digest = 14695981039346656037ull;
    const auto append = [&digest](unsigned char byte) {
        digest ^= byte;
        digest *= 1099511628211ull;
    };
    for (const unsigned char byte : std::string("authenticated-ipc-v4\0", 21)) {
        append(byte);
    }
    for (const unsigned char byte : command) {
        append(byte);
    }
    append(0);
    append(elevate ? 1 : 0);
    append(0);
    for (const unsigned char byte : requestNonce) {
        append(byte);
    }
    append(0);
    for (const unsigned char byte : reloadExpectedNonce) {
        append(byte);
    }

    std::ostringstream marker;
    marker << "authenticated-ipc-v4:" << std::hex << std::setw(16)
           << std::setfill('0') << digest;
    return marker.str();
}

std::string DaemonCommandPolicy::persistedStopMarker(
    const std::string& requestNonce,
    const std::string& expectedAppliedNonce)
{
    std::uint64_t digest = 14695981039346656037ull;
    const auto append = [&digest](unsigned char byte) {
        digest ^= byte;
        digest *= 1099511628211ull;
    };
    for (const unsigned char byte :
         std::string("authenticated-ipc-stop-v1\0", 26)) {
        append(byte);
    }
    for (const unsigned char byte : requestNonce) {
        append(byte);
    }
    append(0);
    for (const unsigned char byte : expectedAppliedNonce) {
        append(byte);
    }

    std::ostringstream marker;
    marker << "authenticated-ipc-stop-v1:" << std::hex << std::setw(16)
           << std::setfill('0') << digest;
    return marker.str();
}

std::filesystem::path DaemonCommandPolicy::currentProcessExecutable()
{
    std::vector<wchar_t> buffer(512);
    for (;;) {
        const DWORD size = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (size == 0) {
            return {};
        }
        if (size < buffer.size() - 1) {
            return std::filesystem::path(std::wstring(buffer.data(), size));
        }
        if (buffer.size() >= 32768) {
            return {};
        }
        buffer.resize(buffer.size() * 2);
    }
}

} // namespace inputleap
