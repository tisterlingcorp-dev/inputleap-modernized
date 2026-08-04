#include "inputleap/win32/DaemonCommandPolicy.h"
#include "inputleap/win32/DaemonApp.h"
#include "arch/win32/ArchMiscWindows.h"
#include "io/filesystem.h"
#include "server/Config.h"

#include <windows.h>

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace inputleap {

struct DaemonAppCommandTransactionTestAccess
{
    using Services = DaemonApp::CommandTransactionServices;

    static void useServices(DaemonApp& app, Services services)
    {
        app.m_commandTransactionServicesOverride = std::move(services);
    }
    static bool start(DaemonApp& app, const std::string& command,
                      bool elevate, const std::string& nonce)
    {
        return app.applyStartTransaction(command, elevate, nonce);
    }
    static bool start(DaemonApp& app, const std::string& command,
                      bool elevate, const std::string& nonce,
                      std::function<bool()> applyRuntimeConfiguration)
    {
        return app.applyStartTransaction(
            command, elevate, nonce, std::move(applyRuntimeConfiguration));
    }
    static bool stop(DaemonApp& app, const std::string& nonce)
    {
        return app.applyStopTransaction(nonce, {});
    }
    static bool stop(DaemonApp& app, const std::string& nonce,
                     const std::string& expectedAppliedNonce)
    {
        return app.applyStopTransaction(nonce, expectedAppliedNonce);
    }
    static bool reload(DaemonApp& app, const std::string& requestNonce,
                       const std::string& expectedAppliedNonce)
    {
        return app.applyReloadTransaction(requestNonce, expectedAppliedNonce);
    }
    static bool restoreStartRequest(
        DaemonApp& app, const std::string& command, bool elevate,
        const std::string& nonce, const std::string& policyMarker,
        const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {})
    {
        return app.restorePersistedStartRequest(
            command, command, elevate, nonce, policyMarker, appliedNonce,
            reloadExpectedNonce);
    }
    static bool applyRestoredStart(
        DaemonApp& app, const std::string& command, bool elevate,
        const std::string& nonce, const std::string& policyMarker,
        const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {})
    {
        return app.applyRestoredStartTransaction(
            command, command, elevate, nonce, policyMarker, appliedNonce,
            reloadExpectedNonce);
    }
    static bool applyRestoredStart(
        DaemonApp& app, const std::string& acceptedCommand,
        const std::string& persistedCommand, bool elevate,
        const std::string& nonce, const std::string& policyMarker,
        const std::string& appliedNonce,
        const std::string& reloadExpectedNonce = {})
    {
        return app.applyRestoredStartTransaction(
            acceptedCommand, persistedCommand, elevate, nonce, policyMarker,
            appliedNonce, reloadExpectedNonce);
    }
    static bool hasStartAuthority(const DaemonApp& app)
    {
        return app.m_lastAppliedStartRequest.has_value();
    }
    static bool hasReloadAuthority(const DaemonApp& app)
    {
        return app.m_lastAppliedReloadRequest.has_value();
    }
    static bool hasStopAuthority(const DaemonApp& app)
    {
        return app.m_lastAppliedStopRequest.has_value();
    }
    static bool restoreStopRequest(
        DaemonApp& app, const std::string& requestNonce,
        const std::string& expectedAppliedNonce,
        const std::string& policyMarker, const std::string& appliedNonce)
    {
        return app.restorePersistedStopRequest(
            requestNonce, expectedAppliedNonce, policyMarker, appliedNonce);
    }
};

struct DaemonAppTopologyTransactionTestAccess
{
    static void configureAuthority(
        DaemonApp& app, const std::filesystem::path& path,
        const std::string& primaryScreen)
    {
        app.m_topologyAuthority = DaemonApp::TopologyAuthority{
            path, primaryScreen};
    }

    static TopologyTransactionResult apply(
        DaemonApp& app, const std::string& requestNonce,
        const std::string& expectedGeneration,
        const std::string& payload)
    {
        return app.applyTopologyTransaction(
            IpcTopologyRequestMessage(
                requestNonce, expectedGeneration, payload), nullptr);
    }

    static std::string appliedGeneration(const DaemonApp& app)
    {
        return app.m_lastAppliedStartRequest
            ? app.m_lastAppliedStartRequest->nonce : std::string();
    }

    static bool recoverAndApply(
        DaemonApp& app, const std::filesystem::path& path,
        const std::string& primaryScreen, const std::string& command,
        const std::string& startNonce)
    {
        return app.applyRestoredTopologyTransaction(
            DaemonApp::TopologyAuthority{path, primaryScreen},
            command, command, false, startNonce,
            DaemonCommandPolicy::persistedCommandMarker(
                command, false, startNonce),
            startNonce, {});
    }

    static bool configureAuthorityFromCommand(
        DaemonApp& app, const ValidatedDaemonCommand& command)
    {
        app.m_topologyAuthority = app.topologyAuthorityForCommand(command);
        return app.m_topologyAuthority.has_value();
    }
};

namespace {

class DaemonCommandPolicyTests : public testing::Test
{
protected:
    void SetUp() override
    {
        const auto suffix = std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
        root_ = std::filesystem::temp_directory_path() / ("inputleap-command-policy-" + suffix);
        daemonDir_ = root_ / "daemon dir";
        otherDir_ = root_ / "other";
        std::filesystem::create_directories(daemonDir_);
        std::filesystem::create_directories(otherDir_);
        touch(daemonDir_ / "input-leapd.exe");
        touch(daemonDir_ / "input-leaps.exe");
        touch(daemonDir_ / "input-leapc.exe");
        touch(daemonDir_ / "powershell.exe");
        touch(otherDir_ / "input-leaps.exe");
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    static void touch(const std::filesystem::path& path)
    {
        std::ofstream(path, std::ios::binary).put('\0');
    }

    std::filesystem::path root_;
    std::filesystem::path daemonDir_;
    std::filesystem::path otherDir_;
};

TEST_F(DaemonCommandPolicyTests, AllowsServerBesideDaemon)
{
    bool server = false;
    const std::vector<std::string> args{
        (daemonDir_ / "input-leaps.exe").string(), "--address", "127.0.0.1"};

    EXPECT_TRUE(DaemonCommandPolicy::validateExecutable(
        args, daemonDir_ / "input-leapd.exe", server));
    EXPECT_TRUE(server);
}

TEST_F(DaemonCommandPolicyTests, AllowsClientBesideDaemon)
{
    bool server = true;
    const std::vector<std::string> args{
        (daemonDir_ / "input-leapc.exe").string(), "server"};

    EXPECT_TRUE(DaemonCommandPolicy::validateExecutable(
        args, daemonDir_ / "input-leapd.exe", server));
    EXPECT_FALSE(server);
}

TEST_F(DaemonCommandPolicyTests, RejectsArbitraryExecutableBesideDaemon)
{
    bool server = false;
    const std::vector<std::string> args{
        (daemonDir_ / "powershell.exe").string(), "-Command", "whoami"};

    EXPECT_FALSE(DaemonCommandPolicy::validateExecutable(
        args, daemonDir_ / "input-leapd.exe", server));
}

TEST_F(DaemonCommandPolicyTests, RejectsAllowedNameFromDifferentDirectory)
{
    bool server = false;
    const std::vector<std::string> args{(otherDir_ / "input-leaps.exe").string()};

    EXPECT_FALSE(DaemonCommandPolicy::validateExecutable(
        args, daemonDir_ / "input-leapd.exe", server));
}

TEST_F(DaemonCommandPolicyTests, RejectsRelativeExecutable)
{
    bool server = false;
    const std::vector<std::string> args{"input-leaps.exe"};

    EXPECT_FALSE(DaemonCommandPolicy::validateExecutable(
        args, daemonDir_ / "input-leapd.exe", server));
}

TEST_F(DaemonCommandPolicyTests, RejectsEmptyArguments)
{
    bool server = false;
    EXPECT_FALSE(DaemonCommandPolicy::validateExecutable(
        {}, daemonDir_ / "input-leapd.exe", server));
}

TEST_F(DaemonCommandPolicyTests, AllowsPersistedServerCommandWithValidArguments)
{
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.1";

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");
    ASSERT_TRUE(validated.has_value());
    EXPECT_EQ(validated->arguments.front(),
              path_to_utf8(daemonDir_ / "input-leaps.exe"));
    EXPECT_EQ(validated->command, command);
}

TEST_F(DaemonCommandPolicyTests,
       ServerConfigDerivesExplicitProfileDirectoryForServiceRuntime)
{
    const auto profile = root_ / "user profile";
    std::filesystem::create_directories(profile);
    const auto config = profile / "runtime.conf";
    touch(config);
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --config \"" + config.string() + "\"";

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");

    ASSERT_TRUE(validated.has_value());
    EXPECT_EQ(validated->command,
              command + " --profile-dir \"" + profile.string() + "\"");
}

TEST_F(DaemonCommandPolicyTests,
       ServerConfigCanonicalizesConfigArgumentWithDerivedProfile)
{
    const auto profile = root_ / "canonical profile";
    std::filesystem::create_directories(profile / "temporary");
    const auto config = profile / "runtime.conf";
    touch(config);
    const auto lexicalConfig = profile / "temporary" / ".." / "runtime.conf";
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --config \"" + lexicalConfig.string() + "\"";

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");

    ASSERT_TRUE(validated.has_value());
    EXPECT_EQ(validated->command,
              "\"" + (daemonDir_ / "input-leaps.exe").string() +
              "\" --config \"" + config.string() +
              "\" --profile-dir \"" + profile.string() + "\"");
}

TEST_F(DaemonCommandPolicyTests,
       ServerConfigRejectsDifferentExplicitProfileDirectory)
{
    const auto profile = root_ / "authoritative profile";
    const auto otherProfile = root_ / "other profile";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(otherProfile);
    const auto config = profile / "runtime.conf";
    touch(config);
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --config \"" + config.string() +
        "\" --profile-dir \"" + otherProfile.string() + "\"";

    EXPECT_FALSE(DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests,
       ServerConfigCanonicalizesEquivalentExplicitProfileDirectory)
{
    const auto profile = root_ / "explicit profile";
    std::filesystem::create_directories(profile / "temporary");
    const auto config = profile / "runtime.conf";
    touch(config);
    const auto lexicalProfile = profile / "temporary" / "..";
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --config \"" + config.string() +
        "\" --profile-dir \"" + lexicalProfile.string() + "\"";

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");

    ASSERT_TRUE(validated.has_value());
    EXPECT_EQ(validated->command,
              "\"" + (daemonDir_ / "input-leaps.exe").string() +
              "\" --config \"" + config.string() +
              "\" --profile-dir \"" + profile.string() + "\"");
}

TEST_F(DaemonCommandPolicyTests,
       SerializesTabInsideArgumentWithoutCreatingChildOptions)
{
    const std::string injectedName =
        "safe\t--config\t" + (root_ / "other" / "runtime.conf").string();
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --name " + injectedName;

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");

    ASSERT_TRUE(validated.has_value());
    ASSERT_EQ(validated->arguments.size(), 3u);
    EXPECT_EQ(validated->arguments[2], injectedName);
    EXPECT_EQ(validated->command,
              "\"" + (daemonDir_ / "input-leaps.exe").string() +
              "\" --name \"" + injectedName + "\"");

    const auto shell = LoadLibraryW(L"shell32.dll");
    ASSERT_NE(shell, nullptr);
    using CommandLineToArgv = LPWSTR* (WINAPI*)(LPCWSTR, int*);
    const auto parseCommand = reinterpret_cast<CommandLineToArgv>(
        GetProcAddress(shell, "CommandLineToArgvW"));
    ASSERT_NE(parseCommand, nullptr);
    const auto wideCommand = path_from_utf8(validated->command).native();
    int childArgc = 0;
    const auto childArgv = parseCommand(wideCommand.c_str(), &childArgc);
    ASSERT_NE(childArgv, nullptr);
    ASSERT_EQ(childArgc, 3);
    EXPECT_EQ(childArgv[2], path_from_utf8(injectedName).native());
    LocalFree(childArgv);
    FreeLibrary(shell);
}

TEST_F(DaemonCommandPolicyTests, CanonicalizesExecutableBeforeReturningCommand)
{
    const std::string command = "\"" +
        path_to_utf8(daemonDir_ / "." / "input-leaps.exe") +
        "\" --address 127.0.0.1";

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");

    ASSERT_TRUE(validated.has_value());
    const auto canonical =
        path_to_utf8(std::filesystem::canonical(daemonDir_ / "input-leaps.exe"));
    EXPECT_EQ(validated->arguments.front(), canonical);
    EXPECT_EQ(validated->command,
              "\"" + canonical + "\" --address 127.0.0.1");
}

TEST_F(DaemonCommandPolicyTests, PreservesUtf8ExecutablePath)
{
    const auto utf8Directory = root_ / L"instalação segura";
    std::filesystem::create_directories(utf8Directory);
    touch(utf8Directory / "input-leapd.exe");
    touch(utf8Directory / "input-leaps.exe");
    const std::string command = "\"" +
        path_to_utf8(utf8Directory / "input-leaps.exe") +
        "\" --address 127.0.0.1";

    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, utf8Directory / "input-leapd.exe");

    ASSERT_TRUE(validated.has_value());
    EXPECT_EQ(validated->arguments.front(),
              path_to_utf8(std::filesystem::canonical(
                  utf8Directory / "input-leaps.exe")));
}

TEST_F(DaemonCommandPolicyTests, RejectsPersistedArbitraryExecutable)
{
    const std::string command = "\"" +
        (daemonDir_ / "powershell.exe").string() +
        "\" -Command whoami";

    EXPECT_FALSE(DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests, RejectsPersistedAllowedExecutableWithInvalidArguments)
{
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --definitely-invalid-option";

    EXPECT_FALSE(DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests, RejectsValidPersistedCommandWithoutCurrentPolicyMarker)
{
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.1";

    EXPECT_FALSE(DaemonCommandPolicy::validatePersistedCommand(
        command, false, "", daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests, AllowsValidPersistedCommandWithCurrentPolicyMarker)
{
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.1";

    EXPECT_TRUE(DaemonCommandPolicy::validatePersistedCommand(
        command, false, DaemonCommandPolicy::persistedCommandMarker(command, false),
        daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests, RejectsMarkerFromDifferentElevationValue)
{
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.1";
    const auto nonElevatedMarker =
        DaemonCommandPolicy::persistedCommandMarker(command, false);

    EXPECT_FALSE(DaemonCommandPolicy::validatePersistedCommand(
        command, true, nonElevatedMarker, daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests, RejectsMarkerFromDifferentCommand)
{
    const std::string first = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.1";
    const std::string second = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.2";

    EXPECT_FALSE(DaemonCommandPolicy::validatePersistedCommand(
        second, false, DaemonCommandPolicy::persistedCommandMarker(first, false),
        daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests, RegistryWriteFailureCannotReportDurableSuccess)
{
    const std::string subkey = "Software\\InputLeap\\Tests\\daemon-command-durability-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    HKEY writable = nullptr;
    ASSERT_EQ(RegCreateKeyExA(
        HKEY_CURRENT_USER, subkey.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS,
        nullptr, &writable, nullptr), ERROR_SUCCESS);
    RegCloseKey(writable);

    HKEY readOnly = nullptr;
    ASSERT_EQ(RegOpenKeyExA(
        HKEY_CURRENT_USER, subkey.c_str(), 0, KEY_READ, &readOnly), ERROR_SUCCESS);
    EXPECT_THROW(
        ArchMiscWindows::setValue(readOnly, "Command", std::string("candidate")),
        std::runtime_error);
    RegCloseKey(readOnly);
    RegDeleteTreeA(HKEY_CURRENT_USER, subkey.c_str());
}

TEST_F(DaemonCommandPolicyTests,
       AtomicTopologyUsesDaemonOwnedPathAndAdvancesRuntimeGeneration)
{
    const auto configPath = root_ / "authoritative.sgc";
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));
    std::ofstream(configPath) << active;
    Config candidate;
    ASSERT_TRUE(candidate.addScreen("primary"));
    ASSERT_TRUE(candidate.addScreen("peer"));
    std::ostringstream payload;
    payload << candidate;

    DaemonApp app;
    int runtimeApplies = 0;
    int acknowledgements = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&](const std::string&, bool) { ++runtimeApplies; return true; },
        [] { return true; },
        [&](const std::string&) { ++acknowledgements; },
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated server command", false, "0123456789abcdef"));
    runtimeApplies = 0;
    acknowledgements = 0;
    DaemonAppTopologyTransactionTestAccess::configureAuthority(
        app, configPath, "primary");

    const auto result = DaemonAppTopologyTransactionTestAccess::apply(
        app, "fedcba9876543210", "0123456789abcdef", payload.str());

    EXPECT_EQ(result.status, TopologyTransactionStatus::Applied) << result.error;
    EXPECT_EQ(runtimeApplies, 1);
    EXPECT_EQ(acknowledgements, 0);
    EXPECT_EQ(DaemonAppTopologyTransactionTestAccess::appliedGeneration(app),
              "fedcba9876543210");
    std::ifstream committed(configPath);
    Config loaded;
    ASSERT_NO_THROW(committed >> loaded);
    EXPECT_TRUE(loaded.isScreen("peer"));
}

TEST_F(DaemonCommandPolicyTests,
       AtomicTopologyRuntimeFailureRestoresFileAndPriorGeneration)
{
    const auto configPath = root_ / "authoritative.sgc";
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));
    std::ostringstream activePayload;
    activePayload << active;
    std::ofstream(configPath, std::ios::binary) << activePayload.str();
    Config candidate;
    ASSERT_TRUE(candidate.addScreen("primary"));
    ASSERT_TRUE(candidate.addScreen("peer"));
    std::ostringstream payload;
    payload << candidate;

    DaemonApp app;
    std::vector<bool> applyResults{true, false, true};
    int applyIndex = 0;
    int stops = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&](const std::string&, bool) {
            return applyResults.at(static_cast<std::size_t>(applyIndex++));
        },
        [&] { ++stops; return true; },
        [](const std::string&) {},
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated server command", false, "0123456789abcdef"));
    DaemonAppTopologyTransactionTestAccess::configureAuthority(
        app, configPath, "primary");

    const auto result = DaemonAppTopologyTransactionTestAccess::apply(
        app, "fedcba9876543210", "0123456789abcdef", payload.str());

    EXPECT_EQ(result.status, TopologyTransactionStatus::Rejected);
    EXPECT_EQ(applyIndex, 3);
    EXPECT_EQ(stops, 1);
    EXPECT_EQ(DaemonAppTopologyTransactionTestAccess::appliedGeneration(app),
              "0123456789abcdef");
    std::ifstream restored(configPath, std::ios::binary);
    const std::string restoredPayload{
        std::istreambuf_iterator<char>(restored),
        std::istreambuf_iterator<char>()};
    EXPECT_EQ(restoredPayload, activePayload.str());
}

TEST_F(DaemonCommandPolicyTests,
       AtomicTopologyCleanRestartRestoresCommittedGeneration)
{
    const auto configPath = root_ / "authoritative.sgc";
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));
    std::ofstream(configPath) << active;
    Config candidate;
    ASSERT_TRUE(candidate.addScreen("primary"));
    ASSERT_TRUE(candidate.addScreen("peer"));
    std::ostringstream payload;
    payload << candidate;
    DaemonTopologyTransaction transaction(configPath);
    ASSERT_EQ(transaction.apply(
        {"fedcba9876543210", "0123456789abcdef", payload.str(), "primary"},
        "0123456789abcdef", {[] { return true; }, [] { return true; }}).status,
        TopologyTransactionStatus::Applied);

    DaemonApp app;
    int runtimeApplies = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&](const std::string&, bool) { ++runtimeApplies; return true; },
        [] { return true; },
        [](const std::string&) {},
    });

    EXPECT_TRUE(DaemonAppTopologyTransactionTestAccess::recoverAndApply(
        app, configPath, "primary", "validated server command",
        "0123456789abcdef"));
    EXPECT_EQ(runtimeApplies, 1);
    EXPECT_EQ(DaemonAppTopologyTransactionTestAccess::appliedGeneration(app),
              "fedcba9876543210");
}

TEST_F(DaemonCommandPolicyTests,
       AtomicTopologyCrashRollbackIsFinalizedOnlyAfterRuntimeConfirmation)
{
    const auto configPath = root_ / "authoritative.sgc";
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));
    std::ostringstream activePayload;
    activePayload << active;
    std::ofstream(configPath) << activePayload.str();
    Config candidate;
    ASSERT_TRUE(candidate.addScreen("primary"));
    ASSERT_TRUE(candidate.addScreen("peer"));
    std::ostringstream payload;
    payload << candidate;
    DaemonTopologyTransaction interrupted(configPath);
    ASSERT_EQ(interrupted.apply(
        {"fedcba9876543210", "0123456789abcdef", payload.str(), "primary"},
        "0123456789abcdef", {[] { return false; }, [] { return false; }}).status,
        TopologyTransactionStatus::RollbackFailed);
    ASSERT_TRUE(std::filesystem::exists(interrupted.journalPath()));

    DaemonApp app;
    std::vector<std::pair<std::string, std::string>> persisted{
        {"CommandRequestNonce", "fedcba9876543210"},
        {"CommandAppliedNonce", "fedcba9876543210"},
        {"CommandReloadExpectedNonce", "0123456789abcdef"},
        {"CommandPolicyVersion", DaemonCommandPolicy::persistedCommandMarker(
             "validated server command", false, "fedcba9876543210",
             "0123456789abcdef")},
    };
    const auto persist = [&persisted](
        const std::string& key, const std::string& value) {
        for (auto& entry : persisted) {
            if (entry.first == key) {
                entry.second = value;
                return true;
            }
        }
        persisted.emplace_back(key, value);
        return true;
    };
    const auto persistedValue = [&persisted](const std::string& key) {
        for (const auto& entry : persisted) {
            if (entry.first == key) {
                return entry.second;
            }
        }
        return std::string();
    };
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        persist,
        [](const std::string&, bool) { return true; },
        [] { return true; },
        [](const std::string&) {},
    });

    EXPECT_TRUE(DaemonAppTopologyTransactionTestAccess::recoverAndApply(
        app, configPath, "primary", "validated server command",
        "0123456789abcdef"));
    EXPECT_EQ(DaemonAppTopologyTransactionTestAccess::appliedGeneration(app),
              "0123456789abcdef");
    EXPECT_EQ(persistedValue("CommandRequestNonce"), "0123456789abcdef");
    EXPECT_EQ(persistedValue("CommandAppliedNonce"), "0123456789abcdef");
    EXPECT_TRUE(persistedValue("CommandReloadExpectedNonce").empty());
    EXPECT_EQ(persistedValue("CommandPolicyVersion"),
              DaemonCommandPolicy::persistedCommandMarker(
                  "validated server command", false, "0123456789abcdef"));
    EXPECT_FALSE(std::filesystem::exists(interrupted.journalPath()));
}

TEST_F(DaemonCommandPolicyTests,
       AtomicTopologyCrashRollbackPersistenceFailureKeepsRecoveryJournal)
{
    Config active;
    ASSERT_TRUE(active.addScreen("primary"));
    std::ostringstream activePayload;
    activePayload << active;
    Config candidate;
    ASSERT_TRUE(candidate.addScreen("primary"));
    ASSERT_TRUE(candidate.addScreen("peer"));
    std::ostringstream payload;
    payload << candidate;

    for (int failAt = 0; failAt < 8; ++failAt) {
        const auto configPath =
            root_ / ("authoritative-recovery-" + std::to_string(failAt) + ".sgc");
        std::ofstream(configPath) << activePayload.str();
        DaemonTopologyTransaction interrupted(configPath);
        ASSERT_EQ(interrupted.apply(
            {"fedcba9876543210", "0123456789abcdef", payload.str(), "primary"},
            "0123456789abcdef", {[] { return false; }, [] { return false; }}).status,
            TopologyTransactionStatus::RollbackFailed);
        ASSERT_TRUE(std::filesystem::exists(interrupted.journalPath()));

        DaemonApp app;
        int writes = 0;
        int stops = 0;
        DaemonAppCommandTransactionTestAccess::useServices(app, {
            [&writes, failAt](const std::string&, const std::string&) {
                return writes++ != failAt;
            },
            [](const std::string&, bool) { return true; },
            [&stops] { ++stops; return true; },
            [](const std::string&) {},
        });

        EXPECT_FALSE(DaemonAppTopologyTransactionTestAccess::recoverAndApply(
            app, configPath, "primary", "validated server command",
            "0123456789abcdef")) << "failed write index " << failAt;
        EXPECT_EQ(stops, 1) << "failed write index " << failAt;
        EXPECT_TRUE(std::filesystem::exists(interrupted.journalPath()))
            << "failed write index " << failAt;
        EXPECT_TRUE(
            DaemonAppTopologyTransactionTestAccess::appliedGeneration(app).empty())
            << "failed write index " << failAt;
    }
}

TEST_F(DaemonCommandPolicyTests,
       AtomicTopologyAuthorityIsDerivedFromValidatedServerCommand)
{
    const auto configPath = root_ / "authoritative.sgc";
    std::ofstream(configPath) << "section: screens\n\tprimary:\nend\n";
    const std::string command = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --config \"" + configPath.string() + "\" --name primary";
    const auto validated = DaemonCommandPolicy::validateCommandLine(
        command, daemonDir_ / "input-leapd.exe");
    ASSERT_TRUE(validated);
    DaemonApp app;

    EXPECT_TRUE(
        DaemonAppTopologyTransactionTestAccess::configureAuthorityFromCommand(
            app, *validated));
}

TEST_F(DaemonCommandPolicyTests, PersistenceFailureDoesNotApplyCommand)
{
    const std::string command = "validated command";
    for (int failAt = 0; failAt < 5; ++failAt) {
        int writes = 0;
        int applied = 0;
        int acknowledged = 0;

        EXPECT_FALSE(DaemonCommandPolicy::persistApplyAndAcknowledge(
            command, true,
            [&writes, failAt](const std::string&, const std::string&) {
                return writes++ != failAt;
            },
            [&applied] { ++applied; return true; },
            [&acknowledged] { ++acknowledged; }));
        EXPECT_EQ(applied, 0) << "failed write index " << failAt;
        EXPECT_EQ(acknowledged, 0) << "failed write index " << failAt;
    }
}

TEST_F(DaemonCommandPolicyTests, FailedCommandApplicationIsNotAcknowledged)
{
    int acknowledged = 0;

    EXPECT_FALSE(DaemonCommandPolicy::persistApplyAndAcknowledge(
        "validated command", false,
        [](const std::string&, const std::string&) { return true; },
        [] { return false; },
        [&acknowledged] { ++acknowledged; }));
    EXPECT_EQ(acknowledged, 0);
}

TEST_F(DaemonCommandPolicyTests, DurableCommandIsAppliedAndAcknowledgedOnce)
{
    int writes = 0;
    int applied = 0;
    int acknowledged = 0;

    EXPECT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledge(
        "validated command", false,
        [&writes](const std::string&, const std::string&) {
            ++writes;
            return true;
        },
        [&applied] { ++applied; return true; },
        [&acknowledged] { ++acknowledged; }));
    EXPECT_EQ(writes, 7);
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 1);
}

TEST_F(DaemonCommandPolicyTests, ReplayedStartNonceAcknowledgesWithoutReapplyingCommand)
{
    int writes = 0;
    int applied = 0;
    int acknowledged = 0;
    std::optional<AppliedDaemonCommandRequest> lastAppliedRequest;
    const auto persist = [&writes](const std::string&, const std::string&) {
        ++writes;
        return true;
    };
    const auto apply = [&applied] { ++applied; return true; };
    const auto acknowledge = [&acknowledged] { ++acknowledged; };

    EXPECT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        "validated command", false, "0123456789abcdef", lastAppliedRequest,
        persist, apply, acknowledge));
    EXPECT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        "validated command", false, "0123456789abcdef", lastAppliedRequest,
        persist, apply, acknowledge));

    EXPECT_EQ(writes, 8);
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 2);
    ASSERT_TRUE(lastAppliedRequest.has_value());
    EXPECT_EQ(lastAppliedRequest->nonce, "0123456789abcdef");
    EXPECT_EQ(lastAppliedRequest->command, "validated command");
    EXPECT_FALSE(lastAppliedRequest->elevate);
}

TEST_F(DaemonCommandPolicyTests, ReusedNonceAcrossReloadAndStartDomainsIsRejected)
{
    std::optional<AppliedDaemonCommandRequest> lastAppliedRequest;
    int applied = 0;
    int acknowledged = 0;
    const auto persist = [](const std::string&, const std::string&) { return true; };
    const auto apply = [&applied] { ++applied; return true; };
    const auto acknowledge = [&acknowledged] { ++acknowledged; };

    ASSERT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        "validated command", false, "fedcba9876543210", lastAppliedRequest,
        persist, apply, acknowledge, "0123456789abcdef"));
    EXPECT_FALSE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        "validated command", false, "fedcba9876543210", lastAppliedRequest,
        persist, apply, acknowledge));

    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 1);
}

TEST_F(DaemonCommandPolicyTests, ReusedNonceWithDifferentCommandIsRejected)
{
    std::optional<AppliedDaemonCommandRequest> lastAppliedRequest;
    int applied = 0;
    int acknowledged = 0;
    const auto persist = [](const std::string&, const std::string&) { return true; };
    const auto apply = [&applied] { ++applied; return true; };
    const auto acknowledge = [&acknowledged] { ++acknowledged; };

    ASSERT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        "first validated command", false, "0123456789abcdef", lastAppliedRequest,
        persist, apply, acknowledge));
    EXPECT_FALSE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        "different validated command", false, "0123456789abcdef", lastAppliedRequest,
        persist, apply, acknowledge));

    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 1);
}

TEST_F(DaemonCommandPolicyTests, DurableStartNonceRestoresReplayAfterConsumerReconstruction)
{
    const std::string command = "validated command";
    const std::string nonce = "0123456789abcdef";
    std::vector<std::pair<std::string, std::string>> persisted;
    std::optional<AppliedDaemonCommandRequest> firstConsumer;
    int applied = 0;
    int acknowledged = 0;
    const auto persist = [&persisted](const std::string& key, const std::string& value) {
        persisted.emplace_back(key, value);
        return true;
    };

    ASSERT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        command, false, nonce, firstConsumer, persist,
        [&applied] { ++applied; return true; },
        [&acknowledged] { ++acknowledged; }));

    const auto valueFor = [&persisted](const std::string& key) {
        for (auto entry = persisted.rbegin(); entry != persisted.rend(); ++entry) {
            if (entry->first == key) return entry->second;
        }
        return std::string();
    };
    auto reconstructedConsumer = DaemonCommandPolicy::restoreAppliedRequest(
        command, false, valueFor("CommandRequestNonce"),
        valueFor("CommandPolicyVersion"), valueFor("CommandAppliedNonce"));
    ASSERT_TRUE(reconstructedConsumer.has_value());

    int replayWrites = 0;
    EXPECT_TRUE(DaemonCommandPolicy::persistApplyAndAcknowledgeOnce(
        command, false, nonce, reconstructedConsumer,
        [&replayWrites](const std::string&, const std::string&) {
            ++replayWrites;
            return true;
        },
        [&applied] { ++applied; return true; },
        [&acknowledged] { ++acknowledged; }));

    EXPECT_EQ(replayWrites, 0);
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 2);
}

TEST_F(DaemonCommandPolicyTests, PersistedStartMarkerRejectsMismatchAndPendingRequest)
{
    const std::string command = "validated command";
    const std::string nonce = "0123456789abcdef";
    const auto marker = DaemonCommandPolicy::persistedCommandMarker(
        command, false, nonce);

    EXPECT_FALSE(DaemonCommandPolicy::restoreAppliedRequest(
        command, false, "fedcba9876543210", marker, "fedcba9876543210"));
    EXPECT_FALSE(DaemonCommandPolicy::restoreAppliedRequest(
        command, false, nonce, marker, std::string()));
}

TEST_F(DaemonCommandPolicyTests, PersistedReloadMarkerBindsExpectedGeneration)
{
    const std::string command = "validated command";
    const std::string requestNonce = "fedcba9876543210";
    const std::string expectedNonce = "0123456789abcdef";
    const auto marker = DaemonCommandPolicy::persistedCommandMarker(
        command, false, requestNonce, expectedNonce);

    EXPECT_TRUE(DaemonCommandPolicy::restoreAppliedRequest(
        command, false, requestNonce, marker, requestNonce, expectedNonce));
    EXPECT_FALSE(DaemonCommandPolicy::restoreAppliedRequest(
        command, false, requestNonce, marker, requestNonce,
        "stale-gen-123456"));
}

TEST_F(DaemonCommandPolicyTests, PersistedStopMarkerBindsDomainAndExpectedGeneration)
{
    const std::string requestNonce = "stop-request-123";
    const std::string expectedNonce = "0123456789abcdef";
    const auto marker = DaemonCommandPolicy::persistedStopMarker(
        requestNonce, expectedNonce);

    EXPECT_TRUE(DaemonCommandPolicy::restoreAppliedStopRequest(
        requestNonce, expectedNonce, marker, requestNonce));
    EXPECT_FALSE(DaemonCommandPolicy::restoreAppliedStopRequest(
        requestNonce, "fedcba9876543210", marker, requestNonce));
    const auto pending = DaemonCommandPolicy::restoreAppliedStopRequest(
        requestNonce, expectedNonce, marker, std::string());
    ASSERT_TRUE(pending.has_value());
    EXPECT_FALSE(pending->completionDurable);
}

TEST_F(DaemonCommandPolicyTests,
       PendingStopCompletionRetryDoesNotStopRuntimeAgain)
{
    const std::string requestNonce = "fedcba9876543210";
    const std::string expectedNonce = "0123456789abcdef";
    std::optional<AppliedDaemonStopRequest> lastAppliedRequest;
    int completionWrites = 0;
    int stopCalls = 0;
    int acknowledgements = 0;
    const auto persist = [&](const std::string& key, const std::string&) {
        if (key == "CommandStopAppliedNonce" && ++completionWrites == 2) {
            return false;
        }
        return true;
    };

    EXPECT_FALSE(DaemonCommandPolicy::persistStopAndAcknowledgeOnce(
        requestNonce, expectedNonce, lastAppliedRequest, persist,
        [&] { ++stopCalls; return true; },
        [&] { ++acknowledgements; }));
    EXPECT_TRUE(DaemonCommandPolicy::persistStopAndAcknowledgeOnce(
        requestNonce, expectedNonce, lastAppliedRequest, persist,
        [&] { ++stopCalls; return true; },
        [&] { ++acknowledgements; }));

    EXPECT_EQ(stopCalls, 1);
    EXPECT_EQ(acknowledgements, 1);
}

TEST_F(DaemonCommandPolicyTests,
       PendingStopCompletionRestoresAndConfirmsRuntimeStopBeforeCompleting)
{
    const std::string requestNonce = "fedcba9876543210";
    const std::string expectedNonce = "0123456789abcdef";
    auto reconstructed = DaemonCommandPolicy::restoreAppliedStopRequest(
        requestNonce, expectedNonce,
        DaemonCommandPolicy::persistedStopMarker(requestNonce, expectedNonce),
        std::string());
    ASSERT_TRUE(reconstructed.has_value());

    int stopCalls = 0;
    int completionWrites = 0;
    int acknowledgements = 0;
    EXPECT_TRUE(DaemonCommandPolicy::persistStopAndAcknowledgeOnce(
        requestNonce, expectedNonce, reconstructed,
        [&](const std::string& key, const std::string& value) {
            if (key == "CommandStopAppliedNonce" && value == requestNonce) {
                ++completionWrites;
            }
            return true;
        },
        [&] { ++stopCalls; return true; },
        [&] { ++acknowledgements; }));

    EXPECT_EQ(stopCalls, 1);
    EXPECT_EQ(completionWrites, 1);
    EXPECT_EQ(acknowledgements, 1);
}

TEST_F(DaemonCommandPolicyTests,
       PendingStopRecoveryRejectsUnconfirmedRuntimeStop)
{
    const std::string requestNonce = "fedcba9876543210";
    const std::string expectedNonce = "0123456789abcdef";
    auto reconstructed = DaemonCommandPolicy::restoreAppliedStopRequest(
        requestNonce, expectedNonce,
        DaemonCommandPolicy::persistedStopMarker(requestNonce, expectedNonce),
        std::string());
    ASSERT_TRUE(reconstructed.has_value());

    int completionWrites = 0;
    int acknowledgements = 0;
    EXPECT_FALSE(DaemonCommandPolicy::persistStopAndAcknowledgeOnce(
        requestNonce, expectedNonce, reconstructed,
        [&](const std::string& key, const std::string& value) {
            if (key == "CommandStopAppliedNonce" && value == requestNonce) {
                ++completionWrites;
            }
            return true;
        },
        [] { return false; },
        [&] { ++acknowledgements; }));

    EXPECT_EQ(completionWrites, 0);
    EXPECT_EQ(acknowledgements, 0);
}

TEST_F(DaemonCommandPolicyTests, DaemonAppRestoresStopReplayAcrossInstances)
{
    const std::string requestNonce = "stop-request-123";
    const std::string expectedNonce = "0123456789abcdef";
    std::vector<std::pair<std::string, std::string>> persisted;
    int firstStops = 0;
    {
        DaemonApp first;
        DaemonAppCommandTransactionTestAccess::useServices(first, {
            [&persisted](const std::string& key, const std::string& value) {
                persisted.emplace_back(key, value);
                return true;
            },
            [](const std::string&, bool) { return true; },
            [&firstStops] { ++firstStops; return true; },
            [](const std::string&) {},
        });
        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
            first, "validated command", false, expectedNonce));
        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
            first, requestNonce, expectedNonce));
    }

    const auto valueFor = [&persisted](const std::string& key) {
        for (auto entry = persisted.rbegin(); entry != persisted.rend(); ++entry) {
            if (entry->first == key) return entry->second;
        }
        return std::string();
    };

    DaemonApp reconstructed;
    int replayWrites = 0;
    int replayStops = 0;
    int replayAcks = 0;
    DaemonAppCommandTransactionTestAccess::useServices(reconstructed, {
        [&replayWrites](const std::string&, const std::string&) {
            ++replayWrites;
            return true;
        },
        [](const std::string&, bool) { return true; },
        [&replayStops] { ++replayStops; return true; },
        [&replayAcks](const std::string&) { ++replayAcks; },
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::restoreStopRequest(
        reconstructed, valueFor("CommandStopRequestNonce"),
        valueFor("CommandStopExpectedAppliedNonce"),
        valueFor("CommandStopPolicyVersion"),
        valueFor("CommandStopAppliedNonce")));
    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        reconstructed, requestNonce, expectedNonce));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        reconstructed, requestNonce, "fedcba9876543210"));

    EXPECT_EQ(firstStops, 1);
    EXPECT_EQ(replayWrites, 0);
    EXPECT_EQ(replayStops, 0);
    EXPECT_EQ(replayAcks, 1);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppRecoversPendingStopBeforeAcknowledgingReplay)
{
    const std::string requestNonce = "stop-request-123";
    const std::string expectedNonce = "0123456789abcdef";
    DaemonApp reconstructed;
    int completionWrites = 0;
    int stopConfirmations = 0;
    int acknowledgements = 0;
    DaemonAppCommandTransactionTestAccess::useServices(reconstructed, {
        [&](const std::string& key, const std::string& value) {
            if (key == "CommandStopAppliedNonce" && value == requestNonce) {
                ++completionWrites;
            }
            return true;
        },
        [](const std::string&, bool) { return true; },
        [&] { ++stopConfirmations; return true; },
        [&](const std::string&) { ++acknowledgements; },
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::restoreStopRequest(
        reconstructed, requestNonce, expectedNonce,
        DaemonCommandPolicy::persistedStopMarker(requestNonce, expectedNonce),
        std::string()));

    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        reconstructed, requestNonce, expectedNonce));

    EXPECT_EQ(stopConfirmations, 1);
    EXPECT_EQ(completionWrites, 1);
    EXPECT_EQ(acknowledgements, 1);
}

TEST_F(DaemonCommandPolicyTests, DaemonAppRestoresStartReplayAcrossInstances)
{
    const std::string command = "validated command";
    const std::string nonce = "0123456789abcdef";
    std::vector<std::pair<std::string, std::string>> persisted;
    int firstApply = 0;
    int firstAck = 0;
    {
        DaemonApp first;
        DaemonAppCommandTransactionTestAccess::useServices(first, {
            [&persisted](const std::string& key, const std::string& value) {
                persisted.emplace_back(key, value);
                return true;
            },
            [&firstApply](const std::string&, bool) { ++firstApply; return true; },
            [] { return true; },
            [&firstAck](const std::string&) { ++firstAck; },
        });
        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
            first, command, false, nonce));
    }

    const auto valueFor = [&persisted](const std::string& key) {
        for (auto entry = persisted.rbegin(); entry != persisted.rend(); ++entry) {
            if (entry->first == key) return entry->second;
        }
        return std::string();
    };

    DaemonApp reconstructed;
    int replayWrites = 0;
    int replayApply = 0;
    int replayAck = 0;
    DaemonAppCommandTransactionTestAccess::useServices(reconstructed, {
        [&replayWrites](const std::string&, const std::string&) {
            ++replayWrites;
            return true;
        },
        [&replayApply](const std::string&, bool) { ++replayApply; return true; },
        [] { return true; },
        [&replayAck](const std::string&) { ++replayAck; },
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::restoreStartRequest(
        reconstructed, command, false, valueFor("CommandRequestNonce"),
        valueFor("CommandPolicyVersion"), valueFor("CommandAppliedNonce")));
    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        reconstructed, command, false, nonce));

    EXPECT_EQ(firstApply, 1);
    EXPECT_EQ(firstAck, 1);
    EXPECT_EQ(replayWrites, 0);
    EXPECT_EQ(replayApply, 0);
    EXPECT_EQ(replayAck, 1);
}

TEST_F(DaemonCommandPolicyTests, DaemonAppRestoresReloadReplayAcrossInstances)
{
    const std::string command = "validated command";
    const std::string startNonce = "0123456789abcdef";
    const std::string reloadNonce = "fedcba9876543210";
    std::vector<std::pair<std::string, std::string>> persisted;
    {
        DaemonApp first;
        DaemonAppCommandTransactionTestAccess::useServices(first, {
            [&persisted](const std::string& key, const std::string& value) {
                persisted.emplace_back(key, value);
                return true;
            },
            [](const std::string&, bool) { return true; },
            [] { return true; },
            [](const std::string&) {},
        });
        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
            first, command, false, startNonce));
        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
            first, reloadNonce, startNonce));
    }

    const auto valueFor = [&persisted](const std::string& key) {
        for (auto entry = persisted.rbegin(); entry != persisted.rend(); ++entry) {
            if (entry->first == key) return entry->second;
        }
        return std::string();
    };

    DaemonApp reconstructed;
    int applied = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(reconstructed, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::restoreStartRequest(
        reconstructed, command, false, valueFor("CommandRequestNonce"),
        valueFor("CommandPolicyVersion"), valueFor("CommandAppliedNonce"),
        valueFor("CommandReloadExpectedNonce")));
    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        reconstructed, reloadNonce, startNonce));

    EXPECT_EQ(applied, 0);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{reloadNonce}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartConsumerNeverAppliesOrAcknowledgesBeforeDurablePersistence)
{
    for (int failAt = 0; failAt < 6; ++failAt) {
        DaemonApp app;
        int writes = 0;
        int applied = 0;
        int acknowledged = 0;
        DaemonAppCommandTransactionTestAccess::useServices(app, {
            [&writes, failAt](const std::string&, const std::string&) {
                return writes++ != failAt;
            },
            [&applied](const std::string&, bool) { ++applied; return true; },
            [] { return true; },
            [&acknowledged](const std::string&) { ++acknowledged; },
        });

        EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
            app, "validated command", true, "0123456789abcdef"));
        EXPECT_EQ(applied, 0) << "failed write index " << failAt;
        EXPECT_EQ(acknowledged, 0) << "failed write index " << failAt;
    }
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartConsumerOrdersPersistenceApplyAckAndReplaysOnlyAck)
{
    DaemonApp app;
    std::vector<std::string> events;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&events](const std::string& key, const std::string&) {
            events.push_back("persist:" + key); return true;
        },
        [&events](const std::string&, bool) { events.push_back("apply"); return true; },
        [] { return true; },
        [&events](const std::string& nonce) { events.push_back("ack:" + nonce); },
    });

    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));

    EXPECT_EQ(events, (std::vector<std::string>{
        "persist:CommandAppliedNonce",
        "persist:CommandPolicyVersion", "persist:Command", "persist:Elevate",
        "persist:CommandRequestNonce", "persist:CommandReloadExpectedNonce",
        "persist:CommandPolicyVersion",
        "apply", "persist:CommandAppliedNonce",
        "ack:0123456789abcdef", "ack:0123456789abcdef"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartDoesNotAcknowledgeWhenAppliedNonceCannotBePersisted)
{
    DaemonApp app;
    int applied = 0;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string& key, const std::string& value) {
            return key != "CommandAppliedNonce" || value.empty();
        },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 0);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppFailedStartCompletionStopsRuntimeAndRevokesPriorGeneration)
{
    DaemonApp app;
    bool failCompletion = false;
    int stopped = 0;
    std::vector<std::string> applied;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&failCompletion](const std::string& key, const std::string& value) {
            return !failCompletion || key != "CommandAppliedNonce" || value.empty();
        },
        [&applied](const std::string& command, bool) {
            applied.push_back(command);
            return true;
        },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    failCompletion = true;
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation B", false, "fedcba9876543210"));

    EXPECT_EQ(stopped, 1);
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(applied, (std::vector<std::string>{"generation A", "generation B"}));
    EXPECT_EQ(acknowledged, (std::vector<std::string>{"0123456789abcdef"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppUncertainStartEffectStopsRuntimeAndRevokesPriorGeneration)
{
    DaemonApp app;
    int applied = 0;
    int stopped = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) {
            ++applied;
            return applied != 2;
        },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation B", false, "fedcba9876543210"));

    EXPECT_EQ(stopped, 1);
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "reload-request12", "0123456789abcdef"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    EXPECT_EQ(applied, 2);
    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{"0123456789abcdef"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppRestoredStartWithUncertainEffectStopsRuntimeAndRevokesAuthorities)
{
    DaemonApp app;
    int applied = 0;
    int stopped = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { return ++applied < 3; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::applyRestoredStart(
        app, "generation C", false, "0011223344556677",
        DaemonCommandPolicy::persistedCommandMarker(
            "generation C", false, "0011223344556677"),
        {}));

    EXPECT_EQ(applied, 3);
    EXPECT_EQ(stopped, 1);
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::hasStartAuthority(app));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::hasReloadAuthority(app));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::hasStopAuthority(app));
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "fedcba9876543210"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppRestoredStartCompletionPersistenceFailureStopsRuntime)
{
    DaemonApp app;
    int persisted = 0;
    int applied = 0;
    int stopped = 0;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&persisted](const std::string& key, const std::string& value) {
            EXPECT_EQ(key, "CommandAppliedNonce");
            EXPECT_EQ(value, "0011223344556677");
            ++persisted;
            return false;
        },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::applyRestoredStart(
        app, "generation C", false, "0011223344556677",
        DaemonCommandPolicy::persistedCommandMarker(
            "generation C", false, "0011223344556677"),
        {}));

    EXPECT_EQ(persisted, 1);
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(acknowledged, 0);
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::hasStartAuthority(app));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::hasReloadAuthority(app));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::hasStopAuthority(app));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartAppliesRuntimeConfigurationAfterCoreAndBeforeAppliedNonce)
{
    DaemonApp app;
    std::vector<std::string> events;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&events](const std::string& key, const std::string& value) {
            events.push_back("persist:" + key + "=" + value); return true;
        },
        [&events](const std::string&, bool) { events.push_back("core"); return true; },
        [] { return true; },
        [&events](const std::string&) { events.push_back("ack"); },
    });

    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef",
        [&events] { events.push_back("runtime-log"); return true; }));

    const auto core = std::find(events.begin(), events.end(), "core");
    const auto runtimeLog = std::find(events.begin(), events.end(), "runtime-log");
    const auto appliedNonce = std::find(
        events.begin(), events.end(),
        "persist:CommandAppliedNonce=0123456789abcdef");
    const auto ack = std::find(events.begin(), events.end(), "ack");
    ASSERT_NE(core, events.end());
    ASSERT_NE(runtimeLog, events.end());
    ASSERT_NE(appliedNonce, events.end());
    ASSERT_NE(ack, events.end());
    EXPECT_LT(core, runtimeLog);
    EXPECT_LT(runtimeLog, appliedNonce);
    EXPECT_LT(appliedNonce, ack);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartDoesNotAcknowledgeFailedRuntimeConfiguration)
{
    DaemonApp app;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [](const std::string&, bool) { return true; },
        [] { return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef",
        [] { return false; }));
    EXPECT_EQ(acknowledged, 0);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadRejectsMissingDurablyAppliedStartRequest)
{
    DaemonApp app;
    int applied = 0;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));
    EXPECT_EQ(applied, 0);
    EXPECT_EQ(acknowledged, 0);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadReusesExactLastAppliedCommandAndAcknowledgesNewNonce)
{
    DaemonApp app;
    std::vector<std::pair<std::string, bool>> applied;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string& command, bool elevate) {
            applied.emplace_back(command, elevate);
            return true;
        },
        [] { return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command --crypto preserved", true, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));

    EXPECT_EQ(applied, (std::vector<std::pair<std::string, bool>>{
        {"validated command --crypto preserved", true},
        {"validated command --crypto preserved", true}}));
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "fedcba9876543210"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadAfterRestoreReusesAcceptedCommand)
{
    DaemonApp app;
    std::vector<std::string> applied;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string& command, bool) {
            applied.push_back(command);
            return true;
        },
        [] { return true; },
        [](const std::string&) {},
    });
    const std::string acceptedCommand = "accepted canonical command";
    const std::string persistedCommand = "raw\t--disable-crypto";
    const std::string startNonce = "0123456789abcdef";

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::applyRestoredStart(
        app, acceptedCommand, persistedCommand, false, startNonce,
        DaemonCommandPolicy::persistedCommandMarker(
            persistedCommand, false, startNonce),
        startNonce));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", startNonce));

    EXPECT_EQ(applied, (std::vector<std::string>{
        acceptedCommand, acceptedCommand}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadRejectsNonceAlreadyUsedByStart)
{
    DaemonApp app;
    int applied = 0;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "0123456789abcdef", "0123456789abcdef"));
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, 1);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadRejectsStaleExpectedAppliedNonce)
{
    DaemonApp app;
    int applied = 0;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "new validated command", false, "fedcba9876543210"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "reload-123456789", "0123456789abcdef"));
    EXPECT_EQ(applied, 2);
    EXPECT_EQ(acknowledged, 2);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadReplayAcknowledgesWithoutApplyingAgain)
{
    DaemonApp app;
    int applied = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));
    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));
    EXPECT_EQ(applied, 2);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "fedcba9876543210", "fedcba9876543210"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadPersistsExpectedGenerationBeforeApplying)
{
    DaemonApp app;
    std::vector<std::string> events;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&events](const std::string& key, const std::string& value) {
            events.push_back("persist:" + key + "=" + value);
            return true;
        },
        [&events](const std::string&, bool) { events.push_back("apply"); return true; },
        [] { return true; },
        [&events](const std::string& nonce) { events.push_back("ack:" + nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    events.clear();
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));

    const auto expectedGeneration = std::find(
        events.begin(), events.end(),
        "persist:CommandReloadExpectedNonce=0123456789abcdef");
    const auto apply = std::find(events.begin(), events.end(), "apply");
    ASSERT_NE(expectedGeneration, events.end());
    ASSERT_NE(apply, events.end());
    EXPECT_LT(expectedGeneration, apply);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartClearsReloadGenerationBeforeApplying)
{
    DaemonApp app;
    std::vector<std::string> events;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&events](const std::string& key, const std::string& value) {
            events.push_back("persist:" + key + "=" + value);
            return true;
        },
        [&events](const std::string&, bool) { events.push_back("apply"); return true; },
        [] { return true; },
        [&events](const std::string& nonce) { events.push_back("ack:" + nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));
    events.clear();
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "new validated command", false, "new-start-123456"));

    const auto clearedGeneration = std::find(
        events.begin(), events.end(), "persist:CommandReloadExpectedNonce=");
    const auto apply = std::find(events.begin(), events.end(), "apply");
    ASSERT_NE(clearedGeneration, events.end());
    ASSERT_NE(apply, events.end());
    EXPECT_LT(clearedGeneration, apply);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppReloadAfterConfirmedStopIsRejected)
{
    DaemonApp app;
    int applied = 0;
    int stopped = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));

    EXPECT_EQ(applied, 1);
    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "stop-request-123"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStaleStopCannotTerminateNewerStartGeneration)
{
    DaemonApp app;
    int stopped = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [](const std::string&, bool) { return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation B", false, "fedcba9876543210"));

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    EXPECT_EQ(stopped, 0);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "fedcba9876543210"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppIdenticalStopReplayAcknowledgesWithoutStoppingTwice)
{
    DaemonApp app;
    int stopped = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [](const std::string&, bool) { return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));

    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "stop-request-123", "stop-request-123"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStopClearsCorrelatedGenerationBeforeStopping)
{
    DaemonApp app;
    std::vector<std::string> events;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&events](const std::string& key, const std::string& value) {
            events.push_back("persist:" + key + "=" + value);
            return true;
        },
        [](const std::string&, bool) { return true; },
        [&events] { events.push_back("stop"); return true; },
        [&events](const std::string& nonce) { events.push_back("ack:" + nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    events.clear();
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    const auto appliedNonce = std::find(
        events.begin(), events.end(), "persist:CommandAppliedNonce=");
    const auto reloadExpected = std::find(
        events.begin(), events.end(), "persist:CommandReloadExpectedNonce=");
    const auto stop = std::find(events.begin(), events.end(), "stop");
    ASSERT_NE(appliedNonce, events.end());
    ASSERT_NE(reloadExpected, events.end());
    ASSERT_NE(stop, events.end());
    EXPECT_LT(appliedNonce, stop);
    EXPECT_LT(reloadExpected, stop);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStopConsumerAcknowledgesOnlyAfterPersistenceAndConfirmedStop)
{
    for (const bool stopConfirmed : {false, true}) {
        DaemonApp app;
        std::vector<std::string> events;
        DaemonAppCommandTransactionTestAccess::useServices(app, {
            [&events](const std::string& key, const std::string&) {
                events.push_back("persist:" + key); return true;
            },
            [](const std::string&, bool) { return true; },
            [&events, stopConfirmed] {
                events.push_back("stop"); return stopConfirmed;
            },
            [&events](const std::string& nonce) { events.push_back("ack:" + nonce); },
        });

        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
            app, "validated command", false, "0123456789abcdef"));
        events.clear();
        EXPECT_EQ(DaemonAppCommandTransactionTestAccess::stop(
                      app, "fedcba9876543210", "0123456789abcdef"),
                  stopConfirmed);
        EXPECT_EQ(events, stopConfirmed
            ? (std::vector<std::string>{
                  "persist:CommandStopAppliedNonce",
                  "persist:CommandStopPolicyVersion",
                  "persist:CommandStopRequestNonce",
                  "persist:CommandStopExpectedAppliedNonce",
                  "persist:CommandStopPolicyVersion",
                  "persist:CommandPolicyVersion", "persist:CommandAppliedNonce",
                  "persist:CommandReloadExpectedNonce", "persist:Command",
                  "persist:Elevate", "persist:CommandRequestNonce",
                  "stop", "persist:CommandStopAppliedNonce",
                  "ack:fedcba9876543210"})
            : (std::vector<std::string>{
                  "persist:CommandStopAppliedNonce",
                  "persist:CommandStopPolicyVersion",
                  "persist:CommandStopRequestNonce",
                  "persist:CommandStopExpectedAppliedNonce",
                  "persist:CommandStopPolicyVersion",
                  "persist:CommandPolicyVersion", "persist:CommandAppliedNonce",
                  "persist:CommandReloadExpectedNonce", "persist:Command",
                  "persist:Elevate", "persist:CommandRequestNonce",
                  "stop"}));
    }
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStopConsumerNeverStopsOrAcknowledgesBeforeDurablePersistence)
{
    for (int failAt = 0; failAt < 11; ++failAt) {
        DaemonApp app;
        int writes = 0;
        int stopped = 0;
        int acknowledged = 0;
        DaemonAppCommandTransactionTestAccess::useServices(app, {
            [](const std::string&, const std::string&) { return true; },
            [](const std::string&, bool) { return true; },
            [] { return true; },
            [](const std::string&) {},
        });
        ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
            app, "validated command", false, "0123456789abcdef"));
        DaemonAppCommandTransactionTestAccess::useServices(app, {
            [&writes, failAt](const std::string&, const std::string&) {
                return writes++ != failAt;
            },
            [](const std::string&, bool) { return true; },
            [&stopped] { ++stopped; return true; },
            [&acknowledged](const std::string&) { ++acknowledged; },
        });

        EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
            app, "fedcba9876543210", "0123456789abcdef"));
        EXPECT_EQ(stopped, 0) << "failed write index " << failAt;
        EXPECT_EQ(acknowledged, 0) << "failed write index " << failAt;
    }
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStopConsumerNeverAcknowledgesBeforeDurableCompletion)
{
    DaemonApp app;
    int stopped = 0;
    int acknowledged = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [](const std::string&, bool) { return true; },
        [] { return true; },
        [](const std::string&) {},
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "validated command", false, "0123456789abcdef"));
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string& key, const std::string& value) {
            return key != "CommandStopAppliedNonce" || value.empty();
        },
        [](const std::string&, bool) { return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string&) { ++acknowledged; },
    });

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        app, "fedcba9876543210", "0123456789abcdef"));
    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(acknowledged, 0);
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppFailedStopCompletionRevokesPriorGeneration)
{
    DaemonApp app;
    int applied = 0;
    int stopped = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string& key, const std::string& value) {
            return key != "CommandStopAppliedNonce" || value.empty();
        },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [&stopped] { ++stopped; return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });
    EXPECT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::stop(
        app, "different-stop-12", "0123456789abcdef"));
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(stopped, 1);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "stop-request-123"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppLegacyStartInvalidatesCorrelatedReloadGeneration)
{
    DaemonApp app;
    std::vector<std::string> applied;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string& command, bool) {
            applied.push_back(command);
            return true;
        },
        [] { return true; },
        [](const std::string&) {},
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "correlated command", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "legacy command", false, ""));

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::reload(
        app, "fedcba9876543210", "0123456789abcdef"));
    EXPECT_EQ(applied, (std::vector<std::string>{
        "correlated command", "legacy command"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppLegacyStartAfterStopPersistsAuthoritativeCommand)
{
    const std::string legacyCommand = "\"" +
        (daemonDir_ / "input-leaps.exe").string() +
        "\" --address 127.0.0.1";
    std::vector<std::pair<std::string, std::string>> persisted;
    DaemonApp app;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [&persisted](const std::string& key, const std::string& value) {
            persisted.emplace_back(key, value);
            return true;
        },
        [](const std::string&, bool) { return true; },
        [] { return true; },
        [](const std::string&) {},
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "stop-request-123", "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, legacyCommand, false, ""));

    const auto valueFor = [&persisted](const std::string& key) {
        for (auto entry = persisted.rbegin(); entry != persisted.rend(); ++entry) {
            if (entry->first == key) return entry->second;
        }
        return std::string();
    };
    EXPECT_EQ(valueFor("Command"), legacyCommand);
    EXPECT_TRUE(valueFor("CommandRequestNonce").empty());
    EXPECT_EQ(valueFor("CommandPolicyVersion"),
              DaemonCommandPolicy::persistedCommandMarker(legacyCommand, false));
    EXPECT_EQ(valueFor("CommandStopAppliedNonce"), "stop-request-123");
    EXPECT_TRUE(DaemonCommandPolicy::validatePersistedCommand(
        valueFor("Command"), false, valueFor("CommandPolicyVersion"),
        daemonDir_ / "input-leapd.exe"));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartRejectsNonceUsedByCompletedStop)
{
    DaemonApp app;
    int applied = 0;
    std::vector<std::string> acknowledged;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [&acknowledged](const std::string& nonce) { acknowledged.push_back(nonce); },
    });

    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation A", false, "0123456789abcdef"));
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::stop(
        app, "fedcba9876543210", "0123456789abcdef"));

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation B", false, "fedcba9876543210"));
    EXPECT_EQ(applied, 1);
    EXPECT_EQ(acknowledged, (std::vector<std::string>{
        "0123456789abcdef", "fedcba9876543210"}));
}

TEST_F(DaemonCommandPolicyTests,
       DaemonAppStartRejectsNonceUsedByRestoredStop)
{
    DaemonApp app;
    int applied = 0;
    DaemonAppCommandTransactionTestAccess::useServices(app, {
        [](const std::string&, const std::string&) { return true; },
        [&applied](const std::string&, bool) { ++applied; return true; },
        [] { return true; },
        [](const std::string&) {},
    });
    ASSERT_TRUE(DaemonAppCommandTransactionTestAccess::restoreStopRequest(
        app, "fedcba9876543210", "0123456789abcdef",
        DaemonCommandPolicy::persistedStopMarker(
            "fedcba9876543210", "0123456789abcdef"),
        "fedcba9876543210"));

    EXPECT_FALSE(DaemonAppCommandTransactionTestAccess::start(
        app, "generation B", false, "fedcba9876543210"));
    EXPECT_EQ(applied, 0);
}

} // namespace
} // namespace inputleap
