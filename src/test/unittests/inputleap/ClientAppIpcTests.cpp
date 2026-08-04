#define INPUTLEAP_TEST_ENV

#include "inputleap/ClientApp.h"
#include "test/global/TestEventQueue.h"

#include <gtest/gtest.h>

namespace inputleap {

class TestClientApp : public ClientApp {
public:
    explicit TestClientApp(IEventQueue* events) : ClientApp(events, nullptr) {}

    using App::cleanupIpcClient;

    bool baseSendIpcConnectionState(IpcConnectionState state, IpcConnectionRole role,
                                    IpcIdentityPresence presence,
                                    const std::string& technicalName)
    {
        return App::sendIpcConnectionState(state, role, presence, technicalName);
    }

    bool sendIpcConnectionState(IpcConnectionState state, IpcConnectionRole role,
                                IpcIdentityPresence identityPresence,
                                const std::string& technicalName,
                                const std::string& detail) override
    {
        lastState = state;
        lastRole = role;
        lastPresence = identityPresence;
        lastName = technicalName;
        lastDetail = detail;
        ++sendCount;
        return true;
    }

    IpcConnectionState lastState{IpcConnectionState::Disconnected};
    IpcConnectionRole lastRole{IpcConnectionRole::ClientPeer};
    IpcIdentityPresence lastPresence{IpcIdentityPresence::Known};
    std::string lastName{"not-empty"};
    std::string lastDetail;
    int sendCount{0};
};

TEST(ClientAppIpcTests, disabledIpcWithoutClientRejectsConnectionState)
{
    TestEventQueue events;
    TestClientApp app(&events);
    app.args().m_enableIpc = false;

    EXPECT_FALSE(app.baseSendIpcConnectionState(
        IpcConnectionState::Connected, IpcConnectionRole::ClientPeer,
        IpcIdentityPresence::LegacyUnavailable, ""));
}

TEST(ClientAppIpcTests, connectedUsesLegacyUnavailableEmptyServerIdentity)
{
    TestEventQueue events;
    TestClientApp app(&events);

    app.handle_client_connected();

    EXPECT_EQ(app.sendCount, 1);
    EXPECT_EQ(app.lastState, IpcConnectionState::Connected);
    EXPECT_EQ(app.lastRole, IpcConnectionRole::ClientPeer);
    EXPECT_EQ(app.lastPresence, IpcIdentityPresence::LegacyUnavailable);
    EXPECT_TRUE(app.lastName.empty());
}

TEST(ClientAppIpcTests, disconnectedUsesLegacyUnavailableEmptyServerIdentity)
{
    TestEventQueue events;
    TestClientApp app(&events);
    app.args().m_restartable = false;

    app.handle_client_disconnected();

    EXPECT_EQ(app.sendCount, 1);
    EXPECT_EQ(app.lastState, IpcConnectionState::Disconnected);
    EXPECT_EQ(app.lastRole, IpcConnectionRole::ClientPeer);
    EXPECT_EQ(app.lastPresence, IpcIdentityPresence::LegacyUnavailable);
    EXPECT_TRUE(app.lastName.empty());
}

TEST(ClientAppIpcTests, cleanupWithoutClientIsIdempotent)
{
    TestEventQueue events;
    TestClientApp app(&events);

    app.cleanupIpcClient();
    app.cleanupIpcClient();
}

} // namespace inputleap