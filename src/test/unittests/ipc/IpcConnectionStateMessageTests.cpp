#include "ipc/Ipc.h"
#include "ipc/IpcMessage.h"

#include <gtest/gtest.h>

using namespace inputleap;

TEST(IpcConnectionStateMessageTests, exposesTypedUtf8State)
{
    IpcConnectionStateMessage message(
        IpcConnectionState::Connected,
        IpcConnectionRole::ClientPeer,
        IpcIdentityPresence::Known,
        "escritório-猫",
        "ligação segura");

    EXPECT_EQ(kIpcConnectionState, message.type());
    EXPECT_EQ(IpcConnectionState::Connected, message.state());
    EXPECT_EQ(IpcConnectionRole::ClientPeer, message.role());
    EXPECT_EQ(IpcIdentityPresence::Known, message.identityPresence());
    EXPECT_EQ("escritório-猫", message.technicalName());
    EXPECT_EQ("ligação segura", message.detail());
}

TEST(IpcConnectionStateMessageTests, rejectsMissingKnownIdentity)
{
    EXPECT_THROW(
        IpcConnectionStateMessage(IpcConnectionState::Available,
                                  IpcConnectionRole::ServerPeer,
                                  IpcIdentityPresence::Known, "", ""),
        std::invalid_argument);
}

TEST(IpcConnectionStateMessageTests, permitsExplicitLegacyIdentityDegradation)
{
    EXPECT_NO_THROW(
        IpcConnectionStateMessage(IpcConnectionState::Disconnected,
                                  IpcConnectionRole::ClientPeer,
                                  IpcIdentityPresence::LegacyUnavailable, "", "legacy client"));
}
