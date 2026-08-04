#include "ipc/IpcServerDisconnectEventPolicy.h"

#include <gtest/gtest.h>
#include <list>

namespace inputleap {
namespace {

TEST(IpcServerDisconnectEventPolicyTests, eventRetainsNodeTypeByValue)
{
    EIpcClientType captured = kIpcClientNode;
    auto event = makeIpcServerClientDisconnectedEvent(nullptr, captured);
    captured = kIpcClientGui;

    EXPECT_EQ(event.getType(), EventType::IPC_SERVER_CLIENT_DISCONNECTED);
    EXPECT_EQ(event.get_data_as<IpcServerClientDisconnectedInfo>().clientType,
              kIpcClientNode);
    Event::deleteData(event);
}

TEST(IpcServerDisconnectEventPolicyTests, createsGuiAndUnknownDisconnectData)
{
    auto gui = makeIpcServerClientDisconnectedEvent(nullptr, kIpcClientGui);
    auto unknown = makeIpcServerClientDisconnectedEvent(nullptr, kIpcClientUnknown);

    EXPECT_EQ(gui.get_data_as<IpcServerClientDisconnectedInfo>().clientType, kIpcClientGui);
    EXPECT_EQ(unknown.get_data_as<IpcServerClientDisconnectedInfo>().clientType,
              kIpcClientUnknown);
    Event::deleteData(gui);
    Event::deleteData(unknown);
}

TEST(IpcServerDisconnectEventPolicyTests, removalByPointerAllowsOnlyOneEmission)
{
    int client = 0;
    std::list<int*> clients{&client};

    EXPECT_TRUE(removeIpcClientByPointer(clients, &client));
    EXPECT_FALSE(removeIpcClientByPointer(clients, &client));
    EXPECT_TRUE(clients.empty());
}

} // namespace
} // namespace inputleap
