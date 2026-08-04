#include "ipc/IpcServer.h"
#include "ipc/IpcMessage.h"

#include <gtest/gtest.h>
#include <memory>

namespace inputleap {
namespace {

TEST(IpcServerMessageForwardingTests, CopiesRuntimeStatusRequestForDaemonDispatch)
{
    IpcRuntimeStatusRequestMessage request("0123456789abcdef");

    const std::shared_ptr<IpcMessage> copied =
        copyIpcServerMessageForDispatch(request);

    ASSERT_NE(copied, nullptr);
    ASSERT_EQ(copied->type(), kIpcRuntimeStatusRequest);
    EXPECT_EQ(
        static_cast<const IpcRuntimeStatusRequestMessage&>(*copied).queryNonce(),
        "0123456789abcdef");
}

TEST(IpcServerMessageForwardingTests, CopiesAtomicTopologyRequestForDaemonDispatch)
{
    IpcTopologyRequestMessage request(
        "fedcba9876543210", "0123456789abcdef", "topology payload");

    const std::shared_ptr<IpcMessage> copied =
        copyIpcServerMessageForDispatch(request);

    ASSERT_NE(copied, nullptr);
    ASSERT_EQ(copied->type(), kIpcTopologyRequest);
    const auto& topology = static_cast<const IpcTopologyRequestMessage&>(*copied);
    EXPECT_EQ(topology.requestNonce(), "fedcba9876543210");
    EXPECT_EQ(topology.expectedGeneration(), "0123456789abcdef");
    EXPECT_EQ(topology.payload(), "topology payload");
}

} // namespace
} // namespace inputleap
