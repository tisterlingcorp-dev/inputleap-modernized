#include "net/SecureSocket.h"
#include "net/SocketMultiplexer.h"
#include "arch/IArchNetwork.h"
#include "test/mock/inputleap/MockEventQueue.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <string>

namespace inputleap {
namespace {

class SecureSocketProbe final : public SecureSocket {
public:
    SecureSocketProbe(IEventQueue* events, SocketMultiplexer* multiplexer) :
        SecureSocket(events, multiplexer, IArchNetwork::kINET,
                     ConnectionSecurityLevel::ENCRYPTED_AUTHENTICATED)
    {
    }

    bool readBlocked() { return doRead() == kRetry; }
    bool writeBlocked() { return doWrite() == kRetry; }

    void queueOutput(const std::string& bytes)
    {
        m_outputBuffer.write(bytes.data(), static_cast<std::uint32_t>(bytes.size()));
    }

    std::uint32_t pendingOutputSize() const { return m_outputBuffer.getSize(); }
    std::uint32_t pendingInputSize() const { return m_inputBuffer.getSize(); }
};

TEST(SecureSocketIoGateTests, ApplicationIoRemainsBlockedUntilPeerIsAuthenticated)
{
    testing::NiceMock<MockEventQueue> events;
    SocketMultiplexer multiplexer;
    SecureSocketProbe socket(&events, &multiplexer);
    socket.initSsl(false);

    ASSERT_FALSE(socket.isSecureReady());
    socket.queueOutput("must-not-leave-before-authentication");
    const auto pendingOutput = socket.pendingOutputSize();

    EXPECT_TRUE(socket.readBlocked());
    EXPECT_TRUE(socket.writeBlocked());
    EXPECT_FALSE(socket.isSecureReady());
    EXPECT_EQ(socket.pendingInputSize(), 0u);
    EXPECT_EQ(socket.pendingOutputSize(), pendingOutput);
}

TEST(SecureSocketIoGateTests, ClosingSocketRevokesSecureReadiness)
{
    testing::NiceMock<MockEventQueue> events;
    SocketMultiplexer multiplexer;
    SecureSocketProbe socket(&events, &multiplexer);
    socket.initSsl(false);

    socket.close();

    EXPECT_FALSE(socket.isSecureReady());
}

} // namespace
} // namespace inputleap
