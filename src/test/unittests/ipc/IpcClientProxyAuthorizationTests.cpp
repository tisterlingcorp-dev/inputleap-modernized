#include "ipc/IpcClientProxy.h"
#include "inputleap/protocol_types.h"
#include "io/IStream.h"
#include "test/mock/inputleap/MockEventQueue.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

namespace inputleap {
namespace {

class AuthorizationStream final : public IStream
{
public:
    void append(const std::vector<std::uint8_t>& bytes)
    {
        bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
    }

    void close() override { closed_ = true; }
    std::uint32_t read(void* buffer, std::uint32_t size) override
    {
        const auto count = std::min<std::size_t>(size, bytes_.size());
        auto* output = static_cast<std::uint8_t*>(buffer);
        for (std::size_t i = 0; i < count; ++i) {
            output[i] = bytes_.front();
            bytes_.pop_front();
        }
        return static_cast<std::uint32_t>(count);
    }
    void write(const void*, std::uint32_t) override {}
    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return &target_; }
    bool isReady() const override { return !bytes_.empty(); }
    std::uint32_t getSize() const override { return static_cast<std::uint32_t>(bytes_.size()); }

    bool closed() const { return closed_; }

private:
    EventTarget target_;
    std::deque<std::uint8_t> bytes_;
    bool closed_ = false;
};

std::vector<std::uint8_t> hello(EIpcClientType type)
{
    return {'I', 'H', 'E', 'L', static_cast<std::uint8_t>(type)};
}

std::vector<std::uint8_t> command()
{
    return {'I', 'C', 'M', 'D', 0, 0, 0, 3, 'r', 'u', 'n', 0};
}

std::vector<std::uint8_t> startRequest()
{
    return {'I', 'S', 'T', 'R', 0, 0, 0, 16,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 0, 0, 3, 'r', 'u', 'n', 0};
}

std::vector<std::uint8_t> maximumStartRequest(std::uint8_t nonceSeed)
{
    constexpr std::size_t commandSize = PROTOCOL_MAX_STRING_LENGTH;
    std::vector<std::uint8_t> frame{
        'I', 'S', 'T', 'R', 0, 0, 0, 16};
    for (std::uint8_t offset = 0; offset < 16; ++offset) {
        frame.push_back(static_cast<std::uint8_t>(nonceSeed + offset));
    }
    frame.insert(frame.end(), {0, 0x10, 0, 0});
    frame.insert(frame.end(), commandSize, 'x');
    frame.push_back(0);
    return frame;
}

std::vector<std::uint8_t> stopRequest()
{
    return {'I', 'S', 'T', 'P', 0, 0, 0, 16,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 0, 0, 16,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31};
}

std::vector<std::uint8_t> reloadRequest()
{
    return {'I', 'R', 'L', 'D', 0, 0, 0, 16,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 0, 0, 16,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31};
}

std::vector<std::uint8_t> runtimeStatusRequest()
{
    return {'I', 'G', 'S', 'T', 0, 0, 0, 16,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
}

std::vector<std::uint8_t> topologyRequest()
{
    return {'I', 'T', 'O', 'P', 0, 0, 0, 16,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            0, 0, 0, 16,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
            0, 0, 0, 3, 'c', 'f', 'g'};
}

std::vector<std::uint8_t> state()
{
    return {'I', 'S', 'T', 'S',
            static_cast<std::uint8_t>(IpcConnectionState::Connected),
            static_cast<std::uint8_t>(IpcConnectionRole::ServerPeer),
            static_cast<std::uint8_t>(IpcIdentityPresence::Known),
            0, 0, 0, 4, 'p', 'e', 'e', 'r',
            0, 0, 0, 0};
}

class IpcClientProxyAuthorizationTests : public testing::Test
{
protected:
    void SetUp() override
    {
        ON_CALL(events_, add_handler(testing::_, testing::_, testing::_))
            .WillByDefault(testing::Invoke(
                [&](EventType type, const EventTarget*, const IEventQueue::EventHandler& handler) {
                    if (type == EventType::STREAM_INPUT_READY) inputReady_ = handler;
                }));
        ON_CALL(events_, add_event(testing::_))
            .WillByDefault(testing::Invoke([&](Event&& event) {
                if (event.getType() == EventType::IPC_CLIENT_PROXY_MESSAGE_RECEIVED) {
                    delivered_.push_back(event.get_data_as<IpcMessage>().type());
                } else if (event.getType() == EventType::IPC_CLIENT_PROXY_DISCONNECTED) {
                    ++disconnects_;
                }
                Event::deleteData(event);
            }));

        auto stream = std::make_unique<AuthorizationStream>();
        stream_ = stream.get();
        proxy_ = std::make_unique<IpcClientProxy>(std::move(stream), &events_);
        ASSERT_TRUE(static_cast<bool>(inputReady_));
    }

    void feed(const std::vector<std::uint8_t>& bytes)
    {
        stream_->append(bytes);
        inputReady_(Event(EventType::STREAM_INPUT_READY, stream_->get_event_target()));
    }

    testing::NiceMock<MockEventQueue> events_;
    IEventQueue::EventHandler inputReady_;
    AuthorizationStream* stream_ = nullptr;
    std::unique_ptr<IpcClientProxy> proxy_;
    std::vector<std::uint8_t> delivered_;
    int disconnects_ = 0;
};

TEST_F(IpcClientProxyAuthorizationTests, CommandBeforeHelloIsRejectedWithoutDelivery)
{
    feed(command());

    EXPECT_TRUE(delivered_.empty());
    EXPECT_EQ(disconnects_, 1);
    EXPECT_TRUE(stream_->closed());
}

TEST_F(IpcClientProxyAuthorizationTests, NodeCannotSendCommand)
{
    feed(hello(kIpcClientNode));
    feed(command());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, GuiCannotSendConnectionState)
{
    feed(hello(kIpcClientGui));
    feed(state());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, SecondHelloIsRejected)
{
    feed(hello(kIpcClientGui));
    feed(hello(kIpcClientNode));

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, GuiCommandAfterHelloIsDelivered)
{
    feed(hello(kIpcClientGui));
    feed(command());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello, kIpcCommand}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, GuiCorrelatedStartAfterHelloIsDelivered)
{
    feed(hello(kIpcClientGui));
    feed(startRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello, kIpcStartRequest}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, CoalescedMaximumFramesAreDeliveredWithoutDisconnect)
{
    feed(hello(kIpcClientGui));
    auto frames = maximumStartRequest(0);
    const auto second = maximumStartRequest(16);
    frames.insert(frames.end(), second.begin(), second.end());

    feed(frames);

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({
        kIpcHello, kIpcStartRequest, kIpcStartRequest}));
    EXPECT_EQ(disconnects_, 0);
    EXPECT_FALSE(stream_->closed());
}

TEST_F(IpcClientProxyAuthorizationTests, GuiCorrelatedStopAfterHelloIsDelivered)
{
    feed(hello(kIpcClientGui));
    feed(stopRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello, kIpcStopRequest}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, GuiCorrelatedReloadAfterHelloIsDelivered)
{
    feed(hello(kIpcClientGui));
    feed(reloadRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello, kIpcReloadRequest}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, GuiRuntimeStatusQueryAfterHelloIsDelivered)
{
    feed(hello(kIpcClientGui));
    feed(runtimeStatusRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({
        kIpcHello, kIpcRuntimeStatusRequest}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, GuiAtomicTopologyAfterHelloIsDelivered)
{
    feed(hello(kIpcClientGui));
    feed(topologyRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({
        kIpcHello, kIpcTopologyRequest}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, NodeCannotSendAtomicTopology)
{
    feed(hello(kIpcClientNode));
    feed(topologyRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, NodeCannotQueryRuntimeStatus)
{
    feed(hello(kIpcClientNode));
    feed(runtimeStatusRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, NodeCannotSendCorrelatedReload)
{
    feed(hello(kIpcClientNode));
    feed(reloadRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, NodeCannotSendCorrelatedStop)
{
    feed(hello(kIpcClientNode));
    feed(stopRequest());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello}));
    EXPECT_EQ(disconnects_, 1);
}

TEST_F(IpcClientProxyAuthorizationTests, NodeStateAfterHelloIsDelivered)
{
    feed(hello(kIpcClientNode));
    feed(state());

    EXPECT_EQ(delivered_, std::vector<std::uint8_t>({kIpcHello, kIpcConnectionState}));
    EXPECT_EQ(disconnects_, 0);
}

TEST_F(IpcClientProxyAuthorizationTests, AuthenticatedGuiCannotClaimNodeRole)
{
    proxy_.reset();
    auto stream = std::make_unique<AuthorizationStream>();
    stream_ = stream.get();
    proxy_ = std::make_unique<IpcClientProxy>(
        std::move(stream), &events_, kIpcClientGui);
    ASSERT_TRUE(static_cast<bool>(inputReady_));

    feed(hello(kIpcClientNode));

    EXPECT_TRUE(delivered_.empty());
    EXPECT_EQ(disconnects_, 1);
    EXPECT_TRUE(stream_->closed());
}

} // namespace
} // namespace inputleap
