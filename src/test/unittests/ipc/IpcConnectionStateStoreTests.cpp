#include "ipc/IpcConnectionStateStore.h"
#include "ipc/IpcClientProxy.h"
#include "ipc/IpcFrameReader.h"
#include "ipc/IpcServerProxy.h"
#include "io/IStream.h"
#include "test/mock/inputleap/MockEventQueue.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <deque>
#include <vector>

namespace inputleap {

namespace {

class FragmentStream final : public IStream
{
public:
    void append(std::uint8_t byte) { bytes_.push_back(byte); }
    bool closed() const { return closed_; }
    const std::vector<std::uint8_t>& written() const { return written_; }

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
    void write(const void* buffer, std::uint32_t size) override
    {
        const auto* bytes = static_cast<const std::uint8_t*>(buffer);
        written_.insert(written_.end(), bytes, bytes + size);
    }
    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return &target_; }
    bool isReady() const override { return !bytes_.empty(); }
    std::uint32_t getSize() const override { return static_cast<std::uint32_t>(bytes_.size()); }

private:
    EventTarget target_;
    std::deque<std::uint8_t> bytes_;
    std::vector<std::uint8_t> written_;
    bool closed_ = false;
};

IpcConnectionStateMessage state(IpcConnectionState value, IpcConnectionRole role,
                                IpcIdentityPresence presence, std::string name)
{
    return {value, role, presence, std::move(name), "detail"};
}

TEST(IpcConnectionStateStoreTests, nodeStateIsStoredAndRelayedOnlyToGui)
{
    IpcConnectionStateStore store;
    auto relays = store.receive(kIpcClientNode,
        state(IpcConnectionState::Connected, IpcConnectionRole::ServerPeer,
              IpcIdentityPresence::Known, "server-a"));

    ASSERT_EQ(relays.size(), 1u);
    EXPECT_EQ(relays[0].recipient, kIpcClientGui);
    EXPECT_EQ(relays[0].message.technicalName(), "server-a");
    EXPECT_EQ(store.snapshot().size(), 1u);

    EXPECT_TRUE(store.receive(kIpcClientGui,
        state(IpcConnectionState::Disconnected, IpcConnectionRole::ServerPeer,
              IpcIdentityPresence::Known, "spoofed")).empty());
    EXPECT_EQ(store.snapshot().size(), 1u);
}

TEST(IpcConnectionStateStoreTests, guiHelloReplaysCurrentSnapshot)
{
    IpcConnectionStateStore store;
    store.receive(kIpcClientNode,
        state(IpcConnectionState::Connected, IpcConnectionRole::ClientPeer,
              IpcIdentityPresence::Known, "peer-a"));

    const auto relays = store.clientConnected(kIpcClientGui);
    ASSERT_EQ(relays.size(), 1u);
    EXPECT_EQ(relays[0].recipient, kIpcClientGui);
    EXPECT_EQ(relays[0].message.state(), IpcConnectionState::Connected);
    EXPECT_EQ(relays[0].message.technicalName(), "peer-a");
    EXPECT_TRUE(store.clientConnected(kIpcClientNode).empty());
}

TEST(IpcConnectionStateStoreTests, nodeDisconnectMarksConnectedPeersAndNotifiesGui)
{
    IpcConnectionStateStore store;
    store.receive(kIpcClientNode, state(IpcConnectionState::Connected,
        IpcConnectionRole::ServerPeer, IpcIdentityPresence::Known, "server-a"));
    store.receive(kIpcClientNode, state(IpcConnectionState::Disconnected,
        IpcConnectionRole::ClientPeer, IpcIdentityPresence::Known, "peer-a"));

    const auto relays = store.clientDisconnected(kIpcClientNode);
    ASSERT_EQ(relays.size(), 1u);
    EXPECT_EQ(relays[0].recipient, kIpcClientGui);
    EXPECT_EQ(relays[0].message.state(), IpcConnectionState::Disconnected);
    EXPECT_EQ(relays[0].message.technicalName(), "server-a");
    EXPECT_EQ(store.snapshot().size(), 2u);
}

TEST(IpcConnectionStateStoreTests, guiDisconnectDoesNotClearSnapshot)
{
    IpcConnectionStateStore store;
    store.receive(kIpcClientNode, state(IpcConnectionState::Connected,
        IpcConnectionRole::ClientPeer, IpcIdentityPresence::Known, "peer-a"));

    EXPECT_TRUE(store.clientDisconnected(kIpcClientGui).empty());
    EXPECT_EQ(store.clientConnected(kIpcClientGui).size(), 1u);
}

TEST(IpcConnectionStateStoreTests, legacyUnavailableSlotsRemainDistinctByRole)
{
    IpcConnectionStateStore store;
    store.receive(kIpcClientNode, state(IpcConnectionState::Connected,
        IpcConnectionRole::ServerPeer, IpcIdentityPresence::LegacyUnavailable, ""));
    store.receive(kIpcClientNode, state(IpcConnectionState::Connected,
        IpcConnectionRole::ClientPeer, IpcIdentityPresence::LegacyUnavailable, ""));

    const auto snapshot = store.clientConnected(kIpcClientGui);
    ASSERT_EQ(snapshot.size(), 2u);
    EXPECT_NE(snapshot[0].message.role(), snapshot[1].message.role());
}

TEST(IpcFrameReaderTests, ClientHelloCanArriveOneByteAtATime)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::array<std::uint8_t, 5> frame{'I', 'H', 'E', 'L',
                                             static_cast<std::uint8_t>(kIpcClientNode)};

    for (std::size_t i = 0; i + 1 < frame.size(); ++i) {
        reader.append(&frame[i], 1);
        EXPECT_EQ(reader.take(), nullptr);
        EXPECT_FALSE(reader.invalid());
    }

    reader.append(&frame.back(), 1);
    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcHello);
    EXPECT_EQ(static_cast<IpcHelloMessage&>(*message).clientType(), kIpcClientNode);
    EXPECT_FALSE(reader.invalid());
}

TEST(IpcClientProxyTests, FragmentedHelloDoesNotDisconnectOrEmitPartialMessage)
{
    testing::NiceMock<MockEventQueue> events;
    IEventQueue::EventHandler inputReady;
    int received = 0;
    int disconnected = 0;
    EIpcClientType receivedType = kIpcClientUnknown;

    ON_CALL(events, add_handler(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Invoke(
            [&](EventType type, const EventTarget*, const IEventQueue::EventHandler& handler) {
                if (type == EventType::STREAM_INPUT_READY) inputReady = handler;
            }));
    ON_CALL(events, add_event(testing::_))
        .WillByDefault(testing::Invoke([&](Event&& event) {
            if (event.getType() == EventType::IPC_CLIENT_PROXY_MESSAGE_RECEIVED) {
                ++received;
                receivedType = static_cast<const IpcHelloMessage&>(
                    event.get_data_as<IpcMessage>()).clientType();
            } else if (event.getType() == EventType::IPC_CLIENT_PROXY_DISCONNECTED) {
                ++disconnected;
            }
            Event::deleteData(event);
        }));

    auto stream = std::make_unique<FragmentStream>();
    auto* rawStream = stream.get();
    {
        IpcClientProxy proxy(std::move(stream), &events);
        ASSERT_TRUE(static_cast<bool>(inputReady));
        const std::array<std::uint8_t, 5> frame{'I', 'H', 'E', 'L',
                                                 static_cast<std::uint8_t>(kIpcClientNode)};
        for (const auto byte : frame) {
            rawStream->append(byte);
            inputReady(Event(EventType::STREAM_INPUT_READY, rawStream->get_event_target()));
        }

        EXPECT_EQ(received, 1);
        EXPECT_EQ(receivedType, kIpcClientNode);
        EXPECT_EQ(disconnected, 0);
        EXPECT_FALSE(rawStream->closed());
    }
}


TEST(IpcServerProxyTests, FragmentedLogLineDoesNotDisconnectOrEmitPartialMessage)
{
    testing::NiceMock<MockEventQueue> events;
    IEventQueue::EventHandler inputReady;
    int received = 0;
    std::string receivedLine;

    ON_CALL(events, add_handler(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Invoke(
            [&](EventType type, const EventTarget*, const IEventQueue::EventHandler& handler) {
                if (type == EventType::STREAM_INPUT_READY) inputReady = handler;
            }));
    ON_CALL(events, add_event(testing::_))
        .WillByDefault(testing::Invoke([&](Event&& event) {
            if (event.getType() == EventType::IPC_SERVER_PROXY_MESSAGE_RECEIVED) {
                ++received;
                receivedLine = static_cast<const IpcLogLineMessage&>(
                    event.get_data_as<IpcMessage>()).logLine();
            }
            Event::deleteData(event);
        }));

    FragmentStream stream;
    {
        IpcServerProxy proxy(stream, &events);
        ASSERT_TRUE(static_cast<bool>(inputReady));
        const std::array<std::uint8_t, 10> frame{
            'I', 'L', 'O', 'G', 0, 0, 0, 2, 'o', 'k'};
        for (const auto byte : frame) {
            stream.append(byte);
            inputReady(Event(EventType::STREAM_INPUT_READY, stream.get_event_target()));
        }

        EXPECT_EQ(received, 1);
        EXPECT_EQ(receivedLine, "ok");
        EXPECT_FALSE(stream.closed());
    }
}

TEST(IpcServerProxyTests, RuntimeStatusResponseIsDispatchedWithoutLosingCorrelation)
{
    testing::NiceMock<MockEventQueue> events;
    IEventQueue::EventHandler inputReady;
    int received = 0;
    std::string queryNonce;
    std::string appliedNonce;
    std::uint8_t schemaVersion = 0;
    IpcRuntimeState runtimeState = IpcRuntimeState::Unknown;

    ON_CALL(events, add_handler(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Invoke(
            [&](EventType type, const EventTarget*, const IEventQueue::EventHandler& handler) {
                if (type == EventType::STREAM_INPUT_READY) inputReady = handler;
            }));
    ON_CALL(events, add_event(testing::_))
        .WillByDefault(testing::Invoke([&](Event&& event) {
            if (event.getType() == EventType::IPC_SERVER_PROXY_MESSAGE_RECEIVED) {
                ++received;
                const auto& status = static_cast<const IpcRuntimeStatusResponseMessage&>(
                    event.get_data_as<IpcMessage>());
                queryNonce = status.queryNonce();
                appliedNonce = status.appliedNonce();
                schemaVersion = status.schemaVersion();
                runtimeState = status.runtimeState();
            }
            Event::deleteData(event);
        }));

    const std::string query{"01234567\0abcdefg", 16};
    const std::string applied{"fedcba98\0" "7654321", 16};
    std::vector<std::uint8_t> frame{'I', 'R', 'T', 'S'};
    const auto appendString = [&frame](const std::string& value) {
        const auto size = static_cast<std::uint32_t>(value.size());
        frame.push_back(static_cast<std::uint8_t>(size >> 24));
        frame.push_back(static_cast<std::uint8_t>(size >> 16));
        frame.push_back(static_cast<std::uint8_t>(size >> 8));
        frame.push_back(static_cast<std::uint8_t>(size));
        frame.insert(frame.end(), value.begin(), value.end());
    };
    appendString(query);
    frame.push_back(1);
    frame.push_back(static_cast<std::uint8_t>(IpcRuntimeState::Running));
    appendString(applied);

    FragmentStream stream;
    {
        IpcServerProxy proxy(stream, &events);
        ASSERT_TRUE(static_cast<bool>(inputReady));
        for (std::size_t i = 0; i < frame.size(); ++i) {
            stream.append(frame[i]);
            inputReady(Event(EventType::STREAM_INPUT_READY, stream.get_event_target()));
            EXPECT_EQ(received, i + 1 == frame.size() ? 1 : 0);
        }

        EXPECT_EQ(queryNonce, query);
        EXPECT_EQ(appliedNonce, applied);
        EXPECT_EQ(schemaVersion, 1);
        EXPECT_EQ(runtimeState, IpcRuntimeState::Running);
        EXPECT_FALSE(stream.closed());
    }
}

} // namespace
} // namespace inputleap
