#include "base/Event.h"
#include "base/EventTarget.h"
#include "base/EventTypes.h"
#include "net/IDataSocket.h"
#include "net/IListenSocket.h"
#include "net/ISocketFactory.h"
#include "net/NetworkAddress.h"
#include "server/ClientListener.h"
#include "test/global/TestEventQueue.h"

#include <gtest/gtest.h>

#include <memory>

namespace inputleap {
namespace {

struct SocketLifetime {
    int destroyed = 0;
};

class FailingDataSocket final : public IDataSocket {
public:
    FailingDataSocket(IEventQueue* events, SocketLifetime* lifetime) :
        IDataSocket(events), lifetime_(lifetime)
    {
    }

    ~FailingDataSocket() override { ++lifetime_->destroyed; }

    void bind(const NetworkAddress&) override {}
    void close() override {}
    const EventTarget* get_event_target() const override { return &target_; }
    void connect(const NetworkAddress&) override {}
    std::uint32_t read(void*, std::uint32_t) override { return 0; }
    void write(const void*, std::uint32_t) override {}
    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    bool isReady() const override { return false; }
    std::uint32_t getSize() const override { return 0; }
    bool isFatal() const override { return true; }

private:
    EventTarget target_;
    SocketLifetime* lifetime_;
};

class FakeListenSocket final : public IListenSocket {
public:
    explicit FakeListenSocket(std::unique_ptr<IDataSocket> socket) : socket_(std::move(socket)) {}

    void bind(const NetworkAddress&) override {}
    void close() override {}
    const EventTarget* get_event_target() const override { return &target_; }
    std::unique_ptr<IDataSocket> accept() override { return std::move(socket_); }

private:
    EventTarget target_;
    std::unique_ptr<IDataSocket> socket_;
};

class FakeSocketFactory final : public ISocketFactory {
public:
    explicit FakeSocketFactory(std::unique_ptr<IListenSocket> listen) : listen_(std::move(listen)) {}

    std::unique_ptr<IDataSocket> create(
        IArchNetwork::EAddressFamily, ConnectionSecurityLevel) const override
    {
        return nullptr;
    }

    std::unique_ptr<IListenSocket> create_listen(
        IArchNetwork::EAddressFamily, ConnectionSecurityLevel) const override
    {
        return std::move(listen_);
    }

private:
    mutable std::unique_ptr<IListenSocket> listen_;
};

TEST(ClientListenerTests, releasesSocketWhenSecureAcceptFails)
{
    TestEventQueue events;
    SocketLifetime lifetime;
    auto data_socket = std::make_unique<FailingDataSocket>(&events, &lifetime);
    const EventTarget* data_target = data_socket->get_event_target();
    auto listen_socket = std::make_unique<FakeListenSocket>(std::move(data_socket));
    const EventTarget* listen_target = listen_socket->get_event_target();
    auto factory = std::make_unique<FakeSocketFactory>(std::move(listen_socket));

    ClientListener listener(NetworkAddress(24801), std::move(factory), &events,
                            ConnectionSecurityLevel::ENCRYPTED_AUTHENTICATED);

    events.dispatchEvent(Event(EventType::LISTEN_SOCKET_CONNECTING, listen_target));
    EXPECT_EQ(lifetime.destroyed, 0);

    events.dispatchEvent(Event(EventType::CLIENT_LISTENER_ACCEPT_FAILED, data_target));
    EXPECT_EQ(lifetime.destroyed, 1);

    // Late or duplicate completion events must not run handlers for the
    // socket after ClientListener has released it.
    events.dispatchEvent(Event(EventType::CLIENT_LISTENER_ACCEPT_FAILED, data_target));
    events.dispatchEvent(Event(EventType::CLIENT_LISTENER_ACCEPTED, data_target));
    EXPECT_EQ(lifetime.destroyed, 1);
}

} // namespace
} // namespace inputleap
