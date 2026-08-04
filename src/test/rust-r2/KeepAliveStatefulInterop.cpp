#define INPUTLEAP_TEST_ENV
#include "inputleap/Screen.h"
#undef INPUTLEAP_TEST_ENV

#include "base/Event.h"
#include "base/EventQueueTimer.h"
#include "base/EventTarget.h"
#include "base/IEventQueue.h"
#include "base/IEventQueueBuffer.h"
#include "base/Log.h"
#include "client/Client.h"
#include "client/ServerProxy.h"
#include "inputleap/ClientArgs.h"
#include "inputleap/ProtocolUtil.h"
#include "inputleap/protocol_types.h"
#include "io/IStream.h"
#include "net/IDataSocket.h"
#include "net/IListenSocket.h"
#include "net/ISocketFactory.h"
#include "net/NetworkAddress.h"
#include "server/ClientProxy1_6.h"
#include "server/IClientConnection.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace inputleap::rust_r2 {
namespace {

class ScriptedStream final : public IStream, public EventTarget
{
public:
    void appendInput(const std::vector<std::uint8_t>& bytes)
    {
        input_.insert(input_.end(), bytes.begin(), bytes.end());
    }

    std::vector<std::uint8_t> takeOutput()
    {
        auto bytes = output_;
        output_.clear();
        return bytes;
    }

    const std::vector<std::uint8_t>& output() const { return output_; }

    void close() override { closed_ = true; }

    std::uint32_t read(void* buffer, std::uint32_t size) override
    {
        const auto remaining = input_.size() - input_offset_;
        const auto count = std::min<std::size_t>(remaining, size);
        if (count != 0 && buffer != nullptr) {
            std::memcpy(buffer, input_.data() + input_offset_, count);
        }
        input_offset_ += count;
        return static_cast<std::uint32_t>(count);
    }

    void write(const void* data, std::uint32_t size) override
    {
        if (size == 0) {
            return;
        }
        if (data == nullptr) {
            throw std::invalid_argument("null stream write");
        }
        if (static_cast<std::size_t>(size) > output_.max_size() - output_.size()) {
            throw std::length_error("stream output size overflow");
        }
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        output_.insert(output_.end(), bytes, bytes + size);
    }

    void flush() override { ++flush_count_; }
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return this; }
    bool isReady() const override { return input_offset_ < input_.size(); }
    std::uint32_t getSize() const override
    {
        const auto remaining = input_.size() - input_offset_;
        if (remaining > (std::numeric_limits<std::uint32_t>::max)()) {
            throw std::length_error("stream input size exceeds u32");
        }
        return static_cast<std::uint32_t>(remaining);
    }

    bool closed() const { return closed_; }

private:
    std::vector<std::uint8_t> input_;
    std::size_t input_offset_ = 0;
    std::vector<std::uint8_t> output_;
    std::uint32_t flush_count_ = 0;
    bool closed_ = false;
};

class SpyEventQueue final : public IEventQueue
{
public:
    ~SpyEventQueue() override
    {
        for (auto* timer : live_timers_) {
            delete timer;
        }
    }

    void loop() override {}
    void set_buffer(std::unique_ptr<IEventQueueBuffer>) override {}
    bool getEvent(Event&, double) override { return false; }

    bool dispatchEvent(const Event& event) override
    {
        const auto exact = handlers_.find({event.getType(), event.getTarget()});
        if (exact != handlers_.end()) {
            exact->second(event);
            return true;
        }
        const auto fallback = handlers_.find({EventType::UNKNOWN, event.getTarget()});
        if (fallback != handlers_.end()) {
            fallback->second(event);
            return true;
        }
        return false;
    }

    void add_event(Event&& event) override
    {
        added_events_.push_back({event.getType(), event.getTarget()});
        if ((event.getFlags() & Event::kDeliverImmediately) != 0) {
            dispatchEvent(event);
        }
        Event::deleteData(event);
    }

    EventQueueTimer* newTimer(double, const EventTarget*) override
    {
        ++new_timer_count_;
        return allocateTimer();
    }

    EventQueueTimer* newOneShotTimer(double, const EventTarget*) override
    {
        ++new_one_shot_count_;
        return allocateTimer();
    }

    void deleteTimer(EventQueueTimer* timer) override
    {
        if (timer == nullptr || live_timers_.erase(timer) != 1) {
            throw std::runtime_error("deleteTimer received unknown timer");
        }
        ++delete_timer_count_;
        handlers_.erase({EventType::TIMER, timer});
        delete timer;
    }

    void add_handler(EventType type, const EventTarget* target,
                     const EventHandler& handler) override
    {
        handlers_[{type, target}] = handler;
    }

    void remove_handler(EventType type, const EventTarget* target) override
    {
        handlers_.erase({type, target});
    }

    void remove_handlers(const EventTarget* target) override
    {
        for (auto it = handlers_.begin(); it != handlers_.end();) {
            if (it->first.second == target) {
                it = handlers_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    void waitForReady() const override {}
    const EventTarget* getSystemTarget() override { return &system_target_; }

    bool sawEvent(EventType type, const EventTarget* target) const
    {
        return std::find(added_events_.begin(), added_events_.end(),
                         std::make_pair(type, target)) != added_events_.end();
    }

    std::size_t newOneShotCount() const { return new_one_shot_count_; }
    std::size_t deleteTimerCount() const { return delete_timer_count_; }

private:
    EventQueueTimer* allocateTimer()
    {
        auto* timer = new EventQueueTimer();
        live_timers_.insert(timer);
        return timer;
    }

    std::map<std::pair<EventType, const EventTarget*>, EventHandler> handlers_;
    std::vector<std::pair<EventType, const EventTarget*>> added_events_;
    std::set<EventQueueTimer*> live_timers_;
    EventTarget system_target_;
    std::size_t new_timer_count_ = 0;
    std::size_t new_one_shot_count_ = 0;
    std::size_t delete_timer_count_ = 0;
};

class FakeScreen final : public Screen, public EventTarget
{
public:
    FakeScreen() : Screen() {}
    const EventTarget* get_event_target() const override { return this; }
    void getShape(std::int32_t& x, std::int32_t& y, std::int32_t& w,
                  std::int32_t& h) const override
    {
        x = 0;
        y = 0;
        w = 100;
        h = 100;
    }
    void getCursorPos(std::int32_t& x, std::int32_t& y) const override
    {
        x = 50;
        y = 50;
    }
    void resetOptions() override {}
    void setOptions(const OptionsList&) override {}
    void enable() override { enabled_ = true; }
    void disable() override { enabled_ = false; }

private:
    bool enabled_ = false;
};

class FakeSocketFactory final : public ISocketFactory
{
public:
    std::unique_ptr<IDataSocket> create(IArchNetwork::EAddressFamily,
                                         ConnectionSecurityLevel) const override
    {
        return {};
    }
    std::unique_ptr<IListenSocket> create_listen(IArchNetwork::EAddressFamily,
                                                  ConnectionSecurityLevel) const override
    {
        return {};
    }
};

class FakeClientConnection final : public IClientConnection, public EventTarget
{
public:
    const EventTarget* get_event_target() override { return this; }
    IStream* get_stream() override { return &stream_; }
    ScriptedStream& stream() { return stream_; }

    void send_query_info_1_6() override { ++send_count_; }
    void send_leave_1_6() override { ++send_count_; }
    void send_enter_1_6(std::int32_t, std::int32_t, std::uint32_t,
                        KeyModifierMask) override { ++send_count_; }
    void send_key_down_1_6(KeyID, KeyModifierMask, KeyButton) override { ++send_count_; }
    void send_key_up_1_6(KeyID, KeyModifierMask, KeyButton) override { ++send_count_; }
    void send_key_repeat_1_6(KeyID, KeyModifierMask, std::int32_t,
                             KeyButton) override { ++send_count_; }
    void send_mouse_down_1_6(ButtonID) override { ++send_count_; }
    void send_mouse_up_1_6(ButtonID) override { ++send_count_; }
    void send_mouse_move_1_6(std::int32_t, std::int32_t) override { ++send_count_; }
    void send_mouse_relative_move_1_6(std::int32_t, std::int32_t) override { ++send_count_; }
    void send_mouse_wheel_1_6(std::int32_t, std::int32_t) override { ++send_count_; }
    void send_drag_info_1_6(std::uint32_t, const std::string&) override { ++send_count_; }
    void send_screensaver_1_6(bool) override { ++send_count_; }
    void send_reset_options_1_6() override { ++send_count_; }
    void send_set_options_1_6(const OptionsList&) override { ++send_count_; }
    void send_info_ack_1_6() override { ++send_count_; }
    void send_keep_alive_1_6() override { ++send_count_; }
    void send_close_1_6(const char*) override { ++send_count_; }
    void send_clipboard_chunk_1_6(const ClipboardChunk&) override { ++send_count_; }
    void send_file_chunk_1_6(const FileChunk&) override { ++send_count_; }
    void send_grab_clipboard(ClipboardID) override { ++send_count_; }
    void flush() override { ++flush_count_; }
    void close() override
    {
        closed_ = true;
        stream_.close();
    }

    std::size_t sendCount() const { return send_count_; }
    bool closed() const { return closed_; }

private:
    ScriptedStream stream_;
    std::size_t send_count_ = 0;
    std::size_t flush_count_ = 0;
    bool closed_ = false;
};

std::vector<std::uint8_t> emitted(const char* format)
{
    ScriptedStream stream;
    ProtocolUtil::writef(&stream, format);
    return stream.takeOutput();
}

std::vector<std::uint8_t> emptyOptions()
{
    ScriptedStream stream;
    const OptionsList options;
    ProtocolUtil::writef(&stream, kMsgDSetOptions, &options);
    return stream.takeOutput();
}

std::vector<std::uint8_t> validInfo()
{
    ScriptedStream stream;
    ProtocolUtil::writef(&stream, kMsgDInfo, 0, 0, 100, 100, 0, 50, 50);
    return stream.takeOutput();
}

void requireBytes(const std::vector<std::uint8_t>& actual,
                  const std::vector<std::uint8_t>& expected, const char* label)
{
    if (actual != expected) {
        throw std::runtime_error(std::string(label) + " bytes differ from oracle");
    }
}

void clientHandshakeCase()
{
    SpyEventQueue events;
    FakeScreen screen;
    auto socket_factory = std::make_unique<FakeSocketFactory>();
    ClientArgs args;
    Client client(&events, "rust-r2", NetworkAddress(), socket_factory.get(), &screen, args);
    client.m_mock = true;
    ScriptedStream stream;
    ServerProxy proxy(&client, &stream, &events);

    stream.appendInput(emitted(kMsgCKeepAlive));
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target()))) {
        throw std::runtime_error("client handshake STREAM_INPUT_READY was not dispatched");
    }
    requireBytes(stream.output(), emitted(kMsgCKeepAlive), "client handshake");
}

void clientActiveCase()
{
    SpyEventQueue events;
    FakeScreen screen;
    auto socket_factory = std::make_unique<FakeSocketFactory>();
    ClientArgs args;
    Client client(&events, "rust-r2", NetworkAddress(), socket_factory.get(), &screen, args);
    client.m_mock = true;
    ScriptedStream stream;
    ServerProxy proxy(&client, &stream, &events);

    stream.appendInput(emptyOptions());
    stream.appendInput(emitted(kMsgCKeepAlive));
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target()))) {
        throw std::runtime_error("client active STREAM_INPUT_READY was not dispatched");
    }
    auto expected = emitted(kMsgCKeepAlive);
    const auto noop = emitted(kMsgCNoop);
    expected.insert(expected.end(), noop.begin(), noop.end());
    requireBytes(stream.output(), expected, "client active CALV then CNOP");
}

void serverHandshakeCase()
{
    SpyEventQueue events;
    auto backend = std::make_unique<FakeClientConnection>();
    auto* backend_ptr = backend.get();
    ClientProxy1_6 proxy("rust-r2", std::move(backend), nullptr, &events);
    backend_ptr->stream().appendInput(emitted(kMsgCKeepAlive));

    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY,
                                    backend_ptr->get_event_target()))) {
        throw std::runtime_error("server handshake STREAM_INPUT_READY was not dispatched");
    }
    if (!backend_ptr->closed() ||
        !events.sawEvent(EventType::CLIENT_PROXY_DISCONNECTED, proxy.get_event_target())) {
        throw std::runtime_error("server handshake CALV did not close and signal disconnect");
    }
}

void serverActiveCase()
{
    SpyEventQueue events;
    auto backend = std::make_unique<FakeClientConnection>();
    auto* backend_ptr = backend.get();
    ClientProxy1_6 proxy("rust-r2", std::move(backend), nullptr, &events);

    backend_ptr->stream().appendInput(validInfo());
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY,
                                    backend_ptr->get_event_target()))) {
        throw std::runtime_error("server DINF STREAM_INPUT_READY was not dispatched");
    }
    const auto sends_after_info = backend_ptr->sendCount();
    const auto one_shots_before_calv = events.newOneShotCount();
    const auto deletes_before_calv = events.deleteTimerCount();

    backend_ptr->stream().appendInput(emitted(kMsgCKeepAlive));
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY,
                                    backend_ptr->get_event_target()))) {
        throw std::runtime_error("server active STREAM_INPUT_READY was not dispatched");
    }
    if (backend_ptr->sendCount() != sends_after_info) {
        throw std::runtime_error("server active CALV unexpectedly emitted a protocol message");
    }
    if (events.newOneShotCount() - one_shots_before_calv != 2 ||
        events.deleteTimerCount() - deletes_before_calv != 2) {
        throw std::runtime_error("server active CALV did not perform two structural alarm resets");
    }
}

} // namespace
} // namespace inputleap::rust_r2

int main()
{
    try {
        inputleap::Log log;
        inputleap::rust_r2::clientHandshakeCase();
        inputleap::rust_r2::clientActiveCase();
        inputleap::rust_r2::serverHandshakeCase();
        inputleap::rust_r2::serverActiveCase();
        std::cout << "RUST_R2_KEEPALIVE_STATEFUL_PASS "
                     "client_handshake=CALV client_active=CALV_THEN_CNOP "
                     "server_handshake=CLOSE_AND_DISCONNECTED "
                     "server_active=NO_SEND_AND_TWO_STRUCTURAL_RESETS "
                     "timer_expiration=NOT_COVERED_VIRTUAL_CLOCK_REQUIRED\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-keepalive-stateful: " << error.what() << '\n';
        return 1;
    }
}
