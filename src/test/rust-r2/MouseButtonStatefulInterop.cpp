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

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
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
        if (bytes.size() > input_.max_size() - input_.size()) {
            throw std::length_error("stream input size overflow");
        }
        input_.insert(input_.end(), bytes.begin(), bytes.end());
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

    void flush() override {}
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

    EventQueueTimer* newTimer(double, const EventTarget*) override { return allocateTimer(); }
    EventQueueTimer* newOneShotTimer(double, const EventTarget*) override
    {
        return allocateTimer();
    }

    void deleteTimer(EventQueueTimer* timer) override
    {
        if (timer == nullptr || live_timers_.erase(timer) != 1) {
            throw std::runtime_error("deleteTimer received unknown timer");
        }
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

class RecordingClient final : public Client
{
public:
    using MouseCallback = std::pair<char, ButtonID>;

    RecordingClient(IEventQueue* events, const std::string& name, const NetworkAddress& address,
                    ISocketFactory* socket_factory, Screen* screen, const ClientArgs& args) :
        Client(events, name, address, socket_factory, screen, args)
    {
    }

    void mouseDown(ButtonID id) override { mouse_callbacks_.emplace_back('D', id); }
    void mouseUp(ButtonID id) override { mouse_callbacks_.emplace_back('U', id); }
    void resetOptions() override { ++reset_options_count_; }
    void setOptions(const OptionsList&) override { ++set_options_count_; }

    const std::vector<MouseCallback>& mouseCallbacks() const { return mouse_callbacks_; }
    std::size_t resetOptionsCount() const { return reset_options_count_; }
    std::size_t setOptionsCount() const { return set_options_count_; }

private:
    std::vector<MouseCallback> mouse_callbacks_;
    std::size_t reset_options_count_ = 0;
    std::size_t set_options_count_ = 0;
};

std::vector<std::uint8_t> emitted(const char* format)
{
    ScriptedStream stream;
    ProtocolUtil::writef(&stream, format);
    return stream.output();
}

std::vector<std::uint8_t> messageCode(const char* format)
{
    return {format, format + 4};
}

std::vector<std::uint8_t> mouseButton(const char* format, std::uint8_t raw)
{
    ScriptedStream stream;
    ProtocolUtil::writef(&stream, format, static_cast<unsigned int>(raw));
    if (stream.output().size() != 5 || stream.output().back() != raw) {
        throw std::logic_error("mouse-button ProtocolUtil writer emitted unexpected bytes");
    }
    return stream.output();
}

std::vector<std::uint8_t> emptyOptions()
{
    ScriptedStream stream;
    const OptionsList options;
    ProtocolUtil::writef(&stream, kMsgDSetOptions, &options);
    return stream.output();
}

std::vector<std::uint8_t> repeatedNoop(std::size_t count)
{
    const auto noop = emitted(kMsgCNoop);
    std::vector<std::uint8_t> expected;
    if (count > expected.max_size() / noop.size()) {
        throw std::length_error("expected CNOP output size overflow");
    }
    expected.reserve(count * noop.size());
    for (std::size_t i = 0; i < count; ++i) {
        expected.insert(expected.end(), noop.begin(), noop.end());
    }
    return expected;
}

void activeClientCase()
{
    SpyEventQueue events;
    FakeScreen screen;
    auto socket_factory = std::make_unique<FakeSocketFactory>();
    ClientArgs args;
    RecordingClient client(&events, "rust-r2-mouse-button", NetworkAddress(),
                           socket_factory.get(), &screen, args);
    client.m_mock = true;
    ScriptedStream stream;
    ServerProxy proxy(&client, &stream, &events);

    stream.appendInput(emptyOptions());
    stream.appendInput(mouseButton(kMsgDMouseDown, 1));
    stream.appendInput(mouseButton(kMsgDMouseUp, 1));
    stream.appendInput(mouseButton(kMsgDMouseDown, 255));
    stream.appendInput(mouseButton(kMsgDMouseUp, 255));
    stream.appendInput(emitted(kMsgCResetOptions));

    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target()))) {
        throw std::runtime_error("active client STREAM_INPUT_READY was not dispatched");
    }

    const std::vector<RecordingClient::MouseCallback> expected_callbacks{
        {'D', static_cast<ButtonID>(1)},
        {'U', static_cast<ButtonID>(1)},
        {'D', static_cast<ButtonID>(255)},
        {'U', static_cast<ButtonID>(255)},
    };
    if (client.mouseCallbacks() != expected_callbacks) {
        throw std::runtime_error("ServerProxy did not preserve ordered DMDN/DMUP u8 callbacks");
    }
    if (client.setOptionsCount() != 1) {
        throw std::runtime_error("active-state setup did not consume the empty DOPT message");
    }
    if (client.resetOptionsCount() != 1 || stream.getSize() != 0) {
        throw std::runtime_error("nonterminal mouse-button parse did not continue to trailing CROP");
    }
    if (stream.output() != repeatedNoop(5)) {
        throw std::runtime_error("active mouse-button sequence did not emit five ordered CNOP replies");
    }
    if (stream.closed() ||
        events.sawEvent(EventType::CLIENT_CONNECTION_FAILED, client.get_event_target()) ||
        events.sawEvent(EventType::CLIENT_DISCONNECTED, client.get_event_target())) {
        throw std::runtime_error("accepted mouse-button messages unexpectedly disconnected the client");
    }
}

void malformedButtonCase(const char* message)
{
    SpyEventQueue events;
    FakeScreen screen;
    auto socket_factory = std::make_unique<FakeSocketFactory>();
    ClientArgs args;
    RecordingClient client(&events, "rust-r2-mouse-button-malformed", NetworkAddress(),
                           socket_factory.get(), &screen, args);
    client.m_mock = true;
    ScriptedStream stream;
    ServerProxy proxy(&client, &stream, &events);

    stream.appendInput(emptyOptions());
    stream.appendInput(messageCode(message));

    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target()))) {
        throw std::runtime_error("malformed STREAM_INPUT_READY was not dispatched");
    }
    if (!client.mouseCallbacks().empty()) {
        throw std::runtime_error("truncated mouse-button message reached a client callback");
    }
    if (stream.output() != emitted(kMsgEBad)) {
        throw std::runtime_error("truncated mouse-button message did not emit EBAD only");
    }
    if (!events.sawEvent(EventType::CLIENT_CONNECTION_FAILED, client.get_event_target())) {
        throw std::runtime_error("truncated mouse-button message did not fail the connection");
    }
}

} // namespace
} // namespace inputleap::rust_r2

int main()
{
    try {
        inputleap::Log log;
        inputleap::rust_r2::activeClientCase();
        inputleap::rust_r2::malformedButtonCase(inputleap::kMsgDMouseDown);
        inputleap::rust_r2::malformedButtonCase(inputleap::kMsgDMouseUp);
        std::cout << "RUST_R2_MOUSE_BUTTON_STATEFUL_PASS "
                     "dispatch=PUBLIC_STREAM_INPUT_READY "
                     "callbacks=DMDN_1_DMUP_1_DMDN_255_DMUP_255 "
                     "trailing_CROP=PROCESSED parse=NORMAL_NONTERMINAL "
                     "replies=FIVE_CNOP disconnect=NONE "
                     "truncated_DMDN_DMUP=EBAD_DISCONNECT_NO_CALLBACK "
                     "os_input=NOT_INVOKED\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-mouse-button-stateful: " << error.what() << '\n';
        return 1;
    }
}
