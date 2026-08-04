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
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace inputleap::rust_r2 {
namespace {

class ScriptedStream final : public IStream, public EventTarget {
public:
    void append(const std::vector<std::uint8_t>& bytes) {
        input_.insert(input_.end(), bytes.begin(), bytes.end());
    }
    void close() override { closed_ = true; }
    std::uint32_t read(void* buffer, std::uint32_t size) override {
        const auto count = std::min<std::size_t>(size, input_.size() - offset_);
        if (count != 0) std::memcpy(buffer, input_.data() + offset_, count);
        offset_ += count;
        return static_cast<std::uint32_t>(count);
    }
    void write(const void* data, std::uint32_t size) override {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        output_.insert(output_.end(), bytes, bytes + size);
    }
    void flush() override {}
    void shutdownInput() override {}
    void shutdownOutput() override {}
    const EventTarget* get_event_target() const override { return this; }
    bool isReady() const override { return offset_ < input_.size(); }
    std::uint32_t getSize() const override {
        return static_cast<std::uint32_t>(input_.size() - offset_);
    }
    const std::vector<std::uint8_t>& output() const { return output_; }
    std::size_t remaining() const { return input_.size() - offset_; }
    bool closed() const { return closed_; }
private:
    std::vector<std::uint8_t> input_, output_;
    std::size_t offset_ = 0;
    bool closed_ = false;
};

class SpyEventQueue final : public IEventQueue {
public:
    ~SpyEventQueue() override {
        for (auto* timer : timers_) delete timer;
    }
    void loop() override {}
    void set_buffer(std::unique_ptr<IEventQueueBuffer>) override {}
    bool getEvent(Event&, double) override { return false; }
    bool dispatchEvent(const Event& event) override {
        const auto it = handlers_.find({event.getType(), event.getTarget()});
        if (it == handlers_.end()) return false;
        it->second(event);
        return true;
    }
    void add_event(Event&& event) override {
        added_.push_back(event.getType());
        Event::deleteData(event);
    }
    EventQueueTimer* newTimer(double, const EventTarget*) override {
        auto* timer = new EventQueueTimer();
        timers_.insert(timer);
        return timer;
    }
    EventQueueTimer* newOneShotTimer(double, const EventTarget*) override {
        return newTimer(0, nullptr);
    }
    void deleteTimer(EventQueueTimer* timer) override {
        timers_.erase(timer);
        delete timer;
    }
    void add_handler(EventType type, const EventTarget* target,
                     const EventHandler& handler) override {
        handlers_[{type, target}] = handler;
    }
    void remove_handler(EventType type, const EventTarget* target) override {
        handlers_.erase({type, target});
    }
    void remove_handlers(const EventTarget* target) override {
        for (auto it = handlers_.begin(); it != handlers_.end();) {
            if (it->first.second == target) it = handlers_.erase(it);
            else ++it;
        }
    }
    void waitForReady() const override {}
    const EventTarget* getSystemTarget() override { return &system_; }
    bool saw(EventType type) const {
        return std::find(added_.begin(), added_.end(), type) != added_.end();
    }
private:
    std::map<std::pair<EventType, const EventTarget*>, EventHandler> handlers_;
    std::set<EventQueueTimer*> timers_;
    std::vector<EventType> added_;
    EventTarget system_;
};

class FakeScreen final : public Screen, public EventTarget {
public:
    const EventTarget* get_event_target() const override { return this; }
    void getShape(std::int32_t& x, std::int32_t& y, std::int32_t& w,
                  std::int32_t& h) const override {
        x = y = 0;
        w = h = 100;
    }
    void getCursorPos(std::int32_t& x, std::int32_t& y) const override { x = y = 50; }
    void resetOptions() override {}
    void setOptions(const OptionsList&) override {}
    void enable() override {}
    void disable() override {}
};

class FakeSocketFactory final : public ISocketFactory {
public:
    std::unique_ptr<IDataSocket> create(IArchNetwork::EAddressFamily,
                                        ConnectionSecurityLevel) const override {
        return {};
    }
    std::unique_ptr<IListenSocket> create_listen(IArchNetwork::EAddressFamily,
                                                  ConnectionSecurityLevel) const override {
        return {};
    }
};

using KeyCall = std::tuple<KeyID, KeyModifierMask, std::int32_t, KeyButton>;

class RecordingClient final : public Client {
public:
    RecordingClient(IEventQueue* events, const std::string& name,
                    const NetworkAddress& address, ISocketFactory* factory, Screen* screen,
                    const ClientArgs& args)
        : Client(events, name, address, factory, screen, args) {}
    void keyRepeat(KeyID key, KeyModifierMask mask, std::int32_t count,
                   KeyButton button) override {
        keyRepeats_.emplace_back(key, mask, count, button);
    }
    void resetOptions() override { ++resets_; }
    void setOptions(const OptionsList&) override { ++options_; }
    const std::vector<KeyCall>& keyRepeats() const { return keyRepeats_; }
    std::size_t resets() const { return resets_; }
    std::size_t options() const { return options_; }
private:
    std::vector<KeyCall> keyRepeats_;
    std::size_t resets_ = 0, options_ = 0;
};

std::vector<std::uint8_t> emit(const char* format) {
    ScriptedStream stream;
    ProtocolUtil::writef(&stream, format);
    return stream.output();
}

std::vector<std::uint8_t> dkrp(std::uint16_t key, std::uint16_t mask,
                               std::uint16_t count, std::uint16_t button) {
    ScriptedStream stream;
    ProtocolUtil::writef(&stream, kMsgDKeyRepeat, static_cast<int>(key),
                         static_cast<int>(mask), static_cast<int>(count),
                         static_cast<int>(button));
    return stream.output();
}

std::vector<std::uint8_t> options() {
    ScriptedStream stream;
    OptionsList value;
    ProtocolUtil::writef(&stream, kMsgDSetOptions, &value);
    return stream.output();
}

std::vector<std::uint8_t> repeatedNoop(std::size_t count) {
    std::vector<std::uint8_t> result;
    const auto noop = emit(kMsgCNoop);
    for (std::size_t i = 0; i < count; ++i)
        result.insert(result.end(), noop.begin(), noop.end());
    return result;
}

void normalCase() {
    SpyEventQueue events;
    FakeScreen screen;
    FakeSocketFactory factory;
    ClientArgs args;
    RecordingClient client(&events, "rust-r2-dkrp", NetworkAddress(), &factory, &screen, args);
    client.m_mock = true;
    ScriptedStream stream;
    ServerProxy proxy(&client, &stream, &events);
    stream.append(options());
    stream.append(dkrp(0x1234, 0x8001, 0xffff, 2));
    stream.append(emit(kMsgCResetOptions));
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target())))
        throw std::runtime_error("public STREAM_INPUT_READY not dispatched");
    stream.append(dkrp(0, 0, 1, 2));
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target())))
        throw std::runtime_error("second STREAM_INPUT_READY not dispatched");
    const std::vector<KeyCall> expected{
        {static_cast<KeyID>(0x1234), static_cast<KeyModifierMask>(0x8001),
         static_cast<std::int32_t>(0xffff), static_cast<KeyButton>(2)},
        {static_cast<KeyID>(0), static_cast<KeyModifierMask>(0),
         static_cast<std::int32_t>(1), static_cast<KeyButton>(2)}};
    if (client.keyRepeats() != expected)
        throw std::runtime_error("DKRP callback field/order mismatch");
    if (client.options() != 1 || client.resets() != 1 || stream.remaining() != 0)
        throw std::runtime_error("DKRP did not continue through trailing CROP");
    if (stream.output() != repeatedNoop(3) || stream.closed() ||
        events.saw(EventType::CLIENT_CONNECTION_FAILED))
        throw std::runtime_error("normal DKRP CNOP/connection behavior mismatch");
}

void malformedLengthCase(std::size_t length) {
    const auto complete = dkrp(0x1234, 0x8001, 0xffff, 2);
    if (length < 4 || length >= complete.size())
        throw std::logic_error("malformed DKRP length must be 4..11");
    SpyEventQueue events;
    FakeScreen screen;
    FakeSocketFactory factory;
    ClientArgs args;
    RecordingClient client(&events, "rust-r2-dkrp-malformed", NetworkAddress(), &factory, &screen,
                           args);
    client.m_mock = true;
    ScriptedStream stream;
    ServerProxy proxy(&client, &stream, &events);
    stream.append(options());
    stream.append(std::vector<std::uint8_t>(complete.begin(), complete.begin() + length));
    if (!events.dispatchEvent(Event(EventType::STREAM_INPUT_READY, stream.get_event_target())))
        throw std::runtime_error("malformed STREAM_INPUT_READY not dispatched");
    if (!client.keyRepeats().empty() || stream.output() != emit(kMsgEBad) ||
        !events.saw(EventType::CLIENT_CONNECTION_FAILED) ||
        events.saw(EventType::CLIENT_DISCONNECTED))
        throw std::runtime_error("truncated DKRP was not rejected via connection-failed event");
}

void malformedCases() {
    for (std::size_t length = 4; length < 12; ++length)
        malformedLengthCase(length);
}

} // namespace
} // namespace inputleap::rust_r2

int main() {
    try {
        inputleap::Log log;
        inputleap::rust_r2::normalCase();
        inputleap::rust_r2::malformedCases();
        std::cout << "RUST_R2_DKRP_STATEFUL_PASS dispatch=PUBLIC_STREAM_INPUT_READY "
                     "callbacks=BOUNDARY_THEN_ZERO_ONE trailing_CROP=PROCESSED "
                     "parse=NORMAL_NONTERMINAL replies=THREE_CNOP "
                     "malformed_lengths_4_to_11=EBAD_CONNECTION_FAILED_NO_CALLBACK "
                     "client_disconnected_event=NOT_CLAIMED os_input=NOT_INVOKED\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "rust-r2-dkrp-stateful: " << error.what() << '\n';
        return 1;
    }
}
