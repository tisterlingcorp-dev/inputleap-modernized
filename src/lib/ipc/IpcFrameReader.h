#pragma once

#include "ipc/IpcMessage.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <vector>

namespace inputleap {

class IpcFrameReader
{
public:
    enum class Direction { ClientToServer, ServerToClient };

    explicit IpcFrameReader(Direction direction) : direction_(direction) {}

    void append(const void* data, std::size_t size);
    std::unique_ptr<IpcMessage> take();
    bool invalid() const { return invalid_; }

private:
    enum class FieldStatus { Ready, NeedMore, Invalid };

    FieldStatus readString(std::size_t offset, std::string& value,
                           std::size_t& nextOffset) const;
    std::unique_ptr<IpcMessage> takeBufferedFrame();
    std::unique_ptr<IpcMessage> takeClientFrame();
    std::unique_ptr<IpcMessage> takeServerFrame();
    void consume(std::size_t size);
    void fail();

    Direction direction_;
    std::vector<std::uint8_t> buffer_;
    std::deque<std::unique_ptr<IpcMessage>> ready_;
    bool invalid_ = false;
};

} // namespace inputleap
