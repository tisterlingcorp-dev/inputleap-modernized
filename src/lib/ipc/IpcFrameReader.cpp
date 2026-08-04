#include "ipc/IpcFrameReader.h"

#include "ipc/Ipc.h"
#include "inputleap/protocol_types.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace inputleap {
namespace {

constexpr std::size_t kCodeSize = 4;
constexpr std::size_t kMaximumFrameSize =
    kCodeSize + 3 + 2 * (4 + static_cast<std::size_t>(PROTOCOL_MAX_STRING_LENGTH));

std::uint32_t readU32(const std::uint8_t* data)
{
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
            static_cast<std::uint32_t>(data[3]);
}

bool codeEquals(const std::vector<std::uint8_t>& buffer, const char* code)
{
    return buffer.size() >= kCodeSize &&
           std::memcmp(buffer.data(), code, kCodeSize) == 0;
}

} // namespace

void IpcFrameReader::append(const void* data, std::size_t size)
{
    if (invalid_ || size == 0) {
        return;
    }
    if (data == nullptr) {
        fail();
        return;
    }

    auto* bytes = static_cast<const std::uint8_t*>(data);
    while (size != 0 && !invalid_) {
        const std::size_t available = kMaximumFrameSize - buffer_.size();
        const std::size_t chunkSize = std::min(size, available);
        buffer_.insert(buffer_.end(), bytes, bytes + chunkSize);
        bytes += chunkSize;
        size -= chunkSize;

        while (!invalid_) {
            auto message = takeBufferedFrame();
            if (!message) {
                break;
            }
            ready_.push_back(std::move(message));
        }

        if (!invalid_ && buffer_.size() == kMaximumFrameSize) {
            fail();
        }
    }
}

std::unique_ptr<IpcMessage> IpcFrameReader::take()
{
    if (invalid_) {
        return nullptr;
    }
    if (!ready_.empty()) {
        auto message = std::move(ready_.front());
        ready_.pop_front();
        return message;
    }
    return takeBufferedFrame();
}

std::unique_ptr<IpcMessage> IpcFrameReader::takeBufferedFrame()
{
    if (buffer_.size() < kCodeSize) {
        return nullptr;
    }
    try {
        return direction_ == Direction::ClientToServer ? takeClientFrame()
                                                        : takeServerFrame();
    }
    catch (const std::exception&) {
        fail();
        return nullptr;
    }
}

IpcFrameReader::FieldStatus IpcFrameReader::readString(
    std::size_t offset, std::string& value, std::size_t& nextOffset) const
{
    if (offset > buffer_.size() || buffer_.size() - offset < 4) {
        return FieldStatus::NeedMore;
    }
    const std::uint32_t length = readU32(buffer_.data() + offset);
    if (length > PROTOCOL_MAX_STRING_LENGTH) {
        return FieldStatus::Invalid;
    }
    const std::size_t payloadOffset = offset + 4;
    if (buffer_.size() - payloadOffset < length) {
        return FieldStatus::NeedMore;
    }
    value.assign(reinterpret_cast<const char*>(buffer_.data() + payloadOffset), length);
    nextOffset = payloadOffset + length;
    return FieldStatus::Ready;
}

std::unique_ptr<IpcMessage> IpcFrameReader::takeClientFrame()
{
    if (codeEquals(buffer_, "IHEL")) {
        if (buffer_.size() < 5) return nullptr;
        const auto type = static_cast<EIpcClientType>(buffer_[4]);
        if (type != kIpcClientGui && type != kIpcClientNode) {
            fail();
            return nullptr;
        }
        consume(5);
        return std::make_unique<IpcHelloMessage>(type);
    }

    if (codeEquals(buffer_, "ICMD")) {
        std::string command;
        std::size_t offset = 0;
        const auto status = readString(4, command, offset);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid) {
            fail();
            return nullptr;
        }
        if (buffer_.size() <= offset) return nullptr;
        const auto elevate = buffer_[offset];
        if (elevate > 1) {
            fail();
            return nullptr;
        }
        consume(offset + 1);
        return std::make_unique<IpcCommandMessage>(command, elevate != 0);
    }

    if (codeEquals(buffer_, "ISTR")) {
        std::string nonce;
        std::string command;
        std::size_t offset = 0;
        auto status = readString(4, nonce, offset);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || nonce.size() != 16) {
            fail();
            return nullptr;
        }
        std::size_t commandEnd = 0;
        status = readString(offset, command, commandEnd);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || buffer_.size() <= commandEnd) {
            fail();
            return nullptr;
        }
        const auto elevate = buffer_[commandEnd];
        if (elevate > 1) {
            fail();
            return nullptr;
        }
        consume(commandEnd + 1);
        return std::make_unique<IpcStartRequestMessage>(
            std::move(nonce), std::move(command), elevate != 0);
    }

    if (codeEquals(buffer_, "ISTP")) {
        std::string requestNonce;
        std::size_t requestEnd = 0;
        auto status = readString(4, requestNonce, requestEnd);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || requestNonce.size() != 16) {
            fail();
            return nullptr;
        }
        std::string expectedAppliedNonce;
        std::size_t end = 0;
        status = readString(requestEnd, expectedAppliedNonce, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || expectedAppliedNonce.size() != 16 ||
            requestNonce == expectedAppliedNonce) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcStopRequestMessage>(
            std::move(requestNonce), std::move(expectedAppliedNonce));
    }

    if (codeEquals(buffer_, "IRLD")) {
        std::string requestNonce;
        std::size_t requestEnd = 0;
        auto status = readString(4, requestNonce, requestEnd);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || requestNonce.size() != 16) {
            fail();
            return nullptr;
        }
        std::string expectedAppliedNonce;
        std::size_t end = 0;
        status = readString(requestEnd, expectedAppliedNonce, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || expectedAppliedNonce.size() != 16) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcReloadRequestMessage>(
            std::move(requestNonce), std::move(expectedAppliedNonce));
    }

    if (codeEquals(buffer_, "IGST")) {
        std::string queryNonce;
        std::size_t end = 0;
        const auto status = readString(4, queryNonce, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || queryNonce.size() != 16) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcRuntimeStatusRequestMessage>(
            std::move(queryNonce));
    }

    if (codeEquals(buffer_, "ITOP")) {
        std::string requestNonce;
        std::size_t requestEnd = 0;
        auto status = readString(4, requestNonce, requestEnd);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || requestNonce.size() != 16) {
            fail();
            return nullptr;
        }
        std::string expectedGeneration;
        std::size_t expectedEnd = 0;
        status = readString(requestEnd, expectedGeneration, expectedEnd);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || expectedGeneration.size() != 16 ||
            requestNonce == expectedGeneration) {
            fail();
            return nullptr;
        }
        std::string payload;
        std::size_t end = 0;
        status = readString(expectedEnd, payload, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcTopologyRequestMessage>(
            std::move(requestNonce), std::move(expectedGeneration),
            std::move(payload));
    }

    if (codeEquals(buffer_, "ISTS")) {
        if (buffer_.size() < 7) return nullptr;
        const auto state = static_cast<IpcConnectionState>(buffer_[4]);
        const auto role = static_cast<IpcConnectionRole>(buffer_[5]);
        const auto presence = static_cast<IpcIdentityPresence>(buffer_[6]);
        if (state > IpcConnectionState::Disconnected ||
            role > IpcConnectionRole::ServerPeer ||
            presence > IpcIdentityPresence::LegacyUnavailable) {
            fail();
            return nullptr;
        }
        std::string technicalName;
        std::string detail;
        std::size_t offset = 0;
        auto status = readString(7, technicalName, offset);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid) {
            fail();
            return nullptr;
        }
        std::size_t end = 0;
        status = readString(offset, detail, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcConnectionStateMessage>(
            state, role, presence, std::move(technicalName), std::move(detail));
    }

    fail();
    return nullptr;
}

std::unique_ptr<IpcMessage> IpcFrameReader::takeServerFrame()
{
    if (codeEquals(buffer_, "ISDN")) {
        consume(4);
        return std::make_unique<IpcShutdownMessage>();
    }

    if (codeEquals(buffer_, "ILOG")) {
        std::string line;
        std::size_t end = 0;
        const auto status = readString(4, line, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcLogLineMessage>(line);
    }

    if (codeEquals(buffer_, "IACK")) {
        std::string nonce;
        std::size_t end = 0;
        const auto status = readString(4, nonce, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || nonce.size() != 16) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcCommandAppliedMessage>(std::move(nonce));
    }

    if (codeEquals(buffer_, "IRTS")) {
        std::string queryNonce;
        std::size_t offset = 0;
        auto status = readString(4, queryNonce, offset);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid || queryNonce.size() != 16) {
            fail();
            return nullptr;
        }
        if (buffer_.size() < offset + 2) return nullptr;
        const auto schemaVersion = buffer_[offset];
        const auto runtimeState = static_cast<IpcRuntimeState>(buffer_[offset + 1]);
        if (schemaVersion != 1 || runtimeState > IpcRuntimeState::Unknown) {
            fail();
            return nullptr;
        }
        std::string appliedNonce;
        std::size_t end = 0;
        status = readString(offset + 2, appliedNonce, end);
        if (status == FieldStatus::NeedMore) return nullptr;
        if (status == FieldStatus::Invalid ||
            (!appliedNonce.empty() && appliedNonce.size() != 16)) {
            fail();
            return nullptr;
        }
        consume(end);
        return std::make_unique<IpcRuntimeStatusResponseMessage>(
            std::move(queryNonce), schemaVersion, runtimeState,
            std::move(appliedNonce));
    }

    // Connection-state frames normally target the Qt GUI, but accepting the
    // documented daemon-to-client frame here keeps this decoder symmetric.
    if (codeEquals(buffer_, "ISTS")) {
        const Direction original = direction_;
        direction_ = Direction::ClientToServer;
        auto message = takeClientFrame();
        direction_ = original;
        return message;
    }

    fail();
    return nullptr;
}

void IpcFrameReader::consume(std::size_t size)
{
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(size));
}

void IpcFrameReader::fail()
{
    invalid_ = true;
    buffer_.clear();
    ready_.clear();
}

} // namespace inputleap
