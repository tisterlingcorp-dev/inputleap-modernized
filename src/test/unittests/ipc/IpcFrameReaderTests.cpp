#include "ipc/IpcFrameReader.h"
#include "inputleap/protocol_types.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

namespace inputleap {
namespace {

void appendU32(std::vector<std::uint8_t>& bytes, std::uint32_t value)
{
    bytes.push_back(static_cast<std::uint8_t>(value >> 24));
    bytes.push_back(static_cast<std::uint8_t>(value >> 16));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> maximumStartFrame(std::uint8_t nonceByte)
{
    std::vector<std::uint8_t> frame{'I', 'S', 'T', 'R'};
    appendU32(frame, 16);
    frame.insert(frame.end(), 16, nonceByte);
    appendU32(frame, PROTOCOL_MAX_STRING_LENGTH);
    frame.insert(frame.end(), PROTOCOL_MAX_STRING_LENGTH, 'x');
    frame.push_back(0);
    return frame;
}

TEST(IpcFrameReaderRobustnessTests, OversizedStringLengthIsRejected)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ServerToClient);
    const std::array<std::uint8_t, 8> frame{
        'I', 'L', 'O', 'G', 0xff, 0xff, 0xff, 0xff};

    reader.append(frame.data(), frame.size());

    EXPECT_EQ(reader.take(), nullptr);
    EXPECT_TRUE(reader.invalid());
}

TEST(IpcFrameReaderRobustnessTests, TruncatedStringRemainsPendingAndValid)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ServerToClient);
    const std::array<std::uint8_t, 9> frame{
        'I', 'L', 'O', 'G', 0, 0, 0, 2, 'o'};

    reader.append(frame.data(), frame.size());

    EXPECT_EQ(reader.take(), nullptr);
    EXPECT_FALSE(reader.invalid());
}

TEST(IpcFrameReaderRobustnessTests, CoalescedFramesAreReturnedInOrder)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::vector<std::uint8_t> frames{
        'I', 'H', 'E', 'L', static_cast<std::uint8_t>(kIpcClientGui),
        'I', 'C', 'M', 'D', 0, 0, 0, 3, 'r', 'u', 'n', 0};

    reader.append(frames.data(), frames.size());

    auto hello = reader.take();
    ASSERT_NE(hello, nullptr);
    ASSERT_EQ(hello->type(), kIpcHello);
    EXPECT_EQ(static_cast<IpcHelloMessage&>(*hello).clientType(), kIpcClientGui);

    auto command = reader.take();
    ASSERT_NE(command, nullptr);
    ASSERT_EQ(command->type(), kIpcCommand);
    const auto& decoded = static_cast<IpcCommandMessage&>(*command);
    EXPECT_EQ(decoded.command(), "run");
    EXPECT_FALSE(decoded.elevate());
    EXPECT_EQ(reader.take(), nullptr);
    EXPECT_FALSE(reader.invalid());
}

TEST(IpcFrameReaderRobustnessTests, CoalescedMaximumFramesInOneAppendAreReturnedInOrder)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    auto frames = maximumStartFrame(0x11);
    const auto second = maximumStartFrame(0x22);
    frames.insert(frames.end(), second.cbegin(), second.cend());

    reader.append(frames.data(), frames.size());

    auto firstMessage = reader.take();
    ASSERT_NE(firstMessage, nullptr);
    ASSERT_EQ(firstMessage->type(), kIpcStartRequest);
    const auto& first = static_cast<const IpcStartRequestMessage&>(*firstMessage);
    EXPECT_EQ(first.nonce(), std::string(16, static_cast<char>(0x11)));
    EXPECT_EQ(first.command().size(), PROTOCOL_MAX_STRING_LENGTH);

    auto secondMessage = reader.take();
    ASSERT_NE(secondMessage, nullptr);
    ASSERT_EQ(secondMessage->type(), kIpcStartRequest);
    const auto& decodedSecond =
        static_cast<const IpcStartRequestMessage&>(*secondMessage);
    EXPECT_EQ(decodedSecond.nonce(), std::string(16, static_cast<char>(0x22)));
    EXPECT_EQ(decodedSecond.command().size(), PROTOCOL_MAX_STRING_LENGTH);
    EXPECT_EQ(reader.take(), nullptr);
    EXPECT_FALSE(reader.invalid());
}

TEST(IpcFrameReaderRobustnessTests, InvalidConnectionStateEnumIsRejected)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::array<std::uint8_t, 7> frame{
        'I', 'S', 'T', 'S', 0xff, 0, 0};

    reader.append(frame.data(), frame.size());

    EXPECT_EQ(reader.take(), nullptr);
    EXPECT_TRUE(reader.invalid());
}

TEST(IpcFrameReaderRobustnessTests, CorrelatedStartRequestPreservesNonceAndCommand)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::vector<std::uint8_t> frame{
        'I', 'S', 'T', 'R', 0, 0, 0, 16,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff,
        0, 0, 0, 3, 'r', 'u', 'n', 1};
    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcStartRequest);
    const auto& start = static_cast<IpcStartRequestMessage&>(*message);
    const std::string expectedNonce(frame.cbegin() + 8, frame.cbegin() + 24);
    EXPECT_EQ(start.nonce(), expectedNonce);
    EXPECT_EQ(start.command(), "run");
    EXPECT_TRUE(start.elevate());
}

TEST(IpcFrameReaderRobustnessTests, CorrelatedStopRequestPreservesBothBinaryNonces)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::vector<std::uint8_t> frame{
        'I', 'S', 'T', 'P', 0, 0, 0, 16,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff,
        0, 0, 0, 16,
        0xff, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcStopRequest);
    const auto& stop = static_cast<IpcStopRequestMessage&>(*message);
    EXPECT_EQ(stop.requestNonce(),
              std::string(frame.cbegin() + 8, frame.cbegin() + 24));
    EXPECT_EQ(stop.expectedAppliedNonce(),
              std::string(frame.cbegin() + 28, frame.cend()));
}

TEST(IpcFrameReaderRobustnessTests, CorrelatedReloadRequestPreservesBothBinaryNonces)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::vector<std::uint8_t> frame{
        'I', 'R', 'L', 'D',
        0, 0, 0, 16,
        0xff, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        0, 0, 0, 16,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff};
    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcReloadRequest);
    const auto& reload = static_cast<IpcReloadRequestMessage&>(*message);
    const std::string expectedRequest(frame.cbegin() + 8, frame.cbegin() + 24);
    const std::string expectedApplied(frame.cbegin() + 28, frame.cend());
    EXPECT_EQ(reload.requestNonce(), expectedRequest);
    EXPECT_EQ(reload.expectedAppliedNonce(), expectedApplied);
}

TEST(IpcFrameReaderRobustnessTests, AtomicTopologyRequestPreservesGenerationsAndPayload)
{
    const std::string payload = "section: screens\n\tprimary:\nend\n";
    std::vector<std::uint8_t> frame{
        'I', 'T', 'O', 'P',
        0, 0, 0, 16,
        0xff, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        0, 0, 0, 16,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff,
        0, 0, 0, static_cast<std::uint8_t>(payload.size())};
    frame.insert(frame.end(), payload.begin(), payload.end());
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);

    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcTopologyRequest);
    const auto& topology = static_cast<IpcTopologyRequestMessage&>(*message);
    EXPECT_EQ(topology.requestNonce(),
              std::string(frame.cbegin() + 8, frame.cbegin() + 24));
    EXPECT_EQ(topology.expectedGeneration(),
              std::string(frame.cbegin() + 28, frame.cbegin() + 44));
    EXPECT_EQ(topology.payload(), payload);
    EXPECT_FALSE(reader.invalid());
}

TEST(IpcFrameReaderRobustnessTests, RuntimeStatusQueryPreservesBinaryNonce)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ClientToServer);
    const std::vector<std::uint8_t> frame{
        'I', 'G', 'S', 'T', 0, 0, 0, 16,
        0xff, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcRuntimeStatusRequest);
    const auto& query = static_cast<IpcRuntimeStatusRequestMessage&>(*message);
    EXPECT_EQ(query.queryNonce(), std::string(frame.cbegin() + 8, frame.cend()));
}

TEST(IpcFrameReaderRobustnessTests, RuntimeStatusResponsePreservesGenerationAndState)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ServerToClient);
    const std::vector<std::uint8_t> frame{
        'I', 'R', 'T', 'S', 0, 0, 0, 16,
        0xff, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
        1, static_cast<std::uint8_t>(IpcRuntimeState::Running),
        0, 0, 0, 16,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff};
    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcRuntimeStatusResponse);
    const auto& status = static_cast<IpcRuntimeStatusResponseMessage&>(*message);
    EXPECT_EQ(status.queryNonce(), std::string(frame.cbegin() + 8, frame.cbegin() + 24));
    EXPECT_EQ(status.schemaVersion(), 1);
    EXPECT_EQ(status.runtimeState(), IpcRuntimeState::Running);
    EXPECT_EQ(status.appliedNonce(), std::string(frame.cbegin() + 30, frame.cend()));
}

TEST(IpcFrameReaderRobustnessTests, CorrelatedStopAcknowledgementPreservesBinaryNonce)
{
    IpcFrameReader reader(IpcFrameReader::Direction::ServerToClient);
    const std::vector<std::uint8_t> frame{
        'I', 'A', 'C', 'K', 0, 0, 0, 16,
        0xff, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    reader.append(frame.data(), frame.size());

    auto message = reader.take();
    ASSERT_NE(message, nullptr);
    ASSERT_EQ(message->type(), kIpcCommandApplied);
    const auto& applied = static_cast<IpcCommandAppliedMessage&>(*message);
    const std::string expected(frame.cbegin() + 8, frame.cend());
    EXPECT_EQ(applied.nonce(), expected);
}

} // namespace
} // namespace inputleap
