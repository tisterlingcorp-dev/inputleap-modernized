#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace inputleap {

struct ServerConnectionEventDecision {
    std::optional<std::string> screenDisconnected;
    bool serverDisconnected = false;
};

class ServerConnectionEventPolicy {
public:
    static ServerConnectionEventDecision activeClientRemoved(
        const std::string& screenName, bool removed, bool allowServerDisconnected,
        std::size_t remainingClientCount, std::size_t closingClientCount)
    {
        if (!removed) {
            return {};
        }
        return {screenName,
                allowServerDisconnected && remainingClientCount == 1 &&
                    closingClientCount == 0};
    }
};

} // namespace inputleap
