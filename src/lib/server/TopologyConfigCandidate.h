#pragma once

#include "server/Config.h"

#include <optional>
#include <string>

namespace inputleap {

struct TopologyConfigCandidateResult
{
    std::optional<Config> config;
    std::string error;
};

class TopologyConfigCandidate
{
public:
    static TopologyConfigCandidateResult parse(
        const std::string& payload, const std::string& primaryScreen);
};

} // namespace inputleap
