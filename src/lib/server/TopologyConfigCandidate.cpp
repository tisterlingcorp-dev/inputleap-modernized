#include "server/TopologyConfigCandidate.h"

#include <exception>
#include <sstream>
#include <utility>

namespace inputleap {

TopologyConfigCandidateResult TopologyConfigCandidate::parse(
    const std::string& payload, const std::string& primaryScreen)
{
    try {
        Config candidate;
        std::istringstream stream(payload);
        stream >> candidate;
        if (!candidate.isScreen(primaryScreen)) {
            return {std::nullopt, "primary screen is missing from topology"};
        }
        return {std::move(candidate), {}};
    }
    catch (const std::exception& error) {
        return {std::nullopt, error.what()};
    }
}

} // namespace inputleap
