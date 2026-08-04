#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace inputleap::protocol_fixture {

enum class Category {
    Accepted,
    NeedMore,
    Malformed,
    Oversized,
    UnsupportedVersion
};

struct Fixture {
    std::string name;
    Category category;
    std::vector<std::uint8_t> bytes;
    std::string oracle;
    std::string kind;
    std::string sourceSymbol;
};

Fixture consecutiveStrings();
std::vector<Fixture> initialCorpus();
void emit(const std::filesystem::path& outputDirectory, const std::vector<Fixture>& fixtures);

} // namespace inputleap::protocol_fixture
