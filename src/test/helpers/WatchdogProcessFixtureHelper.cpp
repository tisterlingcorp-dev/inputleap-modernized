#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <thread>

int main(int argc, char** argv)
{
    if (const char* capturePath =
            std::getenv("INPUTLEAP_WATCHDOG_FIXTURE_ARGV_PATH")) {
        std::ofstream output(capturePath, std::ios::binary | std::ios::app);
        const auto argumentCount = static_cast<std::uint32_t>(argc);
        output.write(
            reinterpret_cast<const char*>(&argumentCount),
            sizeof(argumentCount));
        for (int index = 0; index < argc; ++index) {
            const auto argumentSize =
                static_cast<std::uint32_t>(std::strlen(argv[index]));
            output.write(
                reinterpret_cast<const char*>(&argumentSize),
                sizeof(argumentSize));
            output.write(argv[index], argumentSize);
        }
    }
    if (const char* configuredWait = std::getenv("INPUTLEAP_WATCHDOG_FIXTURE_WAIT_MS")) {
        char* end = nullptr;
        const long waitMs = std::strtol(configuredWait, &end, 10);
        if (end != configuredWait && *end == '\0' && waitMs > 0 && waitMs <= 60000) {
            std::this_thread::sleep_for(std::chrono::milliseconds(waitMs));
            return 0;
        }
    }
    if (argc >= 2 && std::strcmp(argv[1], "--wait") == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }
    else if (argc >= 2 && std::strcmp(argv[1], "--wait-short") == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(4));
    }
    return 0;
}
