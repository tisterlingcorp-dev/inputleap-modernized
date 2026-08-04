#include "base/log_outputters.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

namespace inputleap {
namespace {

TEST(FileLogOutputterTests, FilenameChangeWaitsForActiveFileOperation)
{
    FileLogOutputterState state("first.log");
    std::atomic_bool operationEntered = false;
    std::atomic_bool releaseOperation = false;
    std::atomic_bool filenameChanged = false;

    std::thread operation([&] {
        state.withFilename([&](const std::string&) {
            operationEntered.store(true, std::memory_order_release);
            while (!releaseOperation.load(std::memory_order_acquire))
                std::this_thread::yield();
        });
    });
    while (!operationEntered.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::thread setter([&] {
        state.setFilename("second.log");
        filenameChanged.store(true, std::memory_order_release);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    EXPECT_FALSE(filenameChanged.load(std::memory_order_acquire));
    releaseOperation.store(true, std::memory_order_release);
    operation.join();
    setter.join();
    EXPECT_TRUE(filenameChanged.load(std::memory_order_acquire));
    state.withFilename([](const std::string& filename) {
        EXPECT_EQ(filename, "second.log");
    });
}

TEST(FileLogOutputterTests, ConcurrentFilenameRotationAndWritesAreSerialized)
{
    const auto root = std::filesystem::temp_directory_path() /
        ("inputleap-filelog-race-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    const std::string first = (root / (std::string(80, 'a') + ".log")).string();
    const std::string second = (root / (std::string(80, 'b') + ".log")).string();
    FileLogOutputter outputter(first.c_str());
    std::atomic_bool start = false;

    auto rotate = [&](const std::string& one, const std::string& two) {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (int i = 0; i < 200000; ++i)
            outputter.setLogFilename((i & 1 ? one : two).c_str());
    };
    std::thread setterA(rotate, std::cref(first), std::cref(second));
    std::thread setterB(rotate, std::cref(second), std::cref(first));
    std::thread writer([&] {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        const std::string payload(2048, 'x');
        for (int i = 0; i < 5000; ++i)
            ASSERT_TRUE(outputter.write(kINFO, payload.c_str()));
    });
    start.store(true, std::memory_order_release);
    setterA.join();
    setterB.join();
    writer.join();

    EXPECT_TRUE(std::filesystem::exists(first) || std::filesystem::exists(second));
    EXPECT_TRUE(std::filesystem::exists(first + ".1") ||
                std::filesystem::exists(second + ".1"));
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

} // namespace
} // namespace inputleap
