#include "net/SocketJobRegistration.h"

#include <gtest/gtest.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace inputleap {
namespace {

TEST(SocketJobRegistrationTests, closeRemovesRegistrationThatWasInFlight)
{
    SocketJobRegistration registration;
    std::mutex controlMutex;
    std::condition_variable controlReady;
    bool registrationEntered = false;
    bool releaseRegistration = false;
    bool closeStarted = false;
    std::atomic_bool installed{false};
    std::atomic_bool removed{false};

    std::thread registering([&] {
        registration.registerJob([&] {
            std::unique_lock<std::mutex> lock(controlMutex);
            registrationEntered = true;
            controlReady.notify_all();
            controlReady.wait(lock, [&] { return releaseRegistration; });
            installed = true;
        });
    });

    {
        std::unique_lock<std::mutex> lock(controlMutex);
        controlReady.wait(lock, [&] { return registrationEntered; });
    }

    std::thread closing([&] {
        {
            std::lock_guard<std::mutex> lock(controlMutex);
            closeStarted = true;
        }
        controlReady.notify_all();
        registration.close([&] {
            installed = false;
            removed = true;
        });
    });

    {
        std::unique_lock<std::mutex> lock(controlMutex);
        controlReady.wait(lock, [&] { return closeStarted; });
        releaseRegistration = true;
    }
    controlReady.notify_all();

    registering.join();
    closing.join();

    EXPECT_TRUE(removed);
    EXPECT_FALSE(installed);
}

TEST(SocketJobRegistrationTests, closeRejectsLateRegistration)
{
    SocketJobRegistration registration;
    bool installed = false;

    registration.close([] {});
    const bool accepted = registration.registerJob([&] { installed = true; });

    EXPECT_FALSE(accepted);
    EXPECT_FALSE(installed);
}

} // namespace
} // namespace inputleap
