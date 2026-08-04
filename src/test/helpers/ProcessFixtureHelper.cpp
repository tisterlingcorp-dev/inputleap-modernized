#include "ConfigurationTransactionLock.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

int main(int argc, char** argv)
{
    if (argc >= 2 && std::strcmp(argv[1], "--wait") == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }
    if (argc >= 3 && std::strcmp(argv[1], "--hold-configuration-lock") == 0) {
        ConfigurationTransactionLock lock(5000, QString::fromLocal8Bit(argv[2]));
        if (!lock.isLocked()) return 3;
        std::cout << "READY" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }
    if (argc >= 4 && std::strcmp(argv[1], "--try-configuration-lock") == 0) {
        const int timeoutMs = std::atoi(argv[2]);
        if (timeoutMs < 0) return 4;
        ConfigurationTransactionLock lock(timeoutMs, QString::fromLocal8Bit(argv[3]));
        std::cout << (lock.isLocked() ? "LOCKED" : "BLOCKED") << std::endl;
        return 0;
    }
    if (argc >= 3 && std::strcmp(argv[1], "--exit-code") == 0) {
        return std::atoi(argv[2]);
    }
    return 0;
}
