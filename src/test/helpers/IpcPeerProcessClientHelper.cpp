#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdlib>

#pragma comment(lib, "ws2_32.lib")

int main(int argc, char** argv)
{
    if (argc != 2) {
        return 2;
    }
    const int port = std::atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        return 3;
    }

    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        return 4;
    }
    const SOCKET socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socketHandle == INVALID_SOCKET) {
        WSACleanup();
        return 5;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(static_cast<u_short>(port));
    if (connect(socketHandle, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        closesocket(socketHandle);
        WSACleanup();
        return 6;
    }

    const unsigned char hello[] = {'I', 'H', 'E', 'L', 1};
    if (send(socketHandle, reinterpret_cast<const char*>(hello), sizeof(hello), 0) !=
        static_cast<int>(sizeof(hello))) {
        closesocket(socketHandle);
        WSACleanup();
        return 7;
    }

    char byte = 0;
    recv(socketHandle, &byte, 1, 0);
    closesocket(socketHandle);
    WSACleanup();
    return 0;
}
