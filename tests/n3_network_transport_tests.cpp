#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "upf/adapters/network_adapters.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

using SocketType = SOCKET;
constexpr SocketType kInvalidSocket = INVALID_SOCKET;
} // namespace