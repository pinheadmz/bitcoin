// work in prorgress: minimal http server for bitcoind

#include <chrono>
#include <thread>

#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <util/sock.h>
#include <util/threadnames.h>
#include <util/threadinterrupt.h>

static std::unique_ptr<Sock> sock;
static std::thread g_thread_http;
static CThreadInterrupt g_interrupt_http;
// same value is used for p2p sockets in net.cpp
static const auto SELECT_TIMEOUT = std::chrono::milliseconds(50);
// hard-coded value from libevent in evhttp_bind_socket_with_handle()
static const int SOCKET_BACKLOG{128};

bool InitHTTPServer_mz() {
    // Copied from CService::GetSockAddr() in netaddress.cpp
    // see also ConnectDirectly() in netbase.cpp for unix socket
    // TODO: abstract all three into netbase
    // TODO: (obviously) do not hard code the address and port
    struct sockaddr_in addrin;
    memset(&addrin, 0, sizeof(struct sockaddr_in));
    addrin.sin_family = AF_INET;
    addrin.sin_port = htons(14444);
    addrin.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1
    socklen_t len = sizeof(addrin);

    sock = CreateSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!sock) {
        LogPrintf("Could not create sock for incoming http connections\n");
        return false;
    }

    if (sock->Bind((struct sockaddr*)&addrin, len) == SOCKET_ERROR) {
        LogPrintf("Could not bind to socket for http: %s\n", NetworkErrorString(WSAGetLastError()));
        return false;
    }

    if (sock->Listen(/*backlog=*/SOCKET_BACKLOG) == SOCKET_ERROR) {
        LogPrintf("Could not listen to socket for http: %s\n", NetworkErrorString(WSAGetLastError()));
        return false;
    }

  LogPrintf("Initialized HTTP_mz server\n");
  return true;
}

static void ThreadHTTP_mz()
{
    util::ThreadRename("http_mz");
    LogPrintf("Entering http_mz loop\n");

    while (!g_interrupt_http) {
        // Copied from Session::Accept() in i2p.cpp
        // and CConnman::AcceptConnection() in net.cpp
        struct sockaddr_storage sockaddr_client;
        socklen_t len_client = sizeof(sockaddr);
        std::unique_ptr<Sock> sock_client = sock->Accept((struct sockaddr*)&sockaddr_client, &len_client);
        if (!sock_client) {
            // Nobody there, wait a tick before checking again
            g_interrupt_http.sleep_for(SELECT_TIMEOUT);
            continue;
        }

        Sock::Event occurred;
        if (!sock_client->Wait(MAX_WAIT_FOR_IO, Sock::RECV, &occurred)) {
            LogPrintf("http_mz wait on socket failed\n");
            continue;
        }

        if (occurred == 0) {
            // Timeout, no incoming connections or errors within MAX_WAIT_FOR_IO.
            continue;
        }

        char buf[512];
        int nBytes = sock_client->Recv(buf, sizeof(buf), 0);
        if (nBytes > 0) {
          std::cout << buf << std::endl;
        }
        if (nBytes == 0) {
          LogPrintf("http_mz nbytes=0 connection closed\n");
        }
        if (nBytes < 0) {
          LogPrintf("http_mz nbytes<0 error: %s\n", NetworkErrorString(WSAGetLastError()));
        }
    }

    LogPrintf("Exited http_mz loop\n");
}

void StartHTTPServer_mz() {
  LogPrintf("Starting HTTP_mz server\n");
  g_thread_http = std::thread(ThreadHTTP_mz);
}

void StopHTTPServer_mz() {
  g_interrupt_http();
  LogPrintf("Waiting for HTTP_mz thread to exit\n");
  if (g_thread_http.joinable()) g_thread_http.join();
  LogPrintf("Stopped HTTP_mz server\n");
}