// work in prorgress: minimal http server for bitcoind

#include <chrono>
#include <thread>

#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <util/sock.h>
#include <util/string.h>
#include <util/strencodings.h>
#include <util/threadnames.h>
#include <util/threadinterrupt.h>

static std::unique_ptr<Sock> sock;
static std::thread g_thread_http;
static CThreadInterrupt g_interrupt_http;

// same value is used for p2p sockets in net.cpp
static const auto SELECT_TIMEOUT{std::chrono::milliseconds(50)};
// same value is used for p2p sockets in CConnman::SocketHandlerConnected()
// "typical socket buffer is 8K-64K"
static const size_t SOCKET_BUFFER_SIZE{0x10000};

// hard-coded value from libevent in evhttp_bind_socket_with_handle()
static const int SOCKET_BACKLOG{128};
// shortest valid request line, used by libevent in evhttp_parse_request_line()
static const size_t MIN_REQUEST_LINE_LENGTH{strlen("GET / HTTP/1.0")};
// maximum size of http request (request line + headers)
// see https://github.com/bitcoin/bitcoin/issues/6425
static const size_t MAX_HEADERS_SIZE{8192};

// Field names are case-insensitive https://httpwg.org/specs/rfc9110.html#rfc.section.5.1
using Headers = std::map<std::string, std::string, CaseInsensitiveComparator>;

struct HTTPRequest_mz
{
    std::string method;
    std::string target;
    std::string version;
    Headers headers;
    std::string body;

    std::unique_ptr<Sock> sock_client;
};

bool ParseRequest(HTTPRequest_mz* req) {
    size_t max_data{MAX_HEADERS_SIZE};
    // Request Line aka Control Data https://httpwg.org/specs/rfc9110.html#rfc.section.6.2
    // Three words separated by spaces, terminated by \n or \r\n
    std::string request_line = req->sock_client->RecvUntilTerminator('\n', MAX_WAIT_FOR_IO, g_interrupt_http, max_data);
    request_line = TrimString(request_line); // delete trailing \r if present
    if (request_line.length() < MIN_REQUEST_LINE_LENGTH) return false;
    const std::vector<std::string> parts{SplitString(request_line, ' ')};
    if (parts.size() != 3) return false;
    req->method = parts[0];
    req->target = parts[1];
    req->version = parts[2];

    max_data -= request_line.length();

    // Headers https://httpwg.org/specs/rfc9110.html#rfc.section.6.3
    // A sequence of Field Lines https://httpwg.org/specs/rfc9110.html#rfc.section.5.2
    do {
        std::string line = req->sock_client->RecvUntilTerminator('\n', MAX_WAIT_FOR_IO, g_interrupt_http, max_data);
        line = TrimString(line); // delete trailing \r if present
        // An empty line indicates end of the headers section https://www.rfc-editor.org/rfc/rfc2616#section-4
        if (line.length() == 0) break;

        // keys are not allowed to have delimiters like ":" but values are
        // https://httpwg.org/specs/rfc9110.html#rfc.section.5.6.2
        const size_t pos{line.find(':')};
        if (pos == std::string::npos) return false;
        std::string key = TrimString(line.substr(0, pos));
        std::string value = TrimString(line.substr(pos + 1));
        req->headers[key] = value;

        max_data -= request_line.length();
        if (max_data < 1) return false;
    } while (true);

    // Anything else if present is body content https://httpwg.org/specs/rfc9112.html#message.body
    const auto it = req->headers.find("Content-Length");
    // No Content-length or Transfer-Encoding header means no body, see libevent evhttp_get_body()
    // TODO: we must also implement Transfer-Encoding for chunk-reading
    if (it == req->headers.end()) return true;
    uint64_t body_length;
    if (!ParseUInt64(it->second, &body_length)) return false;
    if (body_length > MAX_SIZE) return false;

    char buf[SOCKET_BUFFER_SIZE];
    while (req->body.length() != body_length) {
        ssize_t nBytes = req->sock_client->Recv(buf, SOCKET_BUFFER_SIZE, /*flags=*/0);
        if (nBytes == 0) break;
        if (nBytes < 0) return false;
        req->body += buf;
    }

    return true;
}

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

        HTTPRequest_mz req;
        req.sock_client = std::move(sock_client);
        if (!ParseRequest(&req)) {
          // TODO: add client details
          LogPrintf("could not parse request from ...\n");
        } else {
            LogPrintf("HTTP req:\n");
            LogPrintf("  method: %s target: %s version: %s\n", req.method, req.target, req.version);
            for (auto it = req.headers.begin(); it != req.headers.end(); ++it) {
              LogPrintf("  headers: %s = %s\n", it->first, it->second);
            }
            LogPrintf("  body: %s\n", req.body);
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