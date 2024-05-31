// work in prorgress: minimal http server for bitcoind

#include <map>
#include <util/sock.h>
#include <util/string.h>

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

// Forward declaration
class HTTPRequest_mz;

class HTTPHeaders
{
public:
    std::optional<std::string> Find(const std::string key) const;
    void Write(const std::string key, const std::string value);
    bool ReadFromRequest(HTTPRequest_mz* req);
    std::string Serialize();

private:
    std::map<std::string, std::string, CaseInsensitiveComparator> map;
};

class HTTPRequest_mz
{
public:
    std::unique_ptr<Sock> sock_client;
    size_t bytes_read{0};

    std::string method;
    std::string target;
    int version_major;
    int version_minor;
    HTTPHeaders headers;
    std::string body;

    bool ReadControlData();
    bool ReadHeaders();
    bool ReadBody();
};

bool ParseRequest(HTTPRequest_mz* req);
bool InitHTTPServer_mz();
void StartHTTPServer_mz();
void StopHTTPServer_mz();
