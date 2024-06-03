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

#include <rpc/protocol.h>
// enum HTTPStatus
// {
//     HTTP_OK                    = 200,
//     HTTP_NO_CONTENT            = 204,
//     HTTP_BAD_REQUEST           = 400,
//     HTTP_UNAUTHORIZED          = 401,
//     HTTP_FORBIDDEN             = 403,
//     HTTP_NOT_FOUND             = 404,
//     HTTP_BAD_METHOD            = 405,
//     HTTP_INTERNAL_SERVER_ERROR = 500,
//     HTTP_SERVICE_UNAVAILABLE   = 503,
// };

const std::map<HTTPStatusCode, std::string> HTTPReason {
    {HTTP_OK,                    "OK"},
    {HTTP_NO_CONTENT,            "No Content"},
    {HTTP_BAD_REQUEST,           "Bad Request"},
    {HTTP_UNAUTHORIZED,          "Unauthorized"},
    {HTTP_FORBIDDEN,             "Forbidden"},
    {HTTP_NOT_FOUND,             "Not Found"},
    {HTTP_BAD_METHOD,            "Method Not Allowed"},
    {HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error"},
    {HTTP_SERVICE_UNAVAILABLE,   "Service Unavailable"},
};

// Forward declaration
class HTTPRequest_mz;

class HTTPHeaders
{
public:
    std::optional<std::string> Find(const std::string key) const;
    void Write(const std::string key, const std::string value);
    bool ReadFromRequest(HTTPRequest_mz* req);
    std::string Stringify() const;

private:
    std::map<std::string, std::string, CaseInsensitiveComparator> map;
};

class HTTPResponse_mz
{
public:
    int version_major;
    int version_minor;
    int status;
    std::string reason;
    HTTPHeaders headers;
    std::string body;

    std::string Stringify() const;
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

    bool WriteReply(HTTPStatusCode status, const std::string& body = "");

private:
    HTTPResponse_mz res;
};

bool ParseRequest(HTTPRequest_mz* req);
bool InitHTTPServer_mz();
void StartHTTPServer_mz();
void StopHTTPServer_mz();
