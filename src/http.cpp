// work in prorgress: minimal http server for bitcoind

#include <http.h>

#include <chrono>
#include <cstdio>
#include <thread>

#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <util/string.h>
#include <time.h>
#include <tinyformat.h>
#include <util/threadnames.h>
#include <util/threadinterrupt.h>

using util::SplitString;
using util::TrimString;

static std::unique_ptr<Sock> sock;
static std::thread g_thread_http;
static CThreadInterrupt g_interrupt_http;

std::optional<std::string> HTTPHeaders::Find(const std::string key) const
{
    const auto it = map.find(key);
    if (it == map.end()) return std::nullopt;
    return it->second;
}

void HTTPHeaders::Write(const std::string key, const std::string value)
{
    // If present, append value to list
    const auto existing_value = Find(key);
    if (existing_value) {
        map[key] = existing_value.value() + ", " + value;
    } else {
        map[key] = value;
    }
}

bool HTTPHeaders::ReadFromRequest(HTTPRequest_mz* req)
{
    // Headers https://httpwg.org/specs/rfc9110.html#rfc.section.6.3
    // A sequence of Field Lines https://httpwg.org/specs/rfc9110.html#rfc.section.5.2
    do {
        size_t max_data{MAX_HEADERS_SIZE - req->bytes_read};
        if (max_data < 1) return false;

        try {
            std::string line = req->sock_client->RecvUntilTerminator('\n', MAX_WAIT_FOR_IO, g_interrupt_http, max_data);
            line = TrimString(line); // delete trailing \r if present
            // An empty line indicates end of the headers section https://www.rfc-editor.org/rfc/rfc2616#section-4
            if (line.length() == 0) break;

            // Header line must have at least one ":"
            // keys are not allowed to have delimiters like ":" but values are
            // https://httpwg.org/specs/rfc9110.html#rfc.section.5.6.2
            const size_t pos{line.find(':')};
            if (pos == std::string::npos) return false;

            // Whitespace is optional
            std::string key = TrimString(line.substr(0, pos));
            std::string value = TrimString(line.substr(pos + 1));
            Write(key, value);

            // Does not include terminator char(s)
            req->bytes_read += line.length();
        } catch (...) {
            return false;
        }
    } while (true);

    return true;
}

std::string HTTPHeaders::Stringify() const
{
    std::string out;
    for (auto it = map.begin(); it != map.end(); ++it) {
        out += it->first + ": " + it->second + "\r\n";
    }

    // Headers are terminated by an empty line
    out += "\r\n";

    return out;
}

bool HTTPRequest_mz::ReadControlData()
{
    // It's the first thing we read so this is overkill
    size_t max_data{MAX_HEADERS_SIZE - bytes_read};
    if (max_data < 1) return false;

    // Request Line aka Control Data https://httpwg.org/specs/rfc9110.html#rfc.section.6.2
    // Three words separated by spaces, terminated by \n or \r\n
    std::string request_line = sock_client->RecvUntilTerminator('\n', MAX_WAIT_FOR_IO, g_interrupt_http, max_data);
    request_line = TrimString(request_line); // delete trailing \r if present
    if (request_line.length() < MIN_REQUEST_LINE_LENGTH) return false;

    const std::vector<std::string> parts{SplitString(request_line, ' ')};
    if (parts.size() != 3) return false;
    method = parts[0];
    target = parts[1];

    // Two decimal digits separated by a dot https://httpwg.org/specs/rfc9110.html#rfc.section.2.5
    if(std::sscanf(parts[2].c_str(), "HTTP/%d.%d", &version_major, &version_minor) != 2) return false;

    // Does not include terminator char(s)
    bytes_read += request_line.length();

    return true;
}

bool HTTPRequest_mz::ReadHeaders()
{
    return headers.ReadFromRequest(this);
}

bool HTTPRequest_mz::ReadBody()
{
    // https://httpwg.org/specs/rfc9112.html#message.body

    // No Content-length or Transfer-Encoding header means no body, see libevent evhttp_get_body()
    // TODO: we must also implement Transfer-Encoding for chunk-reading
    auto content_length_value{headers.Find("Content-Length")};
    if (!content_length_value) return true;

    uint64_t content_length;
    if (!ParseUInt64(content_length_value.value(), &content_length)) return false;

    char buf[SOCKET_BUFFER_SIZE];

    // Read expected number of bytes from socket into request body
    while (body.length() < content_length && bytes_read < MAX_SIZE) {
        ssize_t nBytes = sock_client->Recv(buf, SOCKET_BUFFER_SIZE, /*flags=*/0);
        // Nothing left to read from socket
        if (nBytes == 0) {
          // We're done
          if (body.length() == content_length) break;
          // ...or Content-Length value was a lie?
          return false;
        }
        // I/O error
        if (nBytes < 0) return false;

        // Add chunk to request body
        body += buf;
        bytes_read += nBytes;
    }

    // We could still return false here if we hit MAX_SIZE before finishing the body
    return body.length() == content_length;
}

bool HTTPRequest_mz::WriteReply(HTTPStatusCode status, const std::string& body)
{
    // Response version matches request version
    res.version_major = version_major;
    res.version_minor = version_minor;

    // Add response code and look up reason string
    res.status = status;
    res.reason = HTTPReason.find(status)->second;

    // Add headers
    // see libevent evhttp_make_header_response()
    if (version_major == 1) {
        // TODO: HTTP/1.0 keep-alive

        if (version_minor >= 1) {
            const int64_t now_seconds{TicksSinceEpoch<std::chrono::seconds>(SystemClock::now())};
            res.headers.Write("Date", FormatRFC7231DateTime(now_seconds));

            if (!body.empty()) {
                res.headers.Write("Content-Length", std::to_string(body.length()));
            }
        }
    }

    if (!body.empty() && !res.headers.Find("Content-Type")) {
        // Default type from libevent evhttp_new_object()
        res.headers.Write("Content-Type", "text/html; charset=ISO-8859-1");
    }

    // TODO Connection: close

    // Add body
    res.body = body;

    // Wrap it up and ship it
    std::string reply{res.Stringify()};
    int bytes_sent = sock_client->Send(reply.c_str(), reply.length(), 0);
    // TODO check for errors
    return bytes_sent > 0;
}

std::string HTTPResponse_mz::Stringify() const
{
    return strprintf("HTTP/%d.%d %d %s\r\n%s%s", version_major, version_minor, status, reason, headers.Stringify(), body);
}

bool ParseRequest(HTTPRequest_mz* req)
{
    if (!req->ReadControlData()) {
        LogPrintf("Could not read control line\n");
    }

    if (!req->ReadHeaders()) {
        LogPrintf("Could not read headers\n");
    }

    if (!req->ReadBody()) {
        LogPrintf("Could not read body\n");
    }
    return true;
}

bool InitHTTPServer_mz()
{
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
            req.WriteReply(HTTP_OK, "pretty cool\n");
        }
    }

    LogPrintf("Exited http_mz loop\n");
}

void StartHTTPServer_mz()
{
    LogPrintf("Starting HTTP_mz server\n");
    g_thread_http = std::thread(ThreadHTTP_mz);
}

void StopHTTPServer_mz()
{
    g_interrupt_http();
    LogPrintf("Waiting for HTTP_mz thread to exit\n");
    if (g_thread_http.joinable()) g_thread_http.join();
    LogPrintf("Stopped HTTP_mz server\n");
}