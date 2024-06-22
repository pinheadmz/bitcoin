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
//! HTTP server thread
static std::thread g_thread_http;
static CThreadInterrupt g_interrupt_http;

//! Bound listening sockets
static std::vector<std::shared_ptr<Sock>> listeningSockets;

//! Connected clients with live HTTP connections
static std::vector<HTTPClient> connectedClients;


// TODO: could go in string.h?
struct LineReader
{
    std::vector<uint8_t>::iterator start;
    std::vector<uint8_t>::iterator it;
    std::vector<uint8_t>::iterator end;

    explicit LineReader(std::vector<uint8_t>& buffer)
        : start(buffer.begin()), it(buffer.begin()), end(buffer.end()) {}

    std::optional<std::string> ReadLine()
    {
        if (it == end) {
            return std::nullopt;
        }

        std::string line{};
        while (it != end) {
            char c = static_cast<char>(*it);
            line += c;
            ++it;
            if (c == '\n') break;
        }

        line = TrimString(line); // delete trailing \r and/or \n
        return line;
    }

    size_t Left()
    {
        return std::distance(it, end);
    }

    std::string ReadLength(size_t len)
    {
        if (Left() < len) throw std::out_of_range("Not enough data in buffer");
        std::string out(it, it + len);
        it += len;
        return out;
    }
};


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

bool HTTPHeaders::Read(LineReader& reader)
{
    // Headers https://httpwg.org/specs/rfc9110.html#rfc.section.6.3
    // A sequence of Field Lines https://httpwg.org/specs/rfc9110.html#rfc.section.5.2
    do {
        auto maybe_line = reader.ReadLine();
        if (!maybe_line) return false;
        std::string line = *maybe_line;

        // An empty line indicates end of the headers section https://www.rfc-editor.org/rfc/rfc2616#section-4
        if (line.length() == 0) break;

        // Header line must have at least one ":"
        // keys are not allowed to have delimiters like ":" but values are
        // https://httpwg.org/specs/rfc9110.html#rfc.section.5.6.2
        const size_t pos{line.find(':')};
        if (pos == std::string::npos) throw std::runtime_error("HTTP header missing colon (:)");

        // Whitespace is optional
        std::string key = TrimString(line.substr(0, pos));
        std::string value = TrimString(line.substr(pos + 1));
        Write(key, value);
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

bool HTTPRequest_mz::ReadControlData(LineReader& reader)
{
    auto maybe_line = reader.ReadLine();
    if (!maybe_line) return false;
    std::string request_line = *maybe_line;

    // Request Line aka Control Data https://httpwg.org/specs/rfc9110.html#rfc.section.6.2
    // Three words separated by spaces, terminated by \n or \r\n
    if (request_line.length() < MIN_REQUEST_LINE_LENGTH) throw std::runtime_error("HTTP request line too short");

    const std::vector<std::string> parts{SplitString(request_line, ' ')};
    if (parts.size() != 3) throw std::runtime_error("HTTP request line malformed");
    method = parts[0];
    target = parts[1];

    // Two decimal digits separated by a dot https://httpwg.org/specs/rfc9110.html#rfc.section.2.5
    if(std::sscanf(parts[2].c_str(), "HTTP/%d.%d", &version_major, &version_minor) != 2)  throw std::runtime_error("HTTP request version malformed");;

    return true;
}

bool HTTPRequest_mz::ReadHeaders(LineReader& reader)
{
    return headers.Read(reader);
}

bool HTTPRequest_mz::ReadBody(LineReader& reader)
{
    // https://httpwg.org/specs/rfc9112.html#message.body

    // No Content-length or Transfer-Encoding header means no body, see libevent evhttp_get_body()
    // TODO: we must also implement Transfer-Encoding for chunk-reading
    auto content_length_value{headers.Find("Content-Length")};
    if (!content_length_value) return true;

    uint64_t content_length;
    if (!ParseUInt64(content_length_value.value(), &content_length)) throw std::runtime_error("Cannot paarse Content-Length value");

    // Not enough data in buffer for expected body
    if (reader.Left() < content_length) return false;

    body = reader.ReadLength(content_length);

    return true;
}

void HTTPRequest_mz::WriteReply(HTTPStatusCode status, const std::string& body)
{
    HTTPResponse_mz res;

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

    // Add to outgoing queue
    client.responses.push_front(std::move(res));
}

std::string HTTPResponse_mz::Stringify() const
{
    return strprintf("HTTP/%d.%d %d %s\r\n%s%s", version_major, version_minor, status, reason, headers.Stringify(), body);
}

bool HTTPClient::ReadRequest()
{
    // Create a new request object and try to fill it with data from recvBuffer
    HTTPRequest_mz req(*this);
    LineReader reader(recvBuffer);

    if (!req.ReadControlData(reader)) return false;
    if (!req.ReadHeaders(reader)) return false;
    if (!req.ReadBody(reader)) return false;

    // Move the request into the queue
    requests.push_front(req);

    // Remove the bytes read out of the buffer
    // TODO: if one of the Read functions above fails, we
    //       may still need to clean up the buffer.
    //       OR the caller should know we have a full buffer
    //       but not valid request and drop the client?
    recvBuffer.erase(reader.start, reader.it);

    return true;
}

static bool BindListeningSocket() {
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

    std::shared_ptr<Sock> sock{CreateSock(AF_INET, SOCK_STREAM, IPPROTO_TCP)};
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

    listeningSockets.push_back(std::move(sock));
    return true;
}

bool InitHTTPServer_mz()
{
    // TODO: Will be a for loop to bind to mutiple -rpcbind values
    if (!BindListeningSocket()) {
        LogPrintf("Unable to bind any endpoint for RPC server\n");
        return false;
    }

    LogPrintf("Initialized HTTP_mz server\n");
    return true;
}

static Sock::EventsPerSock GenerateEventsPerSock()
{
    // Map of sockets and a field of flags (send, recv)
    // representing what we want to do with the socket
    Sock::EventsPerSock events_per_sock;

    // We want to receive anything available on all listening sockets
    for (const auto& listenSock : listeningSockets) {
        events_per_sock.emplace(listenSock, Sock::Events{Sock::RECV});
    }

    // We want to either read requests or send replies to connected sockets
    // TODO: don't set SEND unless we have a response actually ready
    //       or if theres leftover bytes in client.sendBuffer
    //       maybe don't set RECV if we are pausing this socket due to flooding (max requests in queue?)
    for (const HTTPClient& connectedClient : connectedClients) {
        events_per_sock.emplace(connectedClient.sock, Sock::Events{Sock::SEND | Sock::RECV});
    }

    return events_per_sock;
}

static void HandleConnections()
{
    Sock::EventsPerSock events_per_sock{GenerateEventsPerSock()};
    // WaitMany() mine as well be a static function, the context
    // of the first Sock in the vector is not relevant.
    if (events_per_sock.empty() || !events_per_sock.begin()->first->WaitMany(SELECT_TIMEOUT, events_per_sock)) {
        // Nothing ready, wait a bit then proceed
        g_interrupt_http.sleep_for(SELECT_TIMEOUT);
    }

    // Iterate through connectedClients and read or write depending on what is ready
    for (auto& client : connectedClients) {
        if (client.disconnect) continue;

        // First find the socket in events_per_sock corresponding to this client
        const auto it = events_per_sock.find(client.sock);
        if (it == events_per_sock.end()) continue;

        // Socket is ready to send
        if (it->second.occurred & Sock::SEND) {
            // Prepare HTTP responses for the wire
            while (client.responses.size() > 0) {
                const HTTPResponse_mz res = client.responses.back();
                client.responses.pop_back();
                // Format response packet
                std::string reply{res.Stringify()};
                // Load into send buffer
                client.sendBuffer.insert(client.sendBuffer.end(), reply.begin(), reply.end());
                // TODO: handle keep-alive header
                client.disconnect_after_send = true;
            }

            // Send everything we can
            size_t res_length{client.sendBuffer.size()};
            ssize_t bytes_sent = client.sock->Send(client.sendBuffer.data(), res_length, 0);

            // Error sending through socket
            if (bytes_sent < 0) {
                LogPrintf("Failed send to client (disconnecting): %s\n", NetworkErrorString(WSAGetLastError()));
                client.disconnect = true;
                continue;
            }

            // Remove sent bytes from the buffer
            client.sendBuffer.erase(client.sendBuffer.begin(), client.sendBuffer.begin() + bytes_sent);
        }

        // Do not attempt to receive bytes if the send buffer is not drained
        if ((it->second.occurred & Sock::RECV && client.sendBuffer.size() == 0)
            || it->second.occurred & Sock::ERR) {

            // Extend the receive buffer memory allocation to prepare for receiving
            // TODO: ensure that we don't keep receiving bytes waiting for a \n for the parser
            // "typical socket buffer is 8K-64K"
            size_t current_size = client.recvBuffer.size();
            size_t additional_size{0x10000};
            client.recvBuffer.resize(current_size + additional_size);

            // Read data from socket into the receive buffer
            ssize_t bytes_received = client.sock->Recv(client.recvBuffer.data() + current_size, additional_size, MSG_DONTWAIT);

            // Socket closed gracefully
            if (bytes_received == 0) {
                client.disconnect = true;
                continue;
            }

            // Socket closed unexpectedly
            if (bytes_received < 0) {
                LogPrintf("Failed recv from client: %s\n", NetworkErrorString(WSAGetLastError()));
                client.disconnect = true;
                continue;
            }

            // Trim unused buffer memory
            client.recvBuffer.resize(current_size + bytes_received);

            // Try reading HTTP requests from the buffer
            while (client.recvBuffer.size() > 0) {
                try {
                    // Stop reading if we need more data from the client
                    if (!client.ReadRequest()) break;
                } catch (const std::runtime_error& e) {
                    LogPrintf("ReadRequest() error: %s\n", e.what());
                    // TODO: send 400 bad request before disconnecting
                    client.disconnect = true;
                    break;
                }
            }
        }
    }
}

static void AcceptConnections()
{
    for (auto& listeningSocket : listeningSockets) {
        // Copied from Session::Accept() in i2p.cpp
        // and CConnman::AcceptConnection() in net.cpp
        struct sockaddr_storage sockaddr_client;
        socklen_t len_client = sizeof(sockaddr);
        std::shared_ptr<Sock> sock_client{listeningSocket->Accept((struct sockaddr*)&sockaddr_client, &len_client)};
        if (sock_client) {
            connectedClients.push_back(HTTPClient(sock_client));
        }
    }
}

static void DropConnections()
{
   for (auto it = connectedClients.begin(); it != connectedClients.end();) {
        if (it->disconnect || (it->disconnect_after_send && it->sendBuffer.size() == 0)) {
            LogPrintf("removing client\n");
            it = connectedClients.erase(it);
        } else {
            ++it;
        }
    }
}

static void ThreadHTTP_mz()
{
    util::ThreadRename("http_mz");
    LogPrintf("Entering http_mz loop\n");

    while (!g_interrupt_http) {
        HandleConnections();
        AcceptConnections();
        DropConnections();

        // TODO: temp for testing
        for (auto& client : connectedClients) {
            while (client.requests.size() > 0) {
                LogPrintf("Sending test response\n");
                auto req = client.requests.back();
                client.requests.pop_back();
                req.WriteReply(HTTP_OK, "Test response!\n");
            }
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