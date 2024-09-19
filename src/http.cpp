// work in prorgress: minimal http server for bitcoind

#include <http.h>

#include <chrono>
#include <cstdio>
#include <thread>

#include <chainparamsbase.h>
#include <common/args.h>
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
static std::vector<std::shared_ptr<HTTPClient>> connectedClients;

//! Callback function to execute HTTP requests
static void* g_http_callback_arg;
static std::function<void(std::shared_ptr<HTTPRequest_mz>, void*)> g_http_callback;


// TODO: could go in string.h?
struct LineReader
{
    const std::vector<uint8_t>::iterator start;
    std::vector<uint8_t>::iterator it;
    const std::vector<uint8_t>::iterator end;
    const size_t max_read;

    explicit LineReader(std::vector<uint8_t>& buffer, size_t max_read)
        : start(buffer.begin()), it(buffer.begin()), end(buffer.end()), max_read(max_read) {}

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
            if ((size_t)std::distance(start, it) >= max_read) throw std::runtime_error("max_read exceeded by LineReader");
        }

        line = TrimString(line); // delete trailing \r and/or \n
        return line;
    }

    size_t Left()
    {
        return std::distance(it, end);
    }

    // Ignores max_read but won't overflow
    std::string ReadLength(size_t len)
    {
        if (Left() < len) throw std::runtime_error("Not enough data in buffer");
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

void HTTPHeaders::Remove(const std::string key)
{
    map.erase(key);
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

void HTTPRequest_mz::WriteReply(HTTPStatusCode status, std::span<const std::byte> reply_body)
{
    HTTPResponse_mz res(&response_headers);

    // Response version matches request version
    res.version_major = version_major;
    res.version_minor = version_minor;

    // Add response code and look up reason string
    res.status = status;
    res.reason = HTTPReason.find(status)->second;

    // see libevent evhttp_response_needs_body()
    bool needs_body{status != HTTP_NO_CONTENT && (status < 100 || status >= 200)};

    // see libevent evhttp_make_header_response()
    if (version_major == 1) {

        if (version_minor == 0) {
            auto connection_header{headers.Find("Connection")};
            if (connection_header && connection_header.value() == "keep-alive") {
                response_headers.Write("Connection", "keep-alive");
                res.keep_alive = true;
            }
        }

        if (version_minor >= 1) {
            const int64_t now_seconds{TicksSinceEpoch<std::chrono::seconds>(SystemClock::now())};
            response_headers.Write("Date", FormatRFC7231DateTime(now_seconds));

            if (needs_body) {
                response_headers.Write("Content-Length", std::to_string(reply_body.size()));
            }

            // Default for HTTP 1.1
            res.keep_alive = true;
        }
    }

    if (needs_body && !response_headers.Find("Content-Type")) {
        // Default type from libevent evhttp_new_object()
        response_headers.Write("Content-Type", "text/html; charset=ISO-8859-1");
    }

    auto connection_header{headers.Find("Connection")};
    if (connection_header && connection_header.value() == "close") {
        response_headers.Remove("Connection");
        response_headers.Write("Connection", "close");
        res.keep_alive = false;
    }

    // We've been using std::span up until now but it is finally time to copy
    // data. The original data will go out of scope when WriteReply() returns.
    // This is analogous to the memcpy() in libevent's evbuffer_add()
    res.body.insert(res.body.end(), reply_body.begin(), reply_body.end());

    // Add to outgoing queue
    client->responses.push_front(std::move(res));

    LogPrintf("[client: %s] HTTP Response added to client queue with status code %d\n", client->origin, status);
}

std::string HTTPResponse_mz::StringifyHeaders() const
{
    return strprintf("HTTP/%d.%d %d %s\r\n%s", version_major, version_minor, status, reason, headers->Stringify());
}

bool HTTPClient::ReadRequest(std::shared_ptr<HTTPRequest_mz> req)
{
    LineReader reader(recvBuffer, MAX_HEADERS_SIZE);

    if (!req->ReadControlData(reader)) return false;
    if (!req->ReadHeaders(reader)) return false;
    if (!req->ReadBody(reader)) return false;

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

static bool BindListeningSocket(const CService& addrBind)
{
    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        LogPrintf("Bind address family for %s not supported\n"), addrBind.ToStringAddrPort();
        return false;
    }

    std::shared_ptr<Sock> sock{CreateSock(addrBind.GetSAFamily(), SOCK_STREAM, IPPROTO_TCP)};
    if (!sock) {
        LogPrintf("Could not create sock for incoming http connections\n");
        return false;
    }

    // Allow binding if the port is still in TIME_WAIT state after the program was closed and restarted.
    int nOne = 1;
    if (sock->SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&nOne, sizeof(int)) == SOCKET_ERROR) {
        LogPrintf("Could not set SO_REUSEADDR on HTTP socket: %s, continuing anyway"), NetworkErrorString(WSAGetLastError());
    }

    // Detect dead connections with periodic pings.
    if (sock->SetSockOpt(SOL_SOCKET, SO_KEEPALIVE, (sockopt_arg_type)&nOne, sizeof(int)) == SOCKET_ERROR) {
        LogPrintf("Could not set SO_KEEPALIVE on HTTP socket: %s, continuing anyway"), NetworkErrorString(WSAGetLastError());
    }

    // Set the no-delay option (disable Nagle's algorithm) on the TCP socket.
    if (sock->SetSockOpt(IPPROTO_TCP, TCP_NODELAY, (sockopt_arg_type)&nOne, sizeof(int)) == SOCKET_ERROR) {
        LogDebug(BCLog::NET, "Unable to set TCP_NODELAY on a newly created socket: %s, continuing anyway\n", NetworkErrorString(WSAGetLastError()));
    }

    // TODO: see libevent evconnlistener_new_bind()
    //


    if (sock->Bind(reinterpret_cast<struct sockaddr*>(&sockaddr), len) == SOCKET_ERROR) {
        LogPrintf("Could not bind to socket for http: %s\n", NetworkErrorString(WSAGetLastError()));
        return false;
    }

    if (sock->Listen(/*backlog=*/SOCKET_BACKLOG) == SOCKET_ERROR) {
        LogPrintf("Could not listen to socket for http: %s\n", NetworkErrorString(WSAGetLastError()));
        return false;
    }

    listeningSockets.push_back(sock);
    return true;
}

/** Bind HTTP server to specified addresses */
static bool HTTPBindAddresses()
{
    uint16_t http_port{static_cast<uint16_t>(gArgs.GetIntArg("-rpcport", BaseParams().RPCPort()))};
    std::vector<std::pair<std::string, uint16_t>> endpoints;

    // Determine what addresses to bind to
    if (!(gArgs.IsArgSet("-rpcallowip") && gArgs.IsArgSet("-rpcbind"))) { // Default to loopback if not allowing external IPs
        endpoints.emplace_back("::1", http_port);
        endpoints.emplace_back("127.0.0.1", http_port);
        if (gArgs.IsArgSet("-rpcallowip")) {
            LogPrintf("WARNING: option -rpcallowip was specified without -rpcbind; this doesn't usually make sense\n");
        }
        if (gArgs.IsArgSet("-rpcbind")) {
            LogPrintf("WARNING: option -rpcbind was ignored because -rpcallowip was not specified, refusing to allow everyone to connect\n");
        }
    } else if (gArgs.IsArgSet("-rpcbind")) { // Specific bind address
        for (const std::string& strRPCBind : gArgs.GetArgs("-rpcbind")) {
            uint16_t port{http_port};
            std::string host;
            SplitHostPort(strRPCBind, port, host);
            endpoints.emplace_back(host, port);
        }
    }

    // Bind addresses
    for (std::vector<std::pair<std::string, uint16_t> >::iterator i = endpoints.begin(); i != endpoints.end(); ++i) {
        LogPrintf("Binding RPC on address %s port %i\n", i->first, i->second);
        const std::optional<CService> bind_addr{Lookup(i->first, i->second, /*fAllowLookup=*/false)};
        if (i->first.empty() || (bind_addr.has_value() && bind_addr->IsBindAny())) {
            LogPrintf("WARNING: the RPC server is not safe to expose to untrusted networks such as the public internet\n");
        }

        if (!BindListeningSocket(bind_addr.value())) {
            LogPrintf("Binding RPC on address %s port %i failed.\n", i->first, i->second);
        }
    }
    return !listeningSockets.empty();
}

void SetHTTPCallback(std::function<void(std::shared_ptr<HTTPRequest_mz>, void*)> http_callback)
{
    g_http_callback = http_callback;
}

bool InitHTTPServer_mz(void* http_callback_arg)
{
    if (!HTTPBindAddresses()) {
        LogPrintf("Unable to bind any endpoint for RPC server\n");
        return false;
    }

    g_http_callback_arg = http_callback_arg;

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
    // TODO: maybe don't set RECV if we are pausing this socket due to flooding (max requests in queue?)
    for (auto& connectedClient : connectedClients) {
        Sock::Events events{Sock::RECV};
        if (connectedClient->sendBuffer.size() > 0 || connectedClient->responses.size() > 0) {
            events.requested |= Sock::SEND;
        }
        events_per_sock.emplace(connectedClient->sock, events);
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
        if (client->disconnect) continue;

        // First find the socket in events_per_sock corresponding to this client
        const auto it = events_per_sock.find(client->sock);
        if (it == events_per_sock.end()) continue;

        // Socket is ready to send
        if (it->second.occurred & Sock::SEND) {
            LogPrintf("[client: %s] ready to send...\n", client->origin);
            // Prepare HTTP responses for the wire
            while (client->responses.size() > 0) {
                const HTTPResponse_mz res = client->responses.back();
                client->responses.pop_back();
                // Format response packet headers
                std::string reply_headers{res.StringifyHeaders()};
                // Load headers into send buffer
                client->sendBuffer.insert(
                    client->sendBuffer.end(),
                    reinterpret_cast<const std::byte*>(reply_headers.data()),
                    reinterpret_cast<const std::byte*>(reply_headers.data() + reply_headers.size()));
                // Load response body into send buffer
                client->sendBuffer.insert(client->sendBuffer.end(), res.body.begin(), res.body.end());
                if (!res.keep_alive) {
                    client->disconnect_after_send = true;
                }
            }

            // Send everything we can
            size_t res_length{client->sendBuffer.size()};
            if (res_length > 0) {
                ssize_t bytes_sent = client->sock->Send(client->sendBuffer.data(), res_length, 0);

                // Error sending through socket
                if (bytes_sent < 0) {
                    LogPrintf("  Failed send to client (disconnecting): %s\n", NetworkErrorString(WSAGetLastError()));
                    client->disconnect = true;
                    continue;
                }

                LogPrintf("  Sent %d bytes to client\n", bytes_sent);
                // Remove sent bytes from the buffer
                client->sendBuffer.erase(client->sendBuffer.begin(), client->sendBuffer.begin() + bytes_sent);
            }
        }

        // Do not attempt to receive bytes if the send buffer is not drained
        if ((it->second.occurred & Sock::RECV && client->sendBuffer.size() == 0)
            || it->second.occurred & Sock::ERR) {

            LogPrintf("[client: %s] ready to recv\n", client->origin);
            // Extend the receive buffer memory allocation to prepare for receiving
            // TODO: ensure that we don't keep receiving bytes waiting for a \n for the parser
            // "typical socket buffer is 8K-64K"
            size_t current_size = client->recvBuffer.size();
            size_t additional_size{0x10000};
            client->recvBuffer.resize(current_size + additional_size);

            // Read data from socket into the receive buffer
            ssize_t bytes_received = client->sock->Recv(client->recvBuffer.data() + current_size, additional_size, MSG_DONTWAIT);

            if (bytes_received == 0) {
                LogPrintf("  Socket closed gracefully\n");
                client->disconnect = true;
                continue;
            }

            // Socket closed unexpectedly
            if (bytes_received < 0) {
                LogPrintf("  Failed recv from client: %s\n", NetworkErrorString(WSAGetLastError()));
                client->disconnect = true;
                continue;
            }

            LogPrintf("  Received %d bytes from client\n", bytes_received);

            // Trim unused buffer memory
            client->recvBuffer.resize(current_size + bytes_received);

            // Try reading (potentially multiple) HTTP requests from the buffer
            while (client->recvBuffer.size() > 0) {
                // Create a new request object and try to fill it with data from recvBuffer
                auto req = std::make_shared<HTTPRequest_mz>(client);
                try {
                    // Stop reading if we need more data from the client to complete the request
                    if (!client->ReadRequest(req)) break;
                } catch (const std::runtime_error& e) {
                    LogPrintf("  ReadRequest() error: %s\n", e.what());
                    
                    // We failed to read a complete request from the buffer
                    // Move the incomplete request object into the client's request queue
                    // anyway because the error reponse we are about to send refers to it
                    client->requests.push_front(req);
                    req->WriteReply(HTTP_BAD_REQUEST, {});

                    client->disconnect_after_send = true;
                    break;
                }

                LogPrintf("  Read HTTP request\n");;
                // We read a complete request from the buffer
                // Move the request into the client's request queue
                client->requests.push_front(req);

                // Process request
                g_http_callback(req, g_http_callback_arg);
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
        socklen_t len_client = sizeof(sockaddr_storage);
        std::shared_ptr<Sock> sock_client{listeningSocket->Accept((struct sockaddr*)&sockaddr_client, &len_client)};
        if (sock_client) {
            auto client{std::make_shared<HTTPClient>(sock_client, sockaddr_client)};
            connectedClients.push_back(std::move(client));
        }
    }
}

static void DropConnections()
{
   for (auto it = connectedClients.begin(); it != connectedClients.end();) {
        if ((*it)->disconnect || ((*it)->disconnect_after_send && (*it)->sendBuffer.size() == 0 && (*it)->responses.size() == 0)) {
            LogPrintf("[client: %s] Removing client\n", (*it)->origin);
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
    }

    LogPrintf("Clearing listening sockets...\n");
    listeningSockets.clear();

    LogPrintf("Flushing all connected clients...\n");
    for (auto& client : connectedClients) {
        client->disconnect_after_send = true;
    }
    while (connectedClients.size() > 0) {
        HandleConnections();
        DropConnections();
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