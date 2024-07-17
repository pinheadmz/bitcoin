// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <config/bitcoin-config.h> // IWYU pragma: keep

#include <httpserver.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <compat/compat.h>
#include <logging.h>
#include <netbase.h>
#include <node/interface_ui.h>
#include <rpc/protocol.h> // For HTTP status codes
#include <sync.h>
#include <util/check.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/threadnames.h>
#include <util/translation.h>

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>

#include <sys/types.h>
#include <sys/stat.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>
#include <event2/thread.h>
#include <event2/util.h>

#include <support/events.h>

/** Maximum size of http request (request line + headers) */
// static const size_t MAX_HEADERS_SIZE = 8192;

/** HTTP request work item */
class HTTPWorkItem final : public HTTPClosure
{
public:
    HTTPWorkItem(std::unique_ptr<HTTPRequest> _req, const std::string &_path, const HTTPRequestHandler& _func):
        req(std::move(_req)), path(_path), func(_func)
    {
    }
    void operator()() override
    {
        func(req.get(), path);
    }

    std::unique_ptr<HTTPRequest> req;

private:
    std::string path;
    HTTPRequestHandler func;
};

/** Simple work queue for distributing work over multiple threads.
 * Work items are simply callable objects.
 */
template <typename WorkItem>
class WorkQueue
{
private:
    Mutex cs;
    std::condition_variable cond GUARDED_BY(cs);
    std::deque<std::unique_ptr<WorkItem>> queue GUARDED_BY(cs);
    bool running GUARDED_BY(cs){true};
    const size_t maxDepth;

public:
    explicit WorkQueue(size_t _maxDepth) : maxDepth(_maxDepth)
    {
    }
    /** Precondition: worker threads have all stopped (they have been joined).
     */
    ~WorkQueue() = default;
    /** Enqueue a work item */
    bool Enqueue(WorkItem* item) EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        LOCK(cs);
        if (!running || queue.size() >= maxDepth) {
            return false;
        }
        queue.emplace_back(std::unique_ptr<WorkItem>(item));
        cond.notify_one();
        return true;
    }
    /** Thread function */
    void Run() EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        while (true) {
            std::unique_ptr<WorkItem> i;
            {
                WAIT_LOCK(cs, lock);
                while (running && queue.empty())
                    cond.wait(lock);
                if (!running && queue.empty())
                    break;
                i = std::move(queue.front());
                queue.pop_front();
            }
            (*i)();
        }
    }
    /** Interrupt and exit loops */
    void Interrupt() EXCLUSIVE_LOCKS_REQUIRED(!cs)
    {
        LOCK(cs);
        running = false;
        cond.notify_all();
    }
};

struct HTTPPathHandler
{
    HTTPPathHandler(std::string _prefix, bool _exactMatch, HTTPRequestHandler _handler):
        prefix(_prefix), exactMatch(_exactMatch), handler(_handler)
    {
    }
    std::string prefix;
    bool exactMatch;
    HTTPRequestHandler handler;
};

/** HTTP module state */

//! libevent event loop
static struct event_base* eventBase = nullptr;
//! HTTP server
static struct evhttp* eventHTTP = nullptr;
//! List of subnets to allow RPC connections from
static std::vector<CSubNet> rpc_allow_subnets;
//! Work queue for handling longer requests off the event loop thread
static std::unique_ptr<WorkQueue<HTTPClosure>> g_work_queue{nullptr};
//! Handlers for (sub)paths
static GlobalMutex g_httppathhandlers_mutex;
static std::vector<HTTPPathHandler> pathHandlers GUARDED_BY(g_httppathhandlers_mutex);
//! Bound listening sockets
static std::vector<evhttp_bound_socket *> boundSockets;

/**
 * @brief Helps keep track of open `evhttp_connection`s with active `evhttp_requests`
 *
 */
class HTTPRequestTracker
{
private:
    mutable Mutex m_mutex;
    mutable std::condition_variable m_cv;
    //! For each connection, keep a counter of how many requests are open
    std::unordered_map<const evhttp_connection*, size_t> m_tracker GUARDED_BY(m_mutex);

    void RemoveConnectionInternal(const decltype(m_tracker)::iterator it) EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        m_tracker.erase(it);
        if (m_tracker.empty()) m_cv.notify_all();
    }
public:
    //! Increase request counter for the associated connection by 1
    void AddRequest(evhttp_request* req) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const evhttp_connection* conn{Assert(evhttp_request_get_connection(Assert(req)))};
        WITH_LOCK(m_mutex, ++m_tracker[conn]);
    }
    //! Decrease request counter for the associated connection by 1, remove connection if counter is 0
    void RemoveRequest(evhttp_request* req) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        const evhttp_connection* conn{Assert(evhttp_request_get_connection(Assert(req)))};
        LOCK(m_mutex);
        auto it{m_tracker.find(conn)};
        if (it != m_tracker.end() && it->second > 0) {
            if (--(it->second) == 0) RemoveConnectionInternal(it);
        }
    }
    //! Remove a connection entirely
    void RemoveConnection(const evhttp_connection* conn) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        auto it{m_tracker.find(Assert(conn))};
        if (it != m_tracker.end()) RemoveConnectionInternal(it);
    }
    size_t CountActiveConnections() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        return WITH_LOCK(m_mutex, return m_tracker.size());
    }
    //! Wait until there are no more connections with active requests in the tracker
    void WaitUntilEmpty() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        WAIT_LOCK(m_mutex, lock);
        m_cv.wait(lock, [this]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_tracker.empty(); });
    }
};
//! Track active requests
static HTTPRequestTracker g_requests;

/** Check if a network address is allowed to access the HTTP server */
static bool ClientAllowed(const CNetAddr& netaddr)
{
    if (!netaddr.IsValid())
        return false;
    for(const CSubNet& subnet : rpc_allow_subnets)
        if (subnet.Match(netaddr))
            return true;
    return false;
}

/** Initialize ACL list for HTTP server */
static bool InitHTTPAllowList()
{
    rpc_allow_subnets.clear();
    rpc_allow_subnets.emplace_back(LookupHost("127.0.0.1", false).value(), 8);  // always allow IPv4 local subnet
    rpc_allow_subnets.emplace_back(LookupHost("::1", false).value());  // always allow IPv6 localhost
    for (const std::string& strAllow : gArgs.GetArgs("-rpcallowip")) {
        const CSubNet subnet{LookupSubNet(strAllow)};
        if (!subnet.IsValid()) {
            uiInterface.ThreadSafeMessageBox(
                strprintf(Untranslated("Invalid -rpcallowip subnet specification: %s. Valid are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24)."), strAllow),
                "", CClientUIInterface::MSG_ERROR);
            return false;
        }
        rpc_allow_subnets.push_back(subnet);
    }
    std::string strAllowed;
    for (const CSubNet& subnet : rpc_allow_subnets)
        strAllowed += subnet.ToString() + " ";
    LogDebug(BCLog::HTTP, "Allowing HTTP connections from: %s\n", strAllowed);
    return true;
}

/** HTTP request method as string - use for logging only */
std::string RequestMethodString(HTTPRequest::RequestMethod m)
{
    switch (m) {
    case HTTPRequest::GET:
        return "GET";
    case HTTPRequest::POST:
        return "POST";
    case HTTPRequest::HEAD:
        return "HEAD";
    case HTTPRequest::PUT:
        return "PUT";
    case HTTPRequest::UNKNOWN:
        return "unknown";
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

/** HTTP request callback */
static void http_request_cb(HTTPRequest_mz* req, void* arg)
{
    auto hreq{std::make_unique<HTTPRequest>(req, *static_cast<const util::SignalInterrupt*>(arg))};

    // Early address-based allow check
    if (!ClientAllowed(hreq->GetPeer())) {
        LogDebug(BCLog::HTTP, "HTTP request from %s rejected: Client network is not allowed RPC access\n",
                 hreq->GetPeer().ToStringAddrPort());
        hreq->WriteReply(HTTP_FORBIDDEN);
        return;
    }

    // Early reject unknown HTTP methods
    if (hreq->GetRequestMethod() == HTTPRequest::UNKNOWN) {
        LogDebug(BCLog::HTTP, "HTTP request from %s rejected: Unknown HTTP request method\n",
                 hreq->GetPeer().ToStringAddrPort());
        hreq->WriteReply(HTTP_BAD_METHOD);
        return;
    }

    LogDebug(BCLog::HTTP, "Received a %s request for %s from %s\n",
             RequestMethodString(hreq->GetRequestMethod()), SanitizeString(hreq->GetURI(), SAFE_CHARS_URI).substr(0, 100), hreq->GetPeer().ToStringAddrPort());

    // Find registered handler for prefix
    std::string strURI = hreq->GetURI();
    std::string path;
    LOCK(g_httppathhandlers_mutex);
    std::vector<HTTPPathHandler>::const_iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::const_iterator iend = pathHandlers.end();
    for (; i != iend; ++i) {
        bool match = false;
        if (i->exactMatch)
            match = (strURI == i->prefix);
        else
            match = strURI.starts_with(i->prefix);
        if (match) {
            path = strURI.substr(i->prefix.size());
            break;
        }
    }

    // Dispatch to worker thread
    if (i != iend) {
        std::unique_ptr<HTTPWorkItem> item(new HTTPWorkItem(std::move(hreq), path, i->handler));
        assert(g_work_queue);
        if (g_work_queue->Enqueue(item.get())) {
            item.release(); /* if true, queue took ownership */
        } else {
            LogPrintf("WARNING: request rejected because http work queue depth exceeded, it can be increased with the -rpcworkqueue= setting\n");
            item->req->WriteReply(HTTP_SERVICE_UNAVAILABLE, "Work queue depth exceeded");
        }
    } else {
        hreq->WriteReply(HTTP_NOT_FOUND);
    }
}

/** Callback to reject HTTP requests after shutdown. */
static void http_reject_request_cb(struct evhttp_request* req, void*)
{
    LogDebug(BCLog::HTTP, "Rejecting request while shutting down\n");
    evhttp_send_error(req, HTTP_SERVUNAVAIL, nullptr);
}

/** Event dispatcher thread */
static void ThreadHTTP(struct event_base* base)
{
    util::ThreadRename("http");
    LogDebug(BCLog::HTTP, "Entering http event loop\n");
    event_base_dispatch(base);
    // Event loop will be interrupted by InterruptHTTPServer()
    LogDebug(BCLog::HTTP, "Exited http event loop\n");
}

/** Simple wrapper to set thread name and run work queue */
static void HTTPWorkQueueRun(WorkQueue<HTTPClosure>* queue, int worker_num)
{
    util::ThreadRename(strprintf("httpworker.%i", worker_num));
    queue->Run();
}

/** libevent event log callback */
static void libevent_log_cb(int severity, const char *msg)
{
    BCLog::Level level;
    switch (severity) {
    case EVENT_LOG_DEBUG:
        level = BCLog::Level::Debug;
        break;
    case EVENT_LOG_MSG:
        level = BCLog::Level::Info;
        break;
    case EVENT_LOG_WARN:
        level = BCLog::Level::Warning;
        break;
    default: // EVENT_LOG_ERR and others are mapped to error
        level = BCLog::Level::Error;
        break;
    }
    LogPrintLevel(BCLog::LIBEVENT, level, "%s\n", msg);
}

bool InitHTTPServer(const util::SignalInterrupt& interrupt)
{
    if (!InitHTTPAllowList())
        return false;


//     // Redirect libevent's logging to our own log
//     event_set_log_callback(&libevent_log_cb);
//     // Update libevent's log handling.
//     UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT));

// #ifdef WIN32
//     evthread_use_windows_threads();
// #else
//     evthread_use_pthreads();
// #endif

    raii_event_base base_ctr = obtain_event_base();

//     /* Create a new evhttp object to handle requests. */
//     raii_evhttp http_ctr = obtain_evhttp(base_ctr.get());
//     struct evhttp* http = http_ctr.get();
//     if (!http) {
//         LogPrintf("couldn't create evhttp. Exiting.\n");
//         return false;
//     }

//     evhttp_set_timeout(http, gArgs.GetIntArg("-rpcservertimeout", DEFAULT_HTTP_SERVER_TIMEOUT));
//     evhttp_set_max_headers_size(http, MAX_HEADERS_SIZE);
//     evhttp_set_max_body_size(http, MAX_SIZE);
//     evhttp_set_gencb(http, http_request_cb, (void*)&interrupt);

//     if (!HTTPBindAddresses(http)) {
//         LogPrintf("Unable to bind any endpoint for RPC server\n");
//         return false;
//     }

    LogDebug(BCLog::HTTP, "Initialized HTTP server\n");
    int workQueueDepth = std::max((long)gArgs.GetIntArg("-rpcworkqueue", DEFAULT_HTTP_WORKQUEUE), 1L);
    LogDebug(BCLog::HTTP, "creating work queue of depth %d\n", workQueueDepth);

    g_work_queue = std::make_unique<WorkQueue<HTTPClosure>>(workQueueDepth);
    // transfer ownership to eventBase/HTTP via .release()
    eventBase = base_ctr.release();
//     eventHTTP = http_ctr.release();
//     return true;

    return InitHTTPServer_mz();
}

void UpdateHTTPServerLogging(bool enable) {
    if (enable) {
        event_enable_debug_logging(EVENT_DBG_ALL);
    } else {
        event_enable_debug_logging(EVENT_DBG_NONE);
    }
}

// static std::thread g_thread_http;
static std::vector<std::thread> g_thread_http_workers;

void StartHTTPServer()
{
    int rpcThreads = std::max((long)gArgs.GetIntArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1L);
    LogInfo("Starting HTTP server with %d worker threads\n", rpcThreads);
    // g_thread_http = std::thread(ThreadHTTP, eventBase);
    StartHTTPServer_mz();

    for (int i = 0; i < rpcThreads; i++) {
        g_thread_http_workers.emplace_back(HTTPWorkQueueRun, g_work_queue.get(), i);
    }
}

void InterruptHTTPServer()
{
    LogDebug(BCLog::HTTP, "Interrupting HTTP server\n");
    if (eventHTTP) {
        // Reject requests on current connections
        evhttp_set_gencb(eventHTTP, http_reject_request_cb, nullptr);
    }
    if (g_work_queue) {
        g_work_queue->Interrupt();
    }
}

void StopHTTPServer()
{
    LogDebug(BCLog::HTTP, "Stopping HTTP server\n");
    if (g_work_queue) {
        LogDebug(BCLog::HTTP, "Waiting for HTTP worker threads to exit\n");
        for (auto& thread : g_thread_http_workers) {
            thread.join();
        }
        g_thread_http_workers.clear();
    }

    // // Unlisten sockets, these are what make the event loop running, which means
    // // that after this and all connections are closed the event loop will quit.
    // for (evhttp_bound_socket *socket : boundSockets) {
    //     evhttp_del_accept_socket(eventHTTP, socket);
    // }
    // boundSockets.clear();
    // {
    //     if (const auto n_connections{g_requests.CountActiveConnections()}; n_connections != 0) {
    //         LogDebug(BCLog::HTTP, "Waiting for %d connections to stop HTTP server\n", n_connections);
    //     }
    //     g_requests.WaitUntilEmpty();
    // }
    // if (eventHTTP) {
    //     // Schedule a callback to call evhttp_free in the event base thread, so
    //     // that evhttp_free does not need to be called again after the handling
    //     // of unfinished request connections that follows.
    //     event_base_once(eventBase, -1, EV_TIMEOUT, [](evutil_socket_t, short, void*) {
    //         evhttp_free(eventHTTP);
    //         eventHTTP = nullptr;
    //     }, nullptr, nullptr);
    // }
    // if (eventBase) {
    //     LogDebug(BCLog::HTTP, "Waiting for HTTP event thread to exit\n");
    //     if (g_thread_http.joinable()) g_thread_http.join();
    //     event_base_free(eventBase);
    //     eventBase = nullptr;
    // }

    StopHTTPServer_mz();
    g_work_queue.reset();
    LogDebug(BCLog::HTTP, "Stopped HTTP server\n");
}

struct event_base* EventBase()
{
    return eventBase;
}

static void httpevent_callback_fn(evutil_socket_t, short, void* data)
{
    // Static handler: simply call inner handler
    HTTPEvent *self = static_cast<HTTPEvent*>(data);
    self->handler();
    if (self->deleteWhenTriggered)
        delete self;
}

HTTPEvent::HTTPEvent(struct event_base* base, bool _deleteWhenTriggered, const std::function<void()>& _handler):
    deleteWhenTriggered(_deleteWhenTriggered), handler(_handler)
{
    ev = event_new(base, -1, 0, httpevent_callback_fn, this);
    assert(ev);
}
HTTPEvent::~HTTPEvent()
{
    event_free(ev);
}
void HTTPEvent::trigger(struct timeval* tv)
{
    if (tv == nullptr)
        event_active(ev, 0, 0); // immediately trigger event in main thread
    else
        evtimer_add(ev, tv); // trigger after timeval passed
}
HTTPRequest::HTTPRequest(HTTPRequest_mz* _req, const util::SignalInterrupt& interrupt, bool _replySent)
    : req(_req), m_interrupt(interrupt), replySent(_replySent)
{
}

HTTPRequest::~HTTPRequest()
{
    if (!replySent) {
        // Keep track of whether reply was sent to avoid request leaks
        LogPrintf("%s: Unhandled request\n", __func__);
        WriteReply(HTTP_INTERNAL_SERVER_ERROR, "Unhandled request");
    }
    // evhttpd cleans up the request, as long as a reply was sent.
}

std::pair<bool, std::string> HTTPRequest::GetHeader(const std::string& hdr) const
{
    std::optional<std::string> result{req->headers.Find(hdr)};
    if (result.has_value())
        return std::make_pair(true, result.value());
    else
        return std::make_pair(false, "");
}

std::string HTTPRequest::ReadBody()
{
    return req->body;
}

void HTTPRequest::WriteHeader(const std::string& hdr, const std::string& value)
{
    req->response_headers.Write(hdr, value);
}

/** Closure sent to main thread to request a reply to be sent to
 * a HTTP request.
 * Replies must be sent in the main loop in the main http thread,
 * this cannot be done from worker threads.
 */
void HTTPRequest::WriteReply(HTTPStatusCode status, std::span<const std::byte> reply)
{
    assert(!replySent && req);
    if (m_interrupt) {
        WriteHeader("Connection", "close");
    }
    req->WriteReply(status, reply);
    replySent = true;
    req = nullptr; // transferred back to main thread
}

CService HTTPRequest::GetPeer() const
{
    CService peer;
    peer.SetSockAddr((struct sockaddr*)&req->client.sockaddr_client);
    return peer;
}

std::string HTTPRequest::GetURI() const
{
    return req->target;
}

HTTPRequest::RequestMethod HTTPRequest::GetRequestMethod() const
{
    if (req->method == "GET") {
        return GET;
    } else if (req->method == "POST") {
        return POST;
    } else if (req->method == "HEAD") {
        return HEAD;
    } else if (req->method == "PUT") {
        return PUT;
    } else {
        return UNKNOWN;
    }
}

std::optional<std::string> HTTPRequest::GetQueryParameter(const std::string& key) const
{
    std::string uri{GetURI()};
    return GetQueryParameterFromUri(uri, key);
}

std::optional<std::string> GetQueryParameterFromUri(std::string& uri, const std::string& key)
{
    evhttp_uri* uri_parsed{evhttp_uri_parse(uri.c_str())};
    if (!uri_parsed) {
        throw std::runtime_error("URI parsing failed, it likely contained RFC 3986 invalid characters");
    }
    const char* query{evhttp_uri_get_query(uri_parsed)};
    std::optional<std::string> result;

    if (query) {
        // Parse the query string into a key-value queue and iterate over it
        struct evkeyvalq params_q;
        evhttp_parse_query_str(query, &params_q);

        for (struct evkeyval* param{params_q.tqh_first}; param != nullptr; param = param->next.tqe_next) {
            if (param->key == key) {
                result = param->value;
                break;
            }
        }
        evhttp_clear_headers(&params_q);
    }
    evhttp_uri_free(uri_parsed);

    return result;
}

void RegisterHTTPHandler(const std::string &prefix, bool exactMatch, const HTTPRequestHandler &handler)
{
    LogDebug(BCLog::HTTP, "Registering HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
    LOCK(g_httppathhandlers_mutex);
    pathHandlers.emplace_back(prefix, exactMatch, handler);
}

void UnregisterHTTPHandler(const std::string &prefix, bool exactMatch)
{
    LOCK(g_httppathhandlers_mutex);
    std::vector<HTTPPathHandler>::iterator i = pathHandlers.begin();
    std::vector<HTTPPathHandler>::iterator iend = pathHandlers.end();
    for (; i != iend; ++i)
        if (i->prefix == prefix && i->exactMatch == exactMatch)
            break;
    if (i != iend)
    {
        LogDebug(BCLog::HTTP, "Unregistering HTTP handler for %s (exactmatch %d)\n", prefix, exactMatch);
        pathHandlers.erase(i);
    }
}
