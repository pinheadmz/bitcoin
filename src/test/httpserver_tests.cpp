// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

using http_bitcoin::HTTP_OK;
using http_bitcoin::HTTPHeaders;
using http_bitcoin::HTTPReason;
using http_bitcoin::HTTPRequest;
using http_bitcoin::HTTPResponse;
using http_bitcoin::MAX_HEADERS_SIZE;
using util::LineReader;

BOOST_FIXTURE_TEST_SUITE(httpserver_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_query_parameters)
{
    std::string uri {};

    // No parameters
    uri = "localhost:8080/rest/headers/someresource.json";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // Single parameter
    uri = "localhost:8080/rest/endpoint/someresource.json?p1=v1";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(), "v1");
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p2").has_value());

    // Multiple parameters
    uri = "/rest/endpoint/someresource.json?p1=v1&p2=v2";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(), "v1");
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p2").value(), "v2");

    // If the query string contains duplicate keys, the first value is returned
    uri = "/rest/endpoint/someresource.json?p1=v1&p1=v2";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(), "v1");

    // Invalid query string syntax is the same as not having parameters
    uri = "/rest/endpoint/someresource.json&p1=v1&p2=v2";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // URI with invalid characters (%) raises a runtime error regardless of which query parameter is queried
    uri = "/rest/endpoint/someresource.json&p1=v1&p2=v2%";
    BOOST_CHECK_EXCEPTION(GetQueryParameterFromUri(uri.c_str(), "p1"), std::runtime_error, HasReason("URI parsing failed, it likely contained RFC 3986 invalid characters"));
}

BOOST_AUTO_TEST_CASE(http_headers_tests)
{
    {
        // Writing response headers
        HTTPHeaders headers{};
        BOOST_CHECK(!headers.Find("Cache-Control"));
        headers.Write("Cache-Control", "no-cache");
        // Check case-insensitive key matching
        BOOST_CHECK_EQUAL(headers.Find("Cache-Control").value(), "no-cache");
        BOOST_CHECK_EQUAL(headers.Find("cache-control").value(), "no-cache");
        // Additional values are comma-separated and appended
        headers.Write("Cache-Control", "no-store");
        BOOST_CHECK_EQUAL(headers.Find("Cache-Control").value(), "no-cache, no-store");
        // Add a few more
        headers.Write("Pie", "apple");
        headers.Write("Sandwich", "ham");
        headers.Write("Coffee", "black");
        BOOST_CHECK_EQUAL(headers.Find("Pie").value(), "apple");
        // Remove
        headers.Remove("Pie");
        BOOST_CHECK(!headers.Find("Pie"));
        // Combine for transmission
        // std::map sorts alphabetically by key, no order is specified for HTTP
        BOOST_CHECK_EQUAL(
            headers.Stringify(),
            "Cache-Control: no-cache, no-store\r\n"
            "Coffee: black\r\n"
            "Sandwich: ham\r\n\r\n");
    }
    {
        // Reading request headers captured from bitcoin-cli
        std::vector<std::byte> buffer{TryParseHex<std::byte>(
            "486f73743a203132372e302e302e310d0a436f6e6e656374696f6e3a20636c6f73"
            "650d0a436f6e74656e742d547970653a206170706c69636174696f6e2f6a736f6e"
            "0d0a417574686f72697a6174696f6e3a204261736963205831396a623239726157"
            "5666587a6f7a597a4a6b4e5441784e44466c4d474a69596d56684d5449354f4467"
            "334e7a49354d544d334e54526d4e54686b4e6a63324f574d775a5459785a6a677a"
            "4e5467794e7a4577595459314f47526b596a566d5a4751330d0a436f6e74656e74"
            "2d4c656e6774683a2034360d0a0d0a").value()};
        util::LineReader reader(buffer, /*max_read=*/1028);
        HTTPHeaders headers{};
        headers.Read(reader);
        BOOST_CHECK_EQUAL(headers.Find("Host").value(), "127.0.0.1");
        BOOST_CHECK_EQUAL(headers.Find("Connection").value(), "close");
        BOOST_CHECK_EQUAL(headers.Find("Content-Type").value(), "application/json");
        BOOST_CHECK_EQUAL(headers.Find("Authorization").value(), "Basic X19jb29raWVfXzozYzJkNTAxNDFlMGJiYmVhMTI5ODg3NzI5MTM3NTRmNThkNjc2OWMwZTYxZjgzNTgyNzEwYTY1OGRkYjVmZGQ3");
        BOOST_CHECK_EQUAL(headers.Find("Content-Length").value(), "46");
        BOOST_CHECK(!headers.Find("Pizza"));
    }
}

BOOST_AUTO_TEST_CASE(http_response_tests)
{
    // Typical HTTP 1.1 response headers
    HTTPHeaders headers{};
    headers.Write("Content-Type", "application/json");
    headers.Write("Date", "Tue, 15 Oct 2024 17:54:12 GMT");
    headers.Write("Content-Length", "41");
    // Response points to headers which already exist because some of them
    // are set before we even know what the response will be.
    HTTPResponse res(&headers);
    res.m_version_major = 1;
    res.m_version_minor = 1;
    res.m_status = HTTP_OK;
    res.m_reason = HTTPReason.find(res.m_status)->second;
    res.m_body = StringToBuffer("{\"result\":865793,\"error\":null,\"id\":null\"}");
    // Everything except the body, which might be raw bytes instead of a string
    BOOST_CHECK_EQUAL(
        res.StringifyHeaders(),
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 41\r\n"
        "Content-Type: application/json\r\n"
        "Date: Tue, 15 Oct 2024 17:54:12 GMT\r\n"
        "\r\n");
}

BOOST_AUTO_TEST_CASE(http_request_tests)
{
    {
        // Reading request captured from bitcoin-cli
        const std::string full_request =
            "504f5354202f20485454502f312e310d0a486f73743a203132372e302e302e310d"
            "0a436f6e6e656374696f6e3a20636c6f73650d0a436f6e74656e742d547970653a"
            "206170706c69636174696f6e2f6a736f6e0d0a417574686f72697a6174696f6e3a"
            "204261736963205831396a6232397261575666587a6f354f4751354f4451334d57"
            "4e6d4e6a67304e7a417a59546b7a4e32457a4e7a6b305a44466c4f4451314e6a5a"
            "6d5954526b5a6a4a694d7a466b596a68684f4449345a4759344d6a566a4f546735"
            "5a4749344f54566c0d0a436f6e74656e742d4c656e6774683a2034360d0a0d0a7b"
            "226d6574686f64223a22676574626c6f636b636f756e74222c22706172616d7322"
            "3a5b5d2c226964223a317d0a";
        HTTPRequest req;
        std::vector<std::byte> buffer{TryParseHex<std::byte>(full_request).value()};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK(req.ReadHeaders(reader));
        BOOST_CHECK(req.ReadBody(reader));
        BOOST_CHECK_EQUAL(req.m_method, "POST");
        BOOST_CHECK_EQUAL(req.m_target, "/");
        BOOST_CHECK_EQUAL(req.m_version_major, 1);
        BOOST_CHECK_EQUAL(req.m_version_minor, 1);
        BOOST_CHECK_EQUAL(req.m_headers.Find("Host").value(), "127.0.0.1");
        BOOST_CHECK_EQUAL(req.m_headers.Find("Connection").value(), "close");
        BOOST_CHECK_EQUAL(req.m_headers.Find("Content-Type").value(), "application/json");
        BOOST_CHECK_EQUAL(req.m_headers.Find("Authorization").value(), "Basic X19jb29raWVfXzo5OGQ5ODQ3MWNmNjg0NzAzYTkzN2EzNzk0ZDFlODQ1NjZmYTRkZjJiMzFkYjhhODI4ZGY4MjVjOTg5ZGI4OTVl");
        BOOST_CHECK_EQUAL(req.m_headers.Find("Content-Length").value(), "46");
        BOOST_CHECK_EQUAL(req.m_body.size(), 46);
        BOOST_CHECK_EQUAL(req.m_body, "{\"method\":\"getblockcount\",\"params\":[],\"id\":1}\n");
    }
    {
        const std::string too_short_request_line = "GET/HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(too_short_request_line)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK_THROW(req.ReadControlData(reader), std::runtime_error);
    }
    {
        const std::string malformed_request_line = "GET / HTTP / 1.0\r\nHost: 127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(malformed_request_line)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK_THROW(req.ReadControlData(reader), std::runtime_error);
    }
    {
        const std::string malformed_request_line = "GET / HTTP1.0\r\nHost: 127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(malformed_request_line)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK_THROW(req.ReadControlData(reader), std::runtime_error);
    }
    {
        const std::string malformed_request_line = "GET / HTTP/11\r\nHost: 127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(malformed_request_line)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK_THROW(req.ReadControlData(reader), std::runtime_error);
    }
    {
        const std::string malformed_request_line = "GET / HTTP/1.x\r\nHost: 127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(malformed_request_line)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK_THROW(req.ReadControlData(reader), std::runtime_error);
    }
    {
        const std::string ok_request_line = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(ok_request_line)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK(req.ReadHeaders(reader));
        BOOST_CHECK(req.ReadBody(reader));
        BOOST_CHECK_EQUAL(req.m_method, "GET");
        BOOST_CHECK_EQUAL(req.m_target, "/");
        BOOST_CHECK_EQUAL(req.m_version_major, 1);
        BOOST_CHECK_EQUAL(req.m_version_minor, 0);
        BOOST_CHECK_EQUAL(req.m_headers.Find("Host").value(), "127.0.0.1");
        // no body is OK
        BOOST_CHECK_EQUAL(req.m_body.size(), 0);
    }
    {
        const std::string malformed_headers = "GET / HTTP/1.0\r\nHost=127.0.0.1\r\n\r\n";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(malformed_headers)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK_THROW(req.ReadHeaders(reader), std::runtime_error);
    }
    {
        // We might not have received enough data from the client which is not
        // an error. We return false so the caller can try again later when the
        // buffer has more data.
        const std::string incomplete_headers = "GET / HTTP/1.0\r\nHost: ";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(incomplete_headers)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK(!req.ReadHeaders(reader));
    }
    {
        const std::string no_content_length = "GET / HTTP/1.0\r\n\r\n{\"method\":\"getblockcount\"}";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(no_content_length)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK(req.ReadHeaders(reader));
        BOOST_CHECK(req.ReadBody(reader));
        // Don't try to read request body if Content-Length is missing
        BOOST_CHECK_EQUAL(req.m_body.size(), 0);
    }
    {
        const std::string bad_content_length = "GET / HTTP/1.0\r\nContent-Length: eleven\r\n\r\n{\"method\":\"getblockcount\"}";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(bad_content_length)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK(req.ReadHeaders(reader));
        BOOST_CHECK_THROW(req.ReadBody(reader), std::runtime_error);
    }
    {
        // Content-Length indicates more data than we have in the buffer.
        // Again, not an error just try again later.
        const std::string excessive_content_length = "GET / HTTP/1.0\r\nContent-Length: 1024\r\n\r\n{\"method\":\"getblockcount\"}";
        HTTPRequest req;
        std::vector<std::byte> buffer{StringToBuffer(excessive_content_length)};
        LineReader reader(buffer, MAX_HEADERS_SIZE);
        BOOST_CHECK(req.ReadControlData(reader));
        BOOST_CHECK(req.ReadHeaders(reader));
        BOOST_CHECK(!req.ReadBody(reader));
    }
}
BOOST_AUTO_TEST_SUITE_END()
