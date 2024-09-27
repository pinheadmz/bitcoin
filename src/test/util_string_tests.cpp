// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/strencodings.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

using namespace util;

BOOST_AUTO_TEST_SUITE(util_string_tests)

// Helper to allow compile-time sanity checks while providing the number of
// args directly. Normally PassFmt<sizeof...(Args)> would be used.
template <unsigned NumArgs>
inline void PassFmt(util::ConstevalFormatString<NumArgs> fmt)
{
    // This was already executed at compile-time, but is executed again at run-time to avoid -Wunused.
    decltype(fmt)::Detail_CheckNumFormatSpecifiers(fmt.fmt);
}
template <unsigned WrongNumArgs>
inline void FailFmtWithError(std::string_view wrong_fmt, std::string_view error)
{
    using ErrType = const char*;
    auto check_throw{[error](const ErrType& str) { return str == error; }};
    BOOST_CHECK_EXCEPTION(util::ConstevalFormatString<WrongNumArgs>::Detail_CheckNumFormatSpecifiers(wrong_fmt), ErrType, check_throw);
}

BOOST_AUTO_TEST_CASE(ConstevalFormatString_NumSpec)
{
    PassFmt<0>("");
    PassFmt<0>("%%");
    PassFmt<1>("%s");
    PassFmt<0>("%%s");
    PassFmt<0>("s%%");
    PassFmt<1>("%%%s");
    PassFmt<1>("%s%%");
    PassFmt<0>(" 1$s");
    PassFmt<1>("%1$s");
    PassFmt<1>("%1$s%1$s");
    PassFmt<2>("%2$s");
    PassFmt<2>("%2$s 4$s %2$s");
    PassFmt<129>("%129$s 999$s %2$s");
    PassFmt<1>("%02d");
    PassFmt<1>("%+2s");
    PassFmt<1>("%.6i");
    PassFmt<1>("%5.2f");
    PassFmt<1>("%#x");
    PassFmt<1>("%1$5i");
    PassFmt<1>("%1$-5i");
    PassFmt<1>("%1$.5i");
    // tinyformat accepts almost any "type" spec, even '%', or '_', or '\n'.
    PassFmt<1>("%123%");
    PassFmt<1>("%123%s");
    PassFmt<1>("%_");
    PassFmt<1>("%\n");

    // The `*` specifier behavior is unsupported and can lead to runtime
    // errors when used in a ConstevalFormatString. Please refer to the
    // note in the ConstevalFormatString docs.
    PassFmt<1>("%*c");
    PassFmt<2>("%2$*3$d");
    PassFmt<1>("%.*f");

    auto err_mix{"Format specifiers must be all positional or all non-positional!"};
    FailFmtWithError<1>("%s%1$s", err_mix);

    auto err_num{"Format specifier count must match the argument count!"};
    FailFmtWithError<1>("", err_num);
    FailFmtWithError<0>("%s", err_num);
    FailFmtWithError<2>("%s", err_num);
    FailFmtWithError<0>("%1$s", err_num);
    FailFmtWithError<2>("%1$s", err_num);

    auto err_0_pos{"Positional format specifier must have position of at least 1"};
    FailFmtWithError<1>("%$s", err_0_pos);
    FailFmtWithError<1>("%$", err_0_pos);
    FailFmtWithError<0>("%0$", err_0_pos);
    FailFmtWithError<0>("%0$s", err_0_pos);

    auto err_term{"Format specifier incorrectly terminated by end of string"};
    FailFmtWithError<1>("%", err_term);
    FailFmtWithError<1>("%1$", err_term);
}

BOOST_AUTO_TEST_CASE(case_insensitive_comparator_test)
{
    CaseInsensitiveComparator cmp;
    BOOST_CHECK(cmp("A", "B"));
    BOOST_CHECK(cmp("A", "b"));
    BOOST_CHECK(cmp("a", "B"));
    BOOST_CHECK(!cmp("B", "A"));
    BOOST_CHECK(!cmp("B", "a"));
    BOOST_CHECK(!cmp("b", "A"));
}

BOOST_AUTO_TEST_CASE(line_reader_test)
{
    {
        // Check three lines terminated by \n, \r\n, and end of buffer, trimming whitespace
        const std::vector<std::byte> input{StringToBuffer("once upon a time\n there was a dog \r\nwho liked food")};
        LineReader reader(input, /*max_read=*/128);
        std::optional<std::string> line1{reader.ReadLine()};
        BOOST_CHECK_EQUAL(reader.Left(), 33);
        std::optional<std::string> line2{reader.ReadLine()};
        BOOST_CHECK_EQUAL(reader.Left(), 14);
        std::optional<std::string> line3{reader.ReadLine()};
        std::optional<std::string> line4{reader.ReadLine()};
        BOOST_CHECK(line1);
        BOOST_CHECK(line2);
        BOOST_CHECK(line3);
        BOOST_CHECK(!line4);
        BOOST_CHECK_EQUAL(line1.value(), "once upon a time");
        BOOST_CHECK_EQUAL(line2.value(), "there was a dog");
        BOOST_CHECK_EQUAL(line3.value(), "who liked food");
    }
    {
        // Do not exceed max_read
        const std::vector<std::byte> input{StringToBuffer("once upon a time there was a dog\nwho liked food")};
        LineReader reader(input, /*max_read=*/10);
        BOOST_CHECK_THROW(reader.ReadLine(), std::runtime_error);
    }
    {
        // Read specific number of bytes regardless of max_read or \n unless buffer is too short
        const std::vector<std::byte> input{StringToBuffer("once upon a time\n there was a dog \r\nwho liked food")};
        LineReader reader(input, /*max_read=*/1);
        BOOST_CHECK_EQUAL(reader.ReadLength(3), "onc");
        BOOST_CHECK_EQUAL(reader.ReadLength(8), "e upon a");
        BOOST_CHECK_EQUAL(reader.ReadLength(8), " time\n t");
        BOOST_CHECK_THROW(reader.ReadLength(128), std::runtime_error);
    }
}

BOOST_AUTO_TEST_SUITE_END()
