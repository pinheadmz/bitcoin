// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/string.h>

#include <regex>
#include <string>

namespace util {
void ReplaceAll(std::string& in_out, const std::string& search, const std::string& substitute)
{
    if (search.empty()) return;
    in_out = std::regex_replace(in_out, std::regex(search), substitute);
}

LineReader::LineReader(std::span<const std::byte> buffer, size_t max_read)
    : start(buffer.begin()), end(buffer.end()), max_read(max_read), it(buffer.begin()) {}

std::optional<std::string> LineReader::ReadLine()
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

// Ignores max_read but won't overflow
std::string LineReader::ReadLength(size_t len)
{
    if (Left() < len) throw std::runtime_error("Not enough data in buffer");
    std::string out(reinterpret_cast<const char*>(&(*it)), len);
    it += len;
    return out;
}

size_t LineReader::Left() const
{
    return std::distance(it, end);
}
} // namespace util
