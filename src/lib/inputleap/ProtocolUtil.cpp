/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2002 Chris Schoeneman
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "inputleap/ProtocolUtil.h"
#include "io/IStream.h"
#include "base/Log.h"
#include "inputleap/protocol_types.h"
#include "inputleap/Exceptions.h"

#include <cctype>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace inputleap {

void ProtocolUtil::writefArgs(inputleap::IStream* stream, const char* fmt,
                              const std::vector<WriteArgument>& arguments)
{
    assert(stream != nullptr);
    assert(fmt != nullptr);
    LOG_DEBUG5("writef(%s)", fmt);

    std::size_t argumentIndex = 0;
    std::size_t total = 0;
    const auto addLength = [&](std::size_t length) {
        if (length > PROTOCOL_MAX_MESSAGE_LENGTH - total) {
            throw std::length_error("protocol message exceeds maximum length");
        }
        total += length;
    };
    const auto next = [&](WriteArgument::Kind kind) -> const WriteArgument& {
        if (argumentIndex >= arguments.size() || arguments[argumentIndex].kind != kind) {
            throw std::invalid_argument("protocol format argument type mismatch");
        }
        return arguments[argumentIndex++];
    };

    const char* cursor = fmt;
    while (*cursor != '\0') {
        if (*cursor++ != '%') {
            addLength(1);
            continue;
        }
        const std::uint32_t length = eatLength(&cursor);
        switch (*cursor++) {
        case 'i':
            if (length != 1 && length != 2 && length != 4) {
                throw std::invalid_argument("invalid integer format length");
            }
            (void)next(WriteArgument::Kind::Integer);
            addLength(length);
            break;
        case 'I': {
            if (length != 1 && length != 2 && length != 4) {
                throw std::invalid_argument("invalid list format length");
            }
            const auto kind = length == 1 ? WriteArgument::Kind::List8 :
                              length == 2 ? WriteArgument::Kind::List16 :
                                            WriteArgument::Kind::List32;
            const auto& value = next(kind);
            if (value.data == nullptr || value.size > PROTOCOL_MAX_LIST_LENGTH) {
                throw std::length_error("protocol list exceeds maximum length");
            }
            if (value.size > (PROTOCOL_MAX_MESSAGE_LENGTH - 4u) / length) {
                throw std::length_error("protocol list byte size overflow");
            }
            addLength(4u + value.size * length);
            break;
        }
        case 's': {
            if (length != 0) {
                throw std::invalid_argument("invalid string format length");
            }
            const auto& value = next(WriteArgument::Kind::String);
            if (value.size > PROTOCOL_MAX_STRING_LENGTH) {
                throw std::length_error("protocol string exceeds maximum length");
            }
            addLength(4u + value.size);
            break;
        }
        case 'S': {
            if (length != 0) {
                throw std::invalid_argument("invalid byte string format length");
            }
            const auto& count = next(WriteArgument::Kind::Integer);
            const auto& value = next(WriteArgument::Kind::Bytes);
            if (count.integer > PROTOCOL_MAX_STRING_LENGTH ||
                (count.integer != 0 && value.data == nullptr)) {
                throw std::length_error("protocol byte string exceeds maximum length");
            }
            addLength(4u + count.integer);
            break;
        }
        case '%':
            if (length != 0) {
                throw std::invalid_argument("invalid percent format length");
            }
            addLength(1);
            break;
        default:
            throw std::invalid_argument("invalid protocol format specifier");
        }
    }
    if (argumentIndex != arguments.size()) {
        throw std::invalid_argument("too many protocol format arguments");
    }

    std::vector<std::uint8_t> buffer;
    buffer.reserve(total);
    argumentIndex = 0;
    const auto appendInteger = [&](std::uint32_t value, std::uint32_t length) {
        for (std::uint32_t shift = length * 8; shift != 0; shift -= 8) {
            buffer.push_back(static_cast<std::uint8_t>((value >> (shift - 8)) & 0xff));
        }
    };
    cursor = fmt;
    while (*cursor != '\0') {
        if (*cursor != '%') {
            buffer.push_back(static_cast<std::uint8_t>(*cursor++));
            continue;
        }
        ++cursor;
        const std::uint32_t length = eatLength(&cursor);
        switch (*cursor++) {
        case 'i':
            appendInteger(arguments[argumentIndex++].integer, length);
            break;
        case 'I': {
            const auto& value = arguments[argumentIndex++];
            appendInteger(static_cast<std::uint32_t>(value.size), 4);
            if (length == 1) {
                const auto& list = *static_cast<const std::vector<std::uint8_t>*>(value.data);
                buffer.insert(buffer.end(), list.begin(), list.end());
            }
            else if (length == 2) {
                const auto& list = *static_cast<const std::vector<std::uint16_t>*>(value.data);
                for (const auto item : list) appendInteger(item, 2);
            }
            else {
                const auto& list = *static_cast<const std::vector<std::uint32_t>*>(value.data);
                for (const auto item : list) appendInteger(item, 4);
            }
            break;
        }
        case 's': {
            const auto& value = arguments[argumentIndex++];
            appendInteger(static_cast<std::uint32_t>(value.size), 4);
            if (value.size != 0) {
                const auto& text = *static_cast<const std::string*>(value.data);
                buffer.insert(buffer.end(), text.begin(), text.end());
            }
            break;
        }
        case 'S': {
            const auto count = arguments[argumentIndex++].integer;
            const auto& value = arguments[argumentIndex++];
            appendInteger(count, 4);
            if (count != 0) {
                const auto* bytes = static_cast<const std::uint8_t*>(value.data);
                buffer.insert(buffer.end(), bytes, bytes + count);
            }
            break;
        }
        case '%':
            buffer.push_back('%');
            break;
        default:
            throw std::invalid_argument("invalid protocol format specifier");
        }
    }

    if (!buffer.empty()) {
        stream->write(buffer.data(), static_cast<std::uint32_t>(buffer.size()));
        LOG_DEBUG5("wrote %d bytes", static_cast<std::uint32_t>(buffer.size()));
    }
}

bool
ProtocolUtil::readf(inputleap::IStream* stream, const char* fmt, ...)
{
    assert(stream != nullptr);
    assert(fmt != nullptr);
    LOG_DEBUG5("readf(%s)", fmt);

    bool result;
    va_list args;
    va_start(args, fmt);
    try {
        vreadf(stream, fmt, args);
        result = true;
    }
    catch (XIO&) {
        result = false;
    }
    va_end(args);
    return result;
}

bool
ProtocolUtil::readf(inputleap::IStream* stream, const char* fmt,
                    std::vector<std::uint32_t>* values)
{
    assert(stream != nullptr);
    assert(fmt != nullptr);
    if (values == nullptr || std::strcmp(fmt, "%4I") != 0) {
        throw std::invalid_argument("typed list reader requires %4I and a destination");
    }

    try {
        std::uint8_t countBytes[4];
        read(stream, countBytes, 4);
        const std::uint32_t count =
            (static_cast<std::uint32_t>(countBytes[0]) << 24) |
            (static_cast<std::uint32_t>(countBytes[1]) << 16) |
            (static_cast<std::uint32_t>(countBytes[2]) << 8) |
             static_cast<std::uint32_t>(countBytes[3]);
        if (count > PROTOCOL_MAX_LIST_LENGTH) {
            throw XBadClient("Too long message received");
        }

        std::vector<std::uint32_t> decoded;
        decoded.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            std::uint8_t item[4];
            read(stream, item, 4);
            decoded.push_back(
                (static_cast<std::uint32_t>(item[0]) << 24) |
                (static_cast<std::uint32_t>(item[1]) << 16) |
                (static_cast<std::uint32_t>(item[2]) << 8) |
                 static_cast<std::uint32_t>(item[3]));
        }
        values->insert(values->end(), decoded.begin(), decoded.end());
        return true;
    }
    catch (XIO&) {
        return false;
    }
}

void
ProtocolUtil::vreadf(inputleap::IStream* stream, const char* fmt, va_list args)
{
    assert(stream != nullptr);
    assert(fmt != nullptr);

    // begin scanning
    while (*fmt) {
        if (*fmt == '%') {
            // format specifier.  determine argument size.
            ++fmt;
            std::uint32_t len = eatLength(&fmt);
            switch (*fmt) {
            case 'i': {
                // check for valid length
                assert(len == 1 || len == 2 || len == 4);

                // read the data
                std::uint8_t buffer[4];
                read(stream, buffer, len);

                // convert it
                void* v = va_arg(args, void*);
                switch (len) {
                case 1:
                    // 1 byte integer
                    *static_cast<std::uint8_t*>(v) = buffer[0];
                    LOG_DEBUG5("readf: read %d byte integer: %d (0x%x)", len,
                         *static_cast<std::uint8_t*>(v), *static_cast<std::uint8_t*>(v));
                    break;

                case 2:
                    // 2 byte integer
                    *static_cast<std::uint16_t*>(v) =
                        static_cast<std::uint16_t>(
                        (static_cast<std::uint16_t>(buffer[0]) << 8) |
                         static_cast<std::uint16_t>(buffer[1]));
                    LOG_DEBUG5("readf: read %d byte integer: %d (0x%x)", len,
                         *static_cast<std::uint16_t*>(v), *static_cast<std::uint16_t*>(v));
                    break;

                case 4:
                    // 4 byte integer
                    *static_cast<std::uint32_t*>(v) =
                        (static_cast<std::uint32_t>(buffer[0]) << 24) |
                        (static_cast<std::uint32_t>(buffer[1]) << 16) |
                        (static_cast<std::uint32_t>(buffer[2]) <<  8) |
                         static_cast<std::uint32_t>(buffer[3]);
                    LOG_DEBUG5("readf: read %d byte integer: %d (0x%x)", len,
                         *static_cast<std::uint32_t*>(v), *static_cast<std::uint32_t*>(v));
                    break;
                default:
                    break;
                }
                break;
            }

            case 'I': {
                // check for valid length
                assert(len == 1 || len == 2 || len == 4);

                // read the vector length
                std::uint8_t buffer[4];
                read(stream, buffer, 4);
                std::uint32_t n = (static_cast<std::uint32_t>(buffer[0]) << 24) |
                                  (static_cast<std::uint32_t>(buffer[1]) << 16) |
                                  (static_cast<std::uint32_t>(buffer[2]) <<  8) |
                                   static_cast<std::uint32_t>(buffer[3]);

                if (n > PROTOCOL_MAX_LIST_LENGTH) {
                    throw XBadClient("Too long message received");
                }

                // convert it
                void* v = va_arg(args, void*);
                switch (len) {
                case 1:
                    // 1 byte integer
                    for (std::uint32_t i = 0; i < n; ++i) {
                        read(stream, buffer, 1);
                        static_cast<std::vector<std::uint8_t>*>(v)->push_back(
                            buffer[0]);
                        LOG_DEBUG5("readf: read %d byte integer[%d]: %d (0x%x)", len, i,
                             static_cast<std::vector<std::uint8_t>*>(v)->back(),
                             static_cast<std::vector<std::uint8_t>*>(v)->back());
                    }
                    break;

                case 2:
                    // 2 byte integer
                    for (std::uint32_t i = 0; i < n; ++i) {
                        read(stream, buffer, 2);
                        static_cast<std::vector<std::uint16_t>*>(v)->push_back(
                            static_cast<std::uint16_t>(
                            (static_cast<std::uint16_t>(buffer[0]) << 8) |
                             static_cast<std::uint16_t>(buffer[1])));
                        LOG_DEBUG5("readf: read %d byte integer[%d]: %d (0x%x)", len, i,
                             static_cast<std::vector<std::uint16_t>*>(v)->back(),
                             static_cast<std::vector<std::uint16_t>*>(v)->back());
                    }
                    break;

                case 4:
                    // 4 byte integer
                    for (std::uint32_t i = 0; i < n; ++i) {
                        read(stream, buffer, 4);
                        static_cast<std::vector<std::uint32_t>*>(v)->push_back(
                            (static_cast<std::uint32_t>(buffer[0]) << 24) |
                            (static_cast<std::uint32_t>(buffer[1]) << 16) |
                            (static_cast<std::uint32_t>(buffer[2]) <<  8) |
                             static_cast<std::uint32_t>(buffer[3]));
                        LOG_DEBUG5("readf: read %d byte integer[%d]: %d (0x%x)", len, i,
                             static_cast<std::vector<std::uint32_t>*>(v)->back(),
                             static_cast<std::vector<std::uint32_t>*>(v)->back());
                    }
                    break;
                default:
                    break;
                }
                break;
            }

            case 's': {
                assert(len == 0);

                // read the string length
                std::uint8_t buffer[128];
                read(stream, buffer, 4);
                std::uint32_t str_len = (static_cast<std::uint32_t>(buffer[0]) << 24) |
                                        (static_cast<std::uint32_t>(buffer[1]) << 16) |
                                        (static_cast<std::uint32_t>(buffer[2]) <<  8) |
                                         static_cast<std::uint32_t>(buffer[3]);

                if (str_len > PROTOCOL_MAX_STRING_LENGTH) {
                    throw XBadClient("Too long message received");
                }

                // use a fixed size buffer if its big enough
                const bool useFixed = (str_len <= sizeof(buffer));

                // allocate a buffer to read the data
                std::uint8_t* sBuffer = buffer;
                if (!useFixed) {
                    sBuffer = new std::uint8_t[str_len];
                }

                // read the data
                try {
                    read(stream, sBuffer, str_len);
                }
                catch (...) {
                    if (!useFixed) {
                        delete[] sBuffer;
                    }
                    throw;
                }

                LOG_DEBUG5("readf: read %d byte string", str_len);

                // save the data
                std::string* dst = va_arg(args, std::string*);
                dst->assign(reinterpret_cast<const char*>(sBuffer), str_len);

                // release the buffer
                if (!useFixed) {
                    delete[] sBuffer;
                }
                break;
            }

            case '%':
                assert(len == 0);
                break;

            default:
                assert(0 && "invalid format specifier");
            }

            // next format character
            ++fmt;
        }
        else {
            // read next character
            char buffer[1];
            read(stream, buffer, 1);

            // verify match
            if (buffer[0] != *fmt) {
                LOG_DEBUG2("readf: format mismatch: %c vs %c", *fmt, buffer[0]);
                throw XIOReadMismatch();
            }

            // next format character
            ++fmt;
        }
    }
}

std::uint32_t ProtocolUtil::eatLength(const char** pfmt)
{
    const char* fmt = *pfmt;
    std::uint32_t n = 0;
    for (;;) {
        std::uint32_t d;
        switch (*fmt) {
        case '0': d = 0; break;
        case '1': d = 1; break;
        case '2': d = 2; break;
        case '3': d = 3; break;
        case '4': d = 4; break;
        case '5': d = 5; break;
        case '6': d = 6; break;
        case '7': d = 7; break;
        case '8': d = 8; break;
        case '9': d = 9; break;
        default: *pfmt = fmt; return n;
        }
        n = 10 * n + d;
        ++fmt;
    }
}

void ProtocolUtil::read(inputleap::IStream* stream, void* vbuffer, std::uint32_t count)
{
    assert(stream != nullptr);
    assert(vbuffer != nullptr);

    std::uint8_t* buffer = static_cast<std::uint8_t*>(vbuffer);
    while (count > 0) {
        // read more
        std::uint32_t n = stream->read(buffer, count);

        // bail if stream has hungup
        if (n == 0) {
            LOG_DEBUG2("unexpected disconnect in readf(), %d bytes left", count);
            throw XIOEndOfStream();
        }

        // prepare for next read
        buffer += n;
        count  -= n;
    }
}


//
// XIOReadMismatch
//

std::string XIOReadMismatch::getWhat() const noexcept
{
    return format("XIOReadMismatch", "ProtocolUtil::readf() mismatch");
}

} // namespace inputleap
