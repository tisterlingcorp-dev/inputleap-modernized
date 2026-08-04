#include "platform/XWindowsClipboardFileListConverter.h"

#include <cctype>

namespace inputleap {

namespace {

int hexValue(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::string decodeFileUri(const std::string& uri)
{
    const std::string prefix = "file://";
    if (uri.compare(0, prefix.size(), prefix) != 0) {
        return {};
    }

    std::string path = uri.substr(prefix.size());
    if (path.compare(0, 1, "/") != 0) {
        return {};
    }
    std::string decoded;
    decoded.reserve(path.size());
    for (size_t index = 0; index < path.size(); ++index) {
        if (path[index] == '%' && index + 2 < path.size()) {
            const int high = hexValue(path[index + 1]);
            const int low = hexValue(path[index + 2]);
            if (high < 0 || low < 0) return {};
            decoded.push_back(static_cast<char>((high << 4) | low));
            index += 2;
        } else {
            decoded.push_back(path[index]);
        }
    }
    return decoded;
}

} // namespace

XWindowsClipboardFileListConverter::XWindowsClipboardFileListConverter(Display* display,
                                                                       const char* atomName,
                                                                       bool gnomeFormat) :
    m_atom(XInternAtom(display, atomName, False)),
    m_gnomeFormat(gnomeFormat)
{
}

IClipboard::EFormat XWindowsClipboardFileListConverter::getFormat() const
{
    return IClipboard::kFileList;
}

Atom XWindowsClipboardFileListConverter::getAtom() const
{
    return m_atom;
}

int XWindowsClipboardFileListConverter::getDataSize() const
{
    return 8;
}

std::string XWindowsClipboardFileListConverter::fromIClipboard(const std::string& data) const
{
    // The internal representation is newline-separated local paths.  X11
    // uses URI list; paths are escaped conservatively for spaces and UTF-8.
    std::string result;
    size_t start = 0;
    while (start <= data.size()) {
        const size_t end = data.find('\n', start);
        std::string path = data.substr(start, end == std::string::npos ? end : end - start);
        if (!path.empty() && path.back() == '\r') path.pop_back();
        if (!path.empty()) {
            if (!result.empty()) result += m_gnomeFormat ? "\n" : "\r\n";
            result += "file://";
            for (const unsigned char value : path) {
                if (std::isalnum(value) || value == '/' || value == '-' || value == '_' || value == '.' || value == '~') {
                    result.push_back(static_cast<char>(value));
                } else {
                    static const char hex[] = "0123456789ABCDEF";
                    result.push_back('%');
                    result.push_back(hex[value >> 4]);
                    result.push_back(hex[value & 0x0f]);
                }
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    if (result.empty()) return {};
    // Match the native GNOME clipboard contract exactly.  The GNOME target
    // has no trailing line break; text/uri-list uses RFC-style CRLF.
    if (m_gnomeFormat) return "copy\n" + result;
    return result + "\r\n";
}

std::string XWindowsClipboardFileListConverter::toIClipboard(const std::string& data) const
{
    std::string result;
    size_t start = 0;
    if (m_gnomeFormat) {
        const size_t firstLine = data.find('\n');
        if (firstLine == std::string::npos ||
            (data.substr(0, firstLine) != "copy" && data.substr(0, firstLine) != "cut")) {
            return {};
        }
        start = firstLine + 1;
    }
    while (start <= data.size()) {
        const size_t end = data.find('\n', start);
        std::string line = data.substr(start, end == std::string::npos ? end : end - start);
        if (!line.empty() && line[0] != '#') {
            if (line.back() == '\r') line.pop_back();
            const std::string path = decodeFileUri(line);
            if (!path.empty()) {
                if (!result.empty()) result.push_back('\n');
                result += path;
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

} // namespace inputleap
