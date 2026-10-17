/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2013-2016 Symless Ltd.
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

#include "inputleap/DragInformation.h"
#include "base/Log.h"
#include "io/filesystem.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace inputleap {

namespace {

constexpr char kFilePackageMagic[] = "ILFILE1";
constexpr std::size_t kMaxFilePackageSize = 256 * 1024 * 1024;
constexpr std::uint32_t kMaxFileCount = 128;
std::atomic<std::uint64_t> g_stagingSequence{0};

class StagingDirectory {
public:
    explicit StagingDirectory(fs::path path) : m_path(std::move(path)) {}
    ~StagingDirectory()
    {
        std::error_code ignored;
        fs::remove_all(m_path, ignored);
    }

    const fs::path& path() const { return m_path; }

private:
    fs::path m_path;
};

bool isSafePackagePath(const fs::path& relative)
{
    if (relative.empty() || relative.is_absolute()) return false;
    for (const fs::path& component : relative) {
        const std::string value = path_to_utf8(component);
        if (value.empty() || value == "." || value == ".." ||
            value.back() == '.' || value.back() == ' ') return false;
        for (const unsigned char character : value) {
            if (character < 0x20 || character == '<' || character == '>' ||
                character == '"' || character == '|' || character == '?' ||
                character == '*' || character == ':') return false;
        }

        std::string deviceName = value.substr(0, value.find('.'));
        while (!deviceName.empty() && (deviceName.back() == '.' || deviceName.back() == ' ')) {
            deviceName.pop_back();
        }
        std::transform(deviceName.begin(), deviceName.end(), deviceName.begin(),
                       [](unsigned char character) {
                           return static_cast<char>(std::toupper(character));
                       });
        if (deviceName == "CON" || deviceName == "PRN" || deviceName == "AUX" ||
            deviceName == "NUL" || deviceName == "CONIN$" || deviceName == "CONOUT$") return false;
        if (deviceName.size() == 4 &&
            (deviceName.compare(0, 3, "COM") == 0 || deviceName.compare(0, 3, "LPT") == 0) &&
            deviceName[3] >= '1' && deviceName[3] <= '9') return false;
    }
    return true;
}

void appendU32(std::string& output, std::uint32_t value)
{
    output.push_back(static_cast<char>((value >> 24) & 0xff));
    output.push_back(static_cast<char>((value >> 16) & 0xff));
    output.push_back(static_cast<char>((value >> 8) & 0xff));
    output.push_back(static_cast<char>(value & 0xff));
}

void appendU64(std::string& output, std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

bool readU32(const std::string& data, std::size_t& offset, std::uint32_t& value)
{
    if (offset + 4 > data.size()) return false;
    value = (static_cast<std::uint32_t>(static_cast<unsigned char>(data[offset])) << 24) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[offset + 1])) << 16) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(data[offset + 2])) << 8) |
            static_cast<std::uint32_t>(static_cast<unsigned char>(data[offset + 3]));
    offset += 4;
    return true;
}

bool readU64(const std::string& data, std::size_t& offset, std::uint64_t& value)
{
    if (offset + 8 > data.size()) return false;
    value = 0;
    for (int index = 0; index < 8; ++index) {
        value = (value << 8) | static_cast<unsigned char>(data[offset + index]);
    }
    offset += 8;
    return true;
}

std::string baseName(const std::string& path)
{
    const std::size_t separator = path.find_last_of("/\\");
    std::string name = separator == std::string::npos ? path : path.substr(separator + 1);
    if (name.empty() || name == "." || name == ".." ||
        name.find('/') != std::string::npos || name.find('\\') != std::string::npos) {
        return {};
    }
    return name;
}

} // namespace

DragInformation::DragInformation() :
    m_filename(),
    m_filesize(0)
{
}

void DragInformation::parseDragInfo(DragFileList& dragFileList, std::uint32_t fileNum,
                                    std::string data)
{
    size_t startPos = 0;
    size_t findResult1 = 0;
    size_t findResult2 = 0;
    dragFileList.clear();
    std::string slash("\\");
    if (data.find("/", startPos) != std::string::npos) {
        slash = "/";
    }

    std::uint32_t index = 0;
    while (index < fileNum) {
        findResult1 = data.find(',', startPos);
        findResult2 = data.find_last_of(slash, findResult1);

        if (findResult1 == startPos) {
            //TODO: file number does not match, something goes wrong
            break;
        }

        // set filename
        if (findResult1 - findResult2 > 1) {
            auto filename = data.substr(findResult2 + 1, findResult1 - findResult2 - 1);
            DragInformation di;
            di.setFilename(filename);
            dragFileList.push_back(di);
        }
        startPos = findResult1 + 1;

        //set filesize
        findResult2 = data.find(',', startPos);
        if (findResult2 - findResult1 > 1) {
            auto filesize = data.substr(findResult1 + 1, findResult2 - findResult1 - 1);
            size_t size = stringToNum(filesize);
            dragFileList.at(index).setFilesize(size);
        }
        startPos = findResult1 + 1;

        ++index;
    }

    LOG_DEBUG("drag info received, total drag file number: %zi",
        dragFileList.size());

    for (size_t i = 0; i < dragFileList.size(); ++i) {
        LOG_DEBUG("dragging file %zi name: %s",
            i + 1,
            dragFileList.at(i).getFilename().c_str());
    }
}

std::string DragInformation::getDragFileExtension(std::string filename)
{
    size_t findResult = std::string::npos;
    findResult = filename.find_last_of(".", filename.size());
    if (findResult != std::string::npos) {
        return filename.substr(findResult + 1, filename.size() - findResult - 1);
    }
    else {
        return "";
    }
}

int
DragInformation::setupDragInfo(DragFileList& fileList, std::string& output)
{
    int size = static_cast<int>(fileList.size());
    for (int i = 0; i < size; ++i) {
        output.append(fileList.at(i).getFilename());
        output.append(",");
        std::string filesize = getFileSize(fileList.at(i).getFilename());
        output.append(filesize);
        output.append(",");
    }
    return size;
}

bool DragInformation::packageFileList(const std::string& fileList, std::string& package)
{
    LOG_INFO("packageFileList input bytes=%zu", fileList.size());
    package.assign(kFilePackageMagic, sizeof(kFilePackageMagic) - 1);
    package.push_back('\0');
    const std::size_t countOffset = package.size();
    appendU32(package, 0);
    struct PackageFile {
        fs::path path;
        std::string name;
    };
    std::vector<PackageFile> files;
    std::uint32_t count = 0;
    std::size_t start = 0;

    while (start <= fileList.size()) {
        const std::size_t end = fileList.find('\n', start);
        std::string path = fileList.substr(start, end == std::string::npos ? end : end - start);
        if (!path.empty() && path.back() == 13) path.pop_back();
        if (!path.empty()) {
            const fs::path source = path_from_utf8(path);
            std::error_code error;
            if (fs::is_regular_file(source, error)) {
                const std::string name = baseName(path);
                if (name.empty()) {
                    LOG_WARN("rejecting clipboard file list: empty file name: %s", path.c_str());
                    return false;
                }
                files.push_back({source, name});
            } else if (fs::is_directory(source, error)) {
                const std::string rootName = path_to_utf8(source.filename());
                if (baseName(rootName).empty()) {
                    LOG_WARN("rejecting clipboard file list: empty directory name: %s", path.c_str());
                    return false;
                }
                fs::recursive_directory_iterator iterator(source, error);
                fs::recursive_directory_iterator endIterator;
                while (!error && iterator != endIterator) {
                    if (iterator->is_regular_file(error)) {
                        const fs::path relative = fs::relative(iterator->path(), source, error);
                        std::string relativeName = path_to_utf8(relative);
                        if (error || relativeName.empty() || relative.is_absolute() ||
                            relativeName.find("..") != std::string::npos) return false;
                        std::replace(relativeName.begin(), relativeName.end(), '\\', '/');
                        files.push_back({iterator->path(), rootName + "/" + relativeName});
                    }
                    iterator.increment(error);
                }
                if (error) {
                    LOG_WARN("rejecting clipboard file list: cannot enumerate directory: %s (%s)",
                             path.c_str(), error.message().c_str());
                    return false;
                }
            } else {
                LOG_WARN("rejecting clipboard file list: source is not a regular file or directory: %s (%s)",
                         path.c_str(), error.message().c_str());
                return false;
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }

    if (files.empty() || files.size() > kMaxFileCount) {
        LOG_WARN("rejecting clipboard file list: no packageable files (%u)", static_cast<unsigned>(files.size()));
        return false;
    }
    for (const PackageFile& entry : files) {
            std::ifstream file;
            open_utf8_path(file, entry.path, std::ios::in | std::ios::binary);
            if (!file.is_open()) {
                LOG_WARN("rejecting clipboard file list: cannot open source file: %s",
                         path_to_utf8(entry.path).c_str());
                return false;
            }
            file.seekg(0, std::ios::end);
            const std::streamoff fileSize = file.tellg();
            file.seekg(0, std::ios::beg);
            if (fileSize < 0 || package.size() + entry.name.size() + 12 +
                static_cast<std::uint64_t>(fileSize) > kMaxFilePackageSize) {
                LOG_WARN("rejecting clipboard file list: invalid or oversized source file: %s",
                         path_to_utf8(entry.path).c_str());
                return false;
            }
            appendU32(package, static_cast<std::uint32_t>(entry.name.size()));
            appendU64(package, static_cast<std::uint64_t>(fileSize));
            package.append(entry.name);
            const std::size_t oldSize = package.size();
            package.resize(oldSize + static_cast<std::size_t>(fileSize));
            file.read(package.data() + oldSize, fileSize);
            if (!file || file.gcount() != fileSize) {
                LOG_WARN("rejecting clipboard file list: failed reading source file: %s",
                         path_to_utf8(entry.path).c_str());
                return false;
            }
            ++count;
    }

    package[countOffset + 0] = static_cast<char>((count >> 24) & 0xff);
    package[countOffset + 1] = static_cast<char>((count >> 16) & 0xff);
    package[countOffset + 2] = static_cast<char>((count >> 8) & 0xff);
    package[countOffset + 3] = static_cast<char>(count & 0xff);
    return true;
}

bool DragInformation::isFilePackage(const std::string& data)
{
    return data.size() >= sizeof(kFilePackageMagic) + 5 &&
        data.compare(0, sizeof(kFilePackageMagic) - 1, kFilePackageMagic) == 0 &&
        data[sizeof(kFilePackageMagic) - 1] == '\0';
}

bool DragInformation::unpackFilePackage(const std::string& package,
                                         const std::string& destination,
                                         std::string& fileList)
{
    if (!isFilePackage(package) || destination.empty() || package.size() > kMaxFilePackageSize) {
        return false;
    }

    struct Entry {
        fs::path relative;
        std::size_t contentOffset;
        std::size_t contentSize;
        fs::path root;
    };

    std::size_t offset = sizeof(kFilePackageMagic);
    std::uint32_t count = 0;
    if (!readU32(package, offset, count) || count == 0 || count > kMaxFileCount) return false;

    const fs::path destinationPath = path_from_utf8(destination);
    std::vector<Entry> entries;
    entries.reserve(count);
    std::vector<std::string> publishedRoots;
    std::set<std::string> relativeNames;
    for (std::uint32_t index = 0; index < count; ++index) {
        std::uint32_t nameSize = 0;
        std::uint64_t contentSize = 0;
        if (!readU32(package, offset, nameSize) || !readU64(package, offset, contentSize) ||
            nameSize == 0 || nameSize > 4096 || contentSize > package.size() - offset ||
            offset + nameSize > package.size()) return false;
        const std::string name = package.substr(offset, nameSize);
        offset += nameSize;
        if (name.find('\\') != std::string::npos) return false;
        const fs::path relative = path_from_utf8(name);
        if (!isSafePackagePath(relative) || contentSize > package.size() - offset) return false;
        std::string duplicateKey = name;
        std::transform(duplicateKey.begin(), duplicateKey.end(), duplicateKey.begin(),
                       [](unsigned char character) {
                           return static_cast<char>(std::tolower(character));
                       });
        if (!relativeNames.insert(duplicateKey).second) return false;
        const fs::path root = *relative.begin();
        const std::string rootName = path_to_utf8(root);
        if (std::find(publishedRoots.begin(), publishedRoots.end(), rootName) == publishedRoots.end()) {
            publishedRoots.push_back(rootName);
        }
        entries.push_back({relative, offset, static_cast<std::size_t>(contentSize), root});
        offset += static_cast<std::size_t>(contentSize);
    }
    if (offset != package.size()) return false;

    // Validate the complete package before writing anything. Stage all files
    // under the destination, then publish only complete top-level roots.
    std::error_code error;
    fs::create_directories(destinationPath, error);
    if (error) return false;
    for (const std::string& rootName : publishedRoots) {
        const fs::path target = destinationPath / path_from_utf8(rootName);
        const fs::file_status status = fs::symlink_status(target, error);
        if (error && error != std::errc::no_such_file_or_directory) return false;
        error.clear();
        if (fs::exists(status) || fs::is_symlink(status)) return false;
    }

    fs::path stagingPath;
    bool stagingCreated = false;
    for (int attempt = 0; attempt < 32 && !stagingCreated; ++attempt) {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto sequence = g_stagingSequence.fetch_add(1, std::memory_order_relaxed);
        stagingPath = destinationPath /
            path_from_utf8(".inputleap-staging-" + std::to_string(stamp) + "-" + std::to_string(sequence));
        stagingCreated = fs::create_directory(stagingPath, error);
        if (error && error != std::errc::file_exists) return false;
        error.clear();
    }
    if (!stagingCreated) return false;
    StagingDirectory staging(stagingPath);

    for (const Entry& entry : entries) {
        const fs::path stagedFile = staging.path() / entry.relative;
        fs::create_directories(stagedFile.parent_path(), error);
        if (error) return false;
        std::ofstream file;
        open_utf8_path(file, stagedFile, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!file.is_open()) return false;
        file.write(package.data() + entry.contentOffset,
                   static_cast<std::streamsize>(entry.contentSize));
        file.close();
        if (!file) return false;
    }

    std::vector<fs::path> publishedPaths;
    for (const std::string& rootName : publishedRoots) {
        const fs::path stagedRoot = staging.path() / path_from_utf8(rootName);
        const fs::path targetRoot = destinationPath / path_from_utf8(rootName);
        fs::rename(stagedRoot, targetRoot, error);
        if (error) {
            for (const fs::path& published : publishedPaths) {
                std::error_code ignored;
                const fs::path stagedRootPath = staging.path() / published.filename();
                fs::rename(published, stagedRootPath, ignored);
            }
            return false;
        }
        publishedPaths.push_back(targetRoot);
    }

    fileList.clear();
    for (const fs::path& published : publishedPaths) {
        if (!fileList.empty()) fileList.push_back('\n');
        fileList += path_to_utf8(published);
    }
    return true;
}

bool DragInformation::isFileValid(std::string filename)
{
    bool result = false;
    std::fstream file(filename.c_str(), std::ios::in|std::ios::binary);

    if (file.is_open()) {
        result = true;
    }

    file. close();

    return result;
}

size_t DragInformation::stringToNum(std::string& str)
{
    std::istringstream iss(str.c_str());
    size_t size;
    iss >> size;
    return size;
}

std::string DragInformation::getFileSize(std::string& filename)
{
    std::fstream file(filename.c_str(), std::ios::in|std::ios::binary);

    if (!file.is_open()) {
      throw std::runtime_error("failed to get file size");
    }

    // check file size
    file.seekg (0, std::ios::end);
    size_t size = static_cast<size_t>(file.tellg());

    std::stringstream ss;
    ss << size;

    file. close();

    return ss.str();
}

} // namespace inputleap
