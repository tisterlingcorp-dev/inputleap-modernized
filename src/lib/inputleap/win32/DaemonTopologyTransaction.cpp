#include "inputleap/win32/DaemonTopologyTransaction.h"

#include "inputleap/protocol_types.h"
#include "server/TopologyConfigCandidate.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

namespace inputleap {
namespace {

constexpr const char* kJournalMarker = "inputleap-topology-journal-v1";
constexpr const char* kStateMarker = "inputleap-topology-state-v1";

std::filesystem::path withSuffix(
    const std::filesystem::path& path, const wchar_t* suffix)
{
    auto result = path;
    result += suffix;
    return result;
}

std::string hexEncode(const std::string& value)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (const unsigned char byte : value) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

std::optional<std::string> hexDecode(const std::string& value)
{
    if (value.size() % 2 != 0) {
        return std::nullopt;
    }
    const auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    std::string result;
    result.reserve(value.size() / 2);
    for (std::size_t index = 0; index < value.size(); index += 2) {
        const int high = nibble(value[index]);
        const int low = nibble(value[index + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        result.push_back(static_cast<char>((high << 4) | low));
    }
    return result;
}

std::optional<std::string> payloadDigest(const std::string& payload)
{
    if (payload.size() > static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())) {
        return std::nullopt;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<unsigned char, 32> digest{};
    const NTSTATUS openStatus = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (openStatus < 0) {
        return std::nullopt;
    }
    const NTSTATUS createStatus = BCryptCreateHash(
        algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    const NTSTATUS hashStatus = createStatus < 0
        ? createStatus
        : BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(payload.data())),
            static_cast<ULONG>(payload.size()), 0);
    const NTSTATUS finishStatus = hashStatus < 0
        ? hashStatus
        : BCryptFinishHash(hash, digest.data(),
                           static_cast<ULONG>(digest.size()), 0);
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (finishStatus < 0) {
        return std::nullopt;
    }
    return hexEncode(std::string(
        reinterpret_cast<const char*>(digest.data()), digest.size()));
}

bool readFile(const std::filesystem::path& path, std::string& value)
{
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }
    value.assign(
        std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>());
    return stream.good() || stream.eof();
}

bool writeDurable(const std::filesystem::path& path, const std::string& value)
{
    HANDLE file = CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    bool success = true;
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto remaining = value.size() - offset;
        const DWORD requested = static_cast<DWORD>(
            (std::min)(remaining,
                       static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (WriteFile(file, value.data() + offset, requested, &written, nullptr) == FALSE ||
            written != requested) {
            success = false;
            break;
        }
        offset += written;
    }
    if (success && FlushFileBuffers(file) == FALSE) {
        success = false;
    }
    if (CloseHandle(file) == FALSE) {
        success = false;
    }
    if (!success) {
        DeleteFileW(path.c_str());
    }
    return success;
}

bool moveReplace(
    const std::filesystem::path& source,
    const std::filesystem::path& destination)
{
    return MoveFileExW(
        source.c_str(), destination.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
}

bool removeIfPresent(const std::filesystem::path& path)
{
    std::error_code error;
    const bool removed = std::filesystem::remove(path, error);
    return removed || !error;
}

bool writeAtomically(const std::filesystem::path& path, const std::string& value)
{
    const auto temporary = withSuffix(path, L".tmp");
    removeIfPresent(temporary);
    if (!writeDurable(temporary, value)) {
        return false;
    }
    if (!moveReplace(temporary, path)) {
        removeIfPresent(temporary);
        return false;
    }
    return true;
}

bool invoke(const std::function<bool()>& operation)
{
    if (!operation) {
        return false;
    }
    try {
        return operation();
    }
    catch (...) {
        return false;
    }
}

} // namespace

struct DaemonTopologyTransaction::JournalRecord
{
    std::string requestNonce;
    std::string expectedGeneration;
    std::string digest;
    bool hadOriginal{false};
};

struct DaemonTopologyTransaction::StateRecord
{
    std::string generation;
    std::string expectedGeneration;
    std::string digest;
};

namespace {

std::string serializeJournal(
    const DaemonTopologyTransaction::JournalRecord& record)
{
    std::ostringstream stream;
    stream << kJournalMarker << '\n'
           << hexEncode(record.requestNonce) << '\n'
           << hexEncode(record.expectedGeneration) << '\n'
           << record.digest << '\n'
           << (record.hadOriginal ? '1' : '0') << '\n';
    return stream.str();
}

std::optional<DaemonTopologyTransaction::JournalRecord> parseJournal(
    const std::string& value)
{
    std::istringstream stream(value);
    std::string marker;
    std::string requestHex;
    std::string expectedHex;
    std::string digest;
    std::string hadOriginal;
    std::string trailing;
    if (!std::getline(stream, marker) || marker != kJournalMarker ||
        !std::getline(stream, requestHex) ||
        !std::getline(stream, expectedHex) ||
        !std::getline(stream, digest) ||
        !std::getline(stream, hadOriginal) ||
        std::getline(stream, trailing)) {
        return std::nullopt;
    }
    const auto request = hexDecode(requestHex);
    const auto expected = hexDecode(expectedHex);
    if (!request || !expected || request->size() != 16 || expected->size() != 16 ||
        *request == *expected || digest.size() != 64 ||
        (hadOriginal != "0" && hadOriginal != "1")) {
        return std::nullopt;
    }
    return DaemonTopologyTransaction::JournalRecord{
        *request, *expected, digest, hadOriginal == "1"};
}

std::string serializeState(const DaemonTopologyTransaction::StateRecord& record)
{
    std::ostringstream stream;
    stream << kStateMarker << '\n'
           << hexEncode(record.generation) << '\n'
           << hexEncode(record.expectedGeneration) << '\n'
           << record.digest << '\n';
    return stream.str();
}

std::optional<DaemonTopologyTransaction::StateRecord> parseState(
    const std::string& value)
{
    std::istringstream stream(value);
    std::string marker;
    std::string generationHex;
    std::string expectedHex;
    std::string digest;
    std::string trailing;
    if (!std::getline(stream, marker) || marker != kStateMarker ||
        !std::getline(stream, generationHex) ||
        !std::getline(stream, expectedHex) ||
        !std::getline(stream, digest) ||
        std::getline(stream, trailing)) {
        return std::nullopt;
    }
    const auto generation = hexDecode(generationHex);
    const auto expected = hexDecode(expectedHex);
    if (!generation || !expected || generation->size() != 16 || expected->size() != 16 ||
        *generation == *expected || digest.size() != 64) {
        return std::nullopt;
    }
    return DaemonTopologyTransaction::StateRecord{
        *generation, *expected, digest};
}

std::optional<DaemonTopologyTransaction::StateRecord> readState(
    const std::filesystem::path& path, bool& malformed)
{
    malformed = false;
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }
    std::string value;
    if (!readFile(path, value)) {
        malformed = true;
        return std::nullopt;
    }
    auto state = parseState(value);
    malformed = !state.has_value();
    return state;
}

} // namespace

DaemonTopologyTransaction::DaemonTopologyTransaction(
    std::filesystem::path authoritativeConfigPath) :
    configPath_(std::move(authoritativeConfigPath)),
    journalPath_(withSuffix(configPath_, L".inputleap-topology-journal")),
    backupPath_(withSuffix(configPath_, L".inputleap-topology-backup")),
    candidatePath_(withSuffix(configPath_, L".inputleap-topology-candidate")),
    statePath_(withSuffix(configPath_, L".inputleap-topology-state"))
{
}

TopologyTransactionResult DaemonTopologyTransaction::apply(
    const TopologyTransactionRequest& request,
    const std::string& authoritativeGeneration,
    const TopologyTransactionServices& services)
{
    const auto reject = [](std::string error) {
        return TopologyTransactionResult{
            TopologyTransactionStatus::Rejected, {}, std::move(error)};
    };
    if (configPath_.empty() || !configPath_.is_absolute()) {
        return reject("authoritative configuration path is not absolute");
    }
    if (request.requestNonce.size() != 16 ||
        request.expectedGeneration.size() != 16 ||
        request.requestNonce == request.expectedGeneration) {
        return reject("invalid topology generations");
    }
    if (request.payload.size() > PROTOCOL_MAX_STRING_LENGTH) {
        return reject("topology payload exceeds IPC string limit");
    }
    const auto digest = payloadDigest(request.payload);
    if (!digest) {
        return reject("could not digest topology payload");
    }
    if (std::filesystem::exists(journalPath_)) {
        return reject("incomplete topology transaction requires recovery");
    }

    bool malformedState = false;
    const auto state = readState(statePath_, malformedState);
    if (malformedState) {
        return reject("persisted topology state is malformed");
    }
    if (state) {
        std::string activePayload;
        const auto activeDigest = readFile(configPath_, activePayload)
            ? payloadDigest(activePayload) : std::nullopt;
        if (!activeDigest || *activeDigest != state->digest) {
            return reject(
                "persisted topology state does not match authoritative config");
        }
    }
    if (state && request.requestNonce == state->generation) {
        if (request.expectedGeneration == state->expectedGeneration &&
            *digest == state->digest) {
            return {TopologyTransactionStatus::Replayed,
                    state->generation, {}};
        }
        return reject("topology request nonce collision");
    }

    const std::string currentGeneration = state
        ? state->generation : authoritativeGeneration;
    if (currentGeneration.size() != 16 ||
        request.expectedGeneration != currentGeneration) {
        return reject("stale topology generation");
    }

    const auto candidate = TopologyConfigCandidate::parse(
        request.payload, request.primaryScreen);
    if (!candidate.config) {
        return reject("invalid topology candidate: " + candidate.error);
    }

    std::string original;
    const bool hadOriginal = std::filesystem::exists(configPath_);
    if (hadOriginal) {
        if (!readFile(configPath_, original) || !writeDurable(backupPath_, original)) {
            return reject("could not persist authoritative topology backup");
        }
    }
    else {
        removeIfPresent(backupPath_);
    }

    const JournalRecord journal{
        request.requestNonce, request.expectedGeneration, *digest, hadOriginal};
    if (!writeAtomically(journalPath_, serializeJournal(journal))) {
        removeIfPresent(backupPath_);
        return reject("could not persist topology journal");
    }
    if (!writeDurable(candidatePath_, request.payload) ||
        !moveReplace(candidatePath_, configPath_)) {
        std::string restoreError;
        restoreOriginal(journal, restoreError);
        cleanupArtifacts();
        return reject("could not atomically install topology candidate");
    }

    const bool candidateApplied = invoke(services.applyCandidate);
    if (!candidateApplied) {
        std::string restoreError;
        const bool fileRestored = restoreOriginal(journal, restoreError);
        const bool runtimeRestored = invoke(services.applyRollback);
        if (fileRestored && runtimeRestored) {
            cleanupArtifacts();
            return reject("runtime rejected topology candidate");
        }
        return {TopologyTransactionStatus::RollbackFailed, {},
                fileRestored ? "runtime rollback was not confirmed" : restoreError};
    }

    const StateRecord committed{
        request.requestNonce, request.expectedGeneration, *digest};
    if (!writeAtomically(statePath_, serializeState(committed))) {
        std::string restoreError;
        const bool fileRestored = restoreOriginal(journal, restoreError);
        const bool runtimeRestored = invoke(services.applyRollback);
        if (fileRestored && runtimeRestored) {
            cleanupArtifacts();
            return reject("topology receipt was not durably persisted");
        }
        return {TopologyTransactionStatus::RollbackFailed, {},
                fileRestored ? "runtime rollback was not confirmed" : restoreError};
    }

    cleanupArtifacts();
    return {TopologyTransactionStatus::Applied, request.requestNonce, {}};
}

TopologyRecoveryResult DaemonTopologyTransaction::recover()
{
    if (configPath_.empty() || !configPath_.is_absolute()) {
        return {TopologyRecoveryAction::Failed, {}, {},
                "authoritative configuration path is not absolute"};
    }
    if (!std::filesystem::exists(journalPath_)) {
        bool malformedState = false;
        const auto state = readState(statePath_, malformedState);
        if (malformedState) {
            return {TopologyRecoveryAction::Failed, {}, {},
                    "persisted topology state is malformed"};
        }
        if (state) {
            std::string activePayload;
            const auto activeDigest = readFile(configPath_, activePayload)
                ? payloadDigest(activePayload) : std::nullopt;
            if (!activeDigest || *activeDigest != state->digest) {
                return {TopologyRecoveryAction::Failed,
                        state->generation, state->expectedGeneration,
                        "persisted topology state does not match authoritative config"};
            }
            removeIfPresent(candidatePath_);
            removeIfPresent(backupPath_);
            removeIfPresent(withSuffix(journalPath_, L".tmp"));
            removeIfPresent(withSuffix(statePath_, L".tmp"));
            return {TopologyRecoveryAction::Committed,
                    state->generation, state->expectedGeneration, {}};
        }
        removeIfPresent(candidatePath_);
        removeIfPresent(backupPath_);
        removeIfPresent(withSuffix(journalPath_, L".tmp"));
        removeIfPresent(withSuffix(statePath_, L".tmp"));
        return {};
    }

    std::string serialized;
    if (!readFile(journalPath_, serialized)) {
        return {TopologyRecoveryAction::Failed, {}, {},
                "could not read topology journal"};
    }
    const auto journal = parseJournal(serialized);
    if (!journal) {
        return {TopologyRecoveryAction::Failed, {}, {},
                "topology journal is malformed"};
    }

    bool malformedState = false;
    const auto state = readState(statePath_, malformedState);
    if (malformedState) {
        return {TopologyRecoveryAction::Failed,
                journal->requestNonce, journal->expectedGeneration,
                "persisted topology state is malformed"};
    }
    if (state && state->generation == journal->requestNonce &&
        state->expectedGeneration == journal->expectedGeneration &&
        state->digest == journal->digest) {
        std::string activePayload;
        const auto activeDigest = readFile(configPath_, activePayload)
            ? payloadDigest(activePayload) : std::nullopt;
        if (!activeDigest || *activeDigest != state->digest) {
            return {TopologyRecoveryAction::Failed,
                    journal->requestNonce, journal->expectedGeneration,
                    "committed topology receipt does not match authoritative config"};
        }
        cleanupArtifacts();
        return {TopologyRecoveryAction::Committed,
                journal->requestNonce, journal->expectedGeneration, {}};
    }

    std::string error;
    if (!restoreOriginal(*journal, error)) {
        return {TopologyRecoveryAction::Failed,
                journal->requestNonce, journal->expectedGeneration,
                std::move(error)};
    }
    return {TopologyRecoveryAction::RolledBack,
            journal->requestNonce, journal->expectedGeneration, {}};
}

void DaemonTopologyTransaction::finalizeRecovery()
{
    cleanupArtifacts();
}

bool DaemonTopologyTransaction::restoreOriginal(
    const JournalRecord& journal, std::string& error) const
{
    if (!journal.hadOriginal) {
        if (!removeIfPresent(configPath_)) {
            error = "could not remove uncommitted topology candidate";
            return false;
        }
        return true;
    }

    std::string original;
    if (!readFile(backupPath_, original) ||
        !writeDurable(candidatePath_, original) ||
        !moveReplace(candidatePath_, configPath_)) {
        error = "could not restore authoritative topology backup";
        return false;
    }
    return true;
}

void DaemonTopologyTransaction::cleanupArtifacts() const
{
    removeIfPresent(candidatePath_);
    removeIfPresent(backupPath_);
    removeIfPresent(withSuffix(journalPath_, L".tmp"));
    removeIfPresent(withSuffix(statePath_, L".tmp"));
    removeIfPresent(journalPath_);
}

} // namespace inputleap
