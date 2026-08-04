#pragma once

#include <QHash>
#include <QMap>
#include <QSet>
#include <QString>
#include <QUuid>
#include <optional>

enum class CapabilityId { Control, FileTransfer, Pairing, Monitor };
enum class NegotiationStatus { Supported, Degraded, UpgradeLocal, UpgradeRemote, Unknown, SecurityBlocked };

struct ProtocolVersion {
    int major = 0;
    int minor = 0;
    bool operator==(const ProtocolVersion&) const = default;
    static std::optional<ProtocolVersion> parse(const QString& text);
    QString toString() const;
};

struct CapabilitySupport {
    ProtocolVersion minimum;
    ProtocolVersion maximum;
    bool securitySensitive = false;
};

struct CapabilityAdvertisement {
    QUuid uuid;
    QMap<CapabilityId, ProtocolVersion> versions;
    QSet<CapabilityId> claimed;
    QSet<CapabilityId> authenticated;
    bool metadataValid = true;
    bool legacy = false;
    QString legacyAppVersion;
};

struct NegotiationDecision {
    NegotiationStatus status = NegotiationStatus::Unknown;
    QString reason;
    QString technical;
    bool awaitingAuthentication = false;
    std::optional<ProtocolVersion> negotiatedVersion;
    bool allowed() const { return status == NegotiationStatus::Supported || status == NegotiationStatus::Degraded; }
    bool protocolCompatible() const { return allowed() || awaitingAuthentication; }
    bool operator==(const NegotiationDecision&) const = default;
};

struct CapabilityNegotiationSnapshot {
    QUuid uuid;
    NegotiationDecision base;
    QMap<CapabilityId, NegotiationDecision> capabilities;
    NegotiationDecision capability(CapabilityId id) const;
    bool baseConnectionAllowed() const { return base.allowed(); }
    bool capabilityAllowed(CapabilityId id) const { return capability(id).allowed(); }
    bool operator==(const CapabilityNegotiationSnapshot&) const = default;
};

class CapabilityNegotiationPolicy {
public:
    CapabilityNegotiationPolicy();
    explicit CapabilityNegotiationPolicy(QMap<CapabilityId, CapabilitySupport> local);
    CapabilityNegotiationSnapshot negotiate(const CapabilityAdvertisement& remote) const;
    const QMap<CapabilityId, CapabilitySupport>& localSupport() const { return local_; }
    static QString encodeVersions(const QMap<CapabilityId, ProtocolVersion>& versions);
    static std::optional<QMap<CapabilityId, ProtocolVersion>> parseVersions(const QString& encoded);
    static QString capabilityName(CapabilityId id);
private:
    NegotiationDecision decide(CapabilityId id, const ProtocolVersion& remote, bool authenticated) const;
    QMap<CapabilityId, CapabilitySupport> local_;
};

class CapabilityNegotiationStore {
public:
    explicit CapabilityNegotiationStore(CapabilityNegotiationPolicy policy = {});
    void replace(const CapabilityAdvertisement& advertisement);
    void remove(const QUuid& uuid);
    std::optional<CapabilityNegotiationSnapshot> snapshot(const QUuid& uuid) const;
    bool revalidate(const QUuid& uuid, CapabilityId capability) const;
private:
    CapabilityNegotiationPolicy policy_;
    QHash<QUuid, CapabilityNegotiationSnapshot> snapshots_;
};
