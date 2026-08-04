#pragma once

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMetaType>
#include <QSet>
#include <QString>
#include <QUuid>
#include <functional>
#include <optional>
#include "CapabilityNegotiationPolicy.h"

constexpr int ZeroconfSchemaVersion = 1;
constexpr int ZeroconfProtocolVersion = 1;

enum class ZeroconfOsFamily { Windows, MacOS, Linux, Other };
enum class ZeroconfRole { Server, Client, Dual };
enum class ZeroconfCapability { Keyboard, Mouse, Clipboard, FileTransfer };
enum class ZeroconfParseStatus { Compatible, Incompatible, Malformed, Legacy };
enum class ZeroconfDiscoveryEvent { Found, Updated, Refreshed, Rejected };

struct ZeroconfMetadata {
    QUuid uuid;
    QString technicalName;
    QString friendlyName;
    ZeroconfOsFamily osFamily = ZeroconfOsFamily::Other;
    QString inputLeapVersion;
    ZeroconfRole role = ZeroconfRole::Client;
    QSet<ZeroconfCapability> capabilities;
    quint16 controlPort = 0;
    quint16 transferPort = 0;
    // Zero means that this compatible peer is not currently accepting pairing.
    quint16 pairingPort = 0;
    QSet<QString> features;
    // Protocol versions are independent from the app version and DNS-SD schema.
    QMap<CapabilityId, ProtocolVersion> protocolVersions;

    bool operator==(const ZeroconfMetadata&) const = default;
};

struct ZeroconfSerializeResult { bool ok = false; QByteArray txt; QString detail; };
struct ZeroconfParseResult {
    ZeroconfParseStatus status = ZeroconfParseStatus::Malformed;
    std::optional<ZeroconfMetadata> metadata;
    QString detail;
};

class ZeroconfMetadataCodec {
public:
    static ZeroconfSerializeResult serialize(const ZeroconfMetadata& metadata);
    static ZeroconfParseResult parse(const QByteArray& txt);
    static constexpr qsizetype maximumTxtBytes() { return 1300; }
};

struct DnsSdTxtEncodeResult { bool ok = false; QByteArray wire; QString detail; };
class DnsSdTxtRecordCodec {
public:
    static DnsSdTxtEncodeResult encode(const QList<QByteArray>& entries);
    static DnsSdTxtEncodeResult fromCanonical(const QByteArray& canonical);
    static ZeroconfParseResult decode(const QByteArray& wire);
};

struct DiscoveredDeviceAdvertisement {
    QUuid uuid;
    ZeroconfMetadata metadata;
    QSet<QString> addresses;
    QSet<quint32> interfaces;
    qint64 lastSeenMs = 0;
    QHash<quint32, qint64> interfaceLastSeenMs;
    QHash<quint32, QSet<QString>> interfaceAddresses;
    QHash<quint32, QHash<QString, qint64>> addressLastSeenMs;
};

class ZeroconfDiscoveryCache {
public:
    using Clock = std::function<qint64()>;
    explicit ZeroconfDiscoveryCache(Clock clock, qint64 ttlMs);
    ZeroconfDiscoveryEvent observe(const ZeroconfMetadata& metadata, const QString& address, quint32 interfaceIndex);
    std::optional<DiscoveredDeviceAdvertisement> remove(const QUuid& uuid, quint32 interfaceIndex);
    std::optional<DiscoveredDeviceAdvertisement> removeAddress(const QUuid& uuid, const QString& address, quint32 interfaceIndex);
    QList<DiscoveredDeviceAdvertisement> expire();
    QList<DiscoveredDeviceAdvertisement> devices() const;
private:
    Clock clock_;
    qint64 ttlMs_;
    QHash<QUuid, DiscoveredDeviceAdvertisement> devices_;
};

Q_DECLARE_METATYPE(DiscoveredDeviceAdvertisement)
